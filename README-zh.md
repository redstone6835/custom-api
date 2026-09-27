# Custom-API：自用 LLM 中转「海关」

一个**双向审计 + 独立计量 + 自动择优路由**的模型中转网关。它插在用户侧网关
（new-api）与上游接入点之间，把「中转站」当作需要过海关的边境，而不是一根管道。

```
用户客户端 (OpenAI / Anthropic 兼容)
        │  用户密钥 = new-api 令牌
        ▼
   new-api（复用：令牌 / 用户 / 配额 / 渠道 / 请求日志）
        │  透传请求与响应原文
        ▼
   customsd ← 本项目：海关代理（单点插入）
        │  A 出站：输入审查 · 滥用检测 · 危险 tool 拦截 · 脱敏留痕
        │  B 入站：usage 核验 · 模型指纹 · 注入检测 · 敏感信息过滤
        │  C 计量：本地 token 重算 · 定价 · 独立防篡改审计账
        ▼
   上游接入点 A / B / C（官方 API · 中转站 · 免费额度）
        ▲
        │  价格 · 跑分 · 指纹基线 · 性价比分
   benchd（情报层）
```

---

## 设计思想：一条信任假设推导出全部功能

> **少数用户与少数接入点可信；其余默认不可信。**

由此对称地长出两条防线，以及三条**永不降级**的底线：

| 方向 | 威胁 | 对策 |
|---|---|---|
| 出站（用户 → 上游） | 违规输入导致**接入点封号**；滥用；危险工具调用 | 内容审查、滥用模式检测、工具白名单、参数路径校验、脱敏留痕 |
| 入站（上游 → 用户） | **虚报 usage**、以次充好/降智、注入恶意提示词、伪造工具指令窃取密钥 | usage 核验、模型指纹、注入检测、敏感信息过滤、工具调用拦截 |
| 情报（旁路） | 选到又贵又差的渠道 | 价格归一化 + 优惠建模、三级跑分、指纹基线 → 性价比分 → 路由权重 |

**例外原则（不可协商）**：*计量记账、配额扣减、审计留痕 —— 任何对象都不跳过。*
可信白名单只放宽**内容检查**（降低延迟与误拦），**账必须记**。代码中这一点由
`TestBlockedRequestStillConsumesQuota` 与验收测试 6.3 强制保证。

---

## 交付内容

| 组件 | 说明 |
|---|---|
| `customsd` | 海关代理：出站审查、入站核验、计量、审计、路由 |
| `benchd` | 情报守护进程：价格采集、指纹探针、跑分、性价比评分 |
| `customsctl` | 运维 CLI：配置校验、审计链校验与浏览、配额发放、比价 |
| `deploy/` | FreeBSD rc.d 脚本、安装器、验收测试、部署脚本 |

**零第三方依赖**：全部基于 Go 标准库。因此可静态交叉编译为单个 FreeBSD 二进制，
目标机上不需要任何 port、不需要 CGO、部署时不需要模块代理。

---

## 快速开始

### 1. 本地测试（任意平台）

```sh
./deploy/scripts/deploy.sh local-test      # go vet + go test -race + 覆盖率
```

### 2. 建立 FreeBSD 测试虚拟机（libvirt 托管、无头、virsh console 可进）

```sh
./vm/create-vm.sh          # 下载镜像、cloud-init、定义并启动域
./vm/create-vm.sh status
virsh -c qemu:///system console customapi-freebsd
```

详见 [`docs/VM-zh.md`](docs/VM-zh.md)。

### 3. 构建并部署到 FreeBSD

```sh
./deploy/scripts/deploy.sh build     # 交叉编译 freebsd/amd64
./deploy/scripts/deploy.sh stage     # 组装发布目录 + 校验和
./deploy/scripts/deploy.sh ship      # 拷贝到目标机
./deploy/scripts/deploy.sh install   # 目标机上安装（rc.d、用户、目录、配置模板）
./deploy/scripts/deploy.sh test      # 89 项端到端验收测试

# 或一步到位
./deploy/scripts/deploy.sh all
```

### 4. 目标机上的收尾

```sh
# 替换所有 replace-me 占位凭据
vi /usr/local/etc/customapi/customsd.env
chmod 640 /usr/local/etc/customapi/customsd.env
chown root:customapi /usr/local/etc/customapi/customsd.env

/usr/local/bin/customsctl config check -config /usr/local/etc/customapi/customs.json
service customsd start
service benchd start
/usr/local/bin/customsctl audit verify -config /usr/local/etc/customapi/customs.json

# 一条命令确认这套部署真的可用（服务、门禁、控制台、账本）
sh /usr/local/share/customapi/verify-deployment.sh
```

---

## 用户面与管理面

### 三种协议并存

网关同时讲三种上游协议，客户端按自己方便的那一种接入即可，不必迁就某个提供商：

| 客户端协议 | 端点 | 说明 |
|---|---|---|
| OpenAI Chat Completions | `POST /v1/chat/completions` | 最通用的一种，绝大多数客户端库的默认 |
| OpenAI Responses | `POST /v1/responses` | 原生解析（有自己的请求/响应/流事件形状），不是别名转发 |
| Anthropic Messages | `POST /v1/messages` | 原生解析，支持 `x-api-key` 与 `anthropic-version` |

**三种协议可以互相到达，不需要客户端迁就上游。** 你用 Responses 协议调用，上游只讲
chat completions——网关帮你转过去、再把回复转回 Responses 形状；反过来也一样。
六种方向（chat/responses/anthropic 两两组合）的请求与响应转换都已实现。

判定规则只有一条：**`supports` 里声明的接口面原样直连，没声明的就转换**。

| 客户端用 | 提供商 `supports` | 结果 |
|---|---|---|
| chat | `["openai","responses"]` | 原样发 `/v1/chat/completions` |
| responses | `["openai","responses"]` | 原样发 `/v1/responses`（**零改写**） |
| messages | `["openai","responses"]` | 转成 chat 发出，回复转回 Messages 形状，带 `X-Customs-Translated` |

转换过的交换在审计账里 `translated: true`，并同时记下 `protocol`（客户端用的）与
`upstream_protocol`（上游实际讲的）。翻译是有损的边界（工具调用、思考字段、服务端
状态会退化），所以默认 `prefer_same_protocol` 把能直连的渠道排在需要转换的前面。

### 多提供商故障转移

配置多家就是为了**一家不行换下一家**：

```json
"routing": {
  "max_attempts": 3,
  "retry_on": ["5xx", "429", "timeout", "network", "quota"]
}
```

`quota` 是关键的一类：提供商账户余额不足（如 naapi 返回 403
`insufficient_user_quota`）时，这不是你的请求有问题，而是这家付不起——请求会自动
落到下一家。识别是窄的：只有响应体明说是提供商自己的账户问题才算 `quota`，
普通 403（key 被封、模型无权限）仍然是终局错误，不会到处重试烧钱。

审计记录会写清"最后是谁服务的、前面谁挂了"：

```
channel=healthy/main provider=healthy attempts=2
failover_note: failed over from "broke/main" to "healthy/main" after attempt 1
```

```sh
# 用户：正常调用（网关自动选路）
curl http://127.0.0.1:8080/v1/chat/completions \
  -H "Authorization: Bearer $CUSTOMS_USER_TOKEN" \
  -d '{"model":"gpt-4o","messages":[{"role":"user","content":"hi"}]}'

# 用户：用 Responses 协议问同一个模型
curl http://127.0.0.1:8080/v1/responses \
  -H "Authorization: Bearer $CUSTOMS_USER_TOKEN" \
  -d '{"model":"gpt-4o","input":"hi"}'

# 用户：用 Anthropic 协议问同一个模型
curl http://127.0.0.1:8080/v1/messages \
  -H "x-api-key: $CUSTOMS_USER_TOKEN" -H "anthropic-version: 2023-06-01" \
  -d '{"model":"gpt-4o","max_tokens":256,"messages":[{"role":"user","content":"hi"}]}'

# 用户：看看现在到底有哪些模型、哪些渠道能供（按自己的权限过滤）
curl "http://127.0.0.1:8080/v1/models?detail=true" -H "Authorization: Bearer $CUSTOMS_USER_TOKEN"

# 用户：固定走某个渠道（例如自己信任的渠道）
curl ... -H "X-Customs-Channel: official" ...

# 用户：查看自己的配额与用量
curl http://127.0.0.1:8080/v1/customs/usage -H "Authorization: Bearer $CUSTOMS_USER_TOKEN"

# 用户：比价（自由浏览）
curl "http://127.0.0.1:8080/v1/customs/prices?model=gpt-4o&input_tokens=100000&output_tokens=20000"
```

### 管理控制台

管理面自带一个前端（Vue 3 + Vite + TypeScript，无 CDN、无图表库、无外部字体），
由管理监听端口直接提供：

```
http://127.0.0.1:8081/          # 概览 / 提供商 / 模型 / 路由 / 用量 / 审计 / 用户 / 评分 / 设置
```

九个页面覆盖：运行状态与审计链完整性、提供商与密钥健康度、合并后的模型目录、
路由策略与比价、按模型/渠道/用户聚合的用量、审计账本浏览与哈希链校验、
配额发放与封禁、性价比评分与指纹证据、配置摘要。

**管理面的可达性是有意收紧的**，因为 `/admin/*` 能封禁用户、改写配额、读取整本审计账：

1. 默认只监听 `127.0.0.1`；
2. 即使把监听地址改成对外地址，处理器本身仍然拒绝非环回调用者（403）；
3. 要让别的机器访问，必须同时 `server.admin_remote: true` 并设置
   `server.admin_token`，此后每个远程调用都要出示该令牌（401 表示"该给令牌了"）。

控制台的外壳（静态 bundle）不受门禁，只有 `/admin/*` 数据接口受门禁——
否则浏览器拿不到那个"用来输入令牌"的页面，远程运维就永远进不来。
令牌只存在浏览器 sessionStorage 里，标签页关闭即消失；也可以用
`http://gateway:8081/#token=<server.admin_token>` 免手工输入打开（令牌走
URL fragment，不会进入服务器日志，用后立即从地址栏抹掉）。

管理 API：

| 端点 | 用途 |
|---|---|
| `GET /admin/stats` | 运行计数、审计链头、策略模式 |
| `GET /admin/config` | 配置摘要（**不含任何密钥**，只报告是否存在） |
| `GET /admin/providers` | 提供商、密钥、展开后的渠道、健康度、支持的协议 |
| `GET /admin/models` · `POST /admin/models/refresh` | 合并后的模型目录；向上游重新拉取 |
| `GET /admin/users` · `POST /admin/users` | 查看用户；发放/调整配额、封禁/解封、设置周期 |
| `GET /admin/audit` | 审计浏览，支持按用户/渠道/模型/判定/结论过滤 |
| `GET /admin/audit/verify` | 校验哈希链与锚点，失败返回 409 |
| `GET /admin/usage` | 按用户/模型/渠道聚合 |
| `GET /admin/prices` · `/admin/prices/compare` | 价目表与按具体 token 量的比价 |
| `GET /admin/scores` · `/admin/fingerprints` | 性价比评分与模型指纹证据 |

CLI 示例：

```sh
customsctl users list
customsctl users grant -user alice -quota 50000000
customsctl audit tail -n 20 -verdict over_billed
customsctl audit stats
customsctl audit verify            # 完整性校验，被篡改则非零退出
customsctl audit rehash -yes       # 重建旧格式账本的哈希链（保留原文件）
customsctl prices compare -model gpt-4o -input 100000 -output 20000
customsctl prices normalize -scheme multiplier -base 2 -model-ratio 1.5 -group-ratio 0.8
```

---

## 关键实现说明

### 1. 计量核验（防虚报）与一个诚实的误差边界

网关**从不采信上游自报的 usage**：它对每次请求与响应独立重算 token，再与上游声明
比对，偏差超过阈值即记审计事件并把该渠道降权（反馈回路由）。

估算器是**刻意不携带词表**的（零依赖的直接代价）：它按字符类别分段并套用与
tiktoken o200k/cl100k、Anthropic 分词器标定过的比率。实测误差：

| 内容类型 | 实测误差 |
|---|---|
| 英文散文 | +7% ~ +17% |
| 中文 | +15% |
| JSON | 0% |
| 代码 | −29% |
| 纯数字密集 | −46% |

因此判据是**两条同时满足**才算异常：

```
判定虚报  ⇔  相对偏差 > tolerance (默认 0.25)  且  绝对偏差 ≥ min_absolute_delta (默认 8 token)
```

**为什么必须加绝对下限**：这是 FreeBSD 验收测试中实测发现的真实问题。5 token 的回复
被声明为 8 token 就是 +60%，纯相对判据会把它当作欺诈——而短请求恰恰是健康检查与
跑分探针最常发的。修复前，一个完全诚实的上游在 36 条跑分记录里被误报 6 次，
渠道诚信分从 1.0 掉到 **0.58**；而诚信分正是路由用来判断"这个渠道能不能信"的量。
加上绝对下限后，同一批记录误报 **0/36**，而 20 倍虚报仍被准确抓住。

> 这是显式的工程取舍，写在这里而不是藏在注释里：如果要更严的阈值，应当给估算器接入
> 真实 BPE 词表（tiktoken 词表约 1.5 MB），而不是把容差压到噪声以下。

### 2. 防篡改审计账

每条记录一行 JSON，带三个链字段：

```
seq         从 1 开始的单调序号
prev_hash   前一条的 entry_hash（首条为 "genesis"）
entry_hash  SHA-256(记录规范化 JSON，去掉 entry_hash 本身)
```

由于 `entry_hash` 覆盖 `prev_hash`，**篡改、重排、插入、删除**任一记录都会使从该点起
的校验失败。管理员改写整条链时，由周期性写入**独立文件**的锚点（`anchor.jsonl`）暴露。
验收测试覆盖了全部五种情形（7.2–7.5）。

两个额外的安全行为：

- **启动即校验整条链**。链已损坏时 `customsd` **拒绝启动**，而不是从尾部继续追加——
  后者会把篡改"洗白"成一条自洽的新链。
- **检测账本被替换**。记录打开文件的 dev/ino，每次追加前比对；被轮转或替换时重新
  打开并校准链尾，而不是继续写入已失联的 inode（验收测试 7.7）。

### 3. 流式的两难与解法

流式响应下"尽早转发"与"拦截前不泄露"本质冲突。本项目按**渠道可信度自动选择**：

| 模式 | 触发 | 行为 |
|---|---|---|
| `buffered` | 不可信渠道且入站为 enforce（默认） | 完整累积 → 审计 → 通过才回放。**零泄露**，代价是失去增量延迟 |
| `live` | 可信渠道，或入站为 report | 逐块即时转发，滑动窗口边收边审；命中致命规则则中断并以错误事件结束 |

滑动窗口保留固定重叠区，因此上游把 `Ignore previous instructions` 拆成多个 SSE delta
也逃不掉（验收测试 8.5，单测 `TestStreamDetectorCatchesSplitPattern`）。
响应头 `X-Customs-Stream-Mode` 明示本次用了哪种模式。

### 4. 路由 = 性价比 × 诚信

```
value = capability × fingerprint_match × reliability × usage_integrity² / 有效单价
```

- 价格用**本次请求的真实 token 量**计算，因此"本次才触发的用量阶梯优惠"会立刻反映到选路。
- `usage_integrity` 取平方，使被抓到虚报的渠道（0.5）比其线性份额受到更重惩罚。
- 未测量的项取中性值，新渠道不因缺少数据被惩罚或优待。
- 每次决策都写入 `route_reason`，可解释、可追责。

### 5. 价格归一化与优惠建模

上游价目形态各异，全部归一到「每百万 token 的输入/输出价」以便直接比较：

| 形态 | 处理 |
|---|---|
| `multiplier` | `price = base × model_ratio × group_ratio`，输出 = 输入 × completion_ratio |
| `flat` | 直接换算 |
| `per_request` | 按典型 token 量折算为等效每百万价（需给出典型配比） |
| `tiered` | 按典型用量做加权平均折叠为单一可比较价格 |
| `manual` | 手工录入 |

优惠建模（本项目增量）：**低谷时段倍率**（支持跨午夜窗口）、**用量阶梯**、
**订阅套餐盈亏平衡**（月费 / 包含额度 → 等效倍率）。对外统一输出
「给定输入/输出 token 量的**有效单价**」。

### 6. 密钥卫生

- 上游密钥与用户令牌**只从 env 文件读取**（`-env-file`），不进入可 world-readable 的配置。
- rc.d 在启动前检查 env 文件权限（必须 600/640）**且**确认服务用户可读。
- 凭证**永不写入审计账**：审计里只有 `excerpt_hash`（加盐 SHA-256 前缀）。
- 管理 API 的 `/admin/config` 只报告 `has_key: true/false`。
- **被拦截请求的原文不落盘**：只有被放行的交换才可能带脱敏样本。
  验收测试 5.3 / 9.1–9.4 逐条验证。

---

## 项目结构

```
custom-api/
├── src/customapi/             Go 模块（零第三方依赖）
│   ├── cmd/customsd/          海关代理
│   ├── cmd/benchd/            情报守护进程
│   ├── cmd/customsctl/        运维 CLI
│   └── internal/
│       ├── protocol/          L0  线协议类型、SSE 解析、原地改写
│       ├── config/            配置、校验、env 文件
│       ├── policy/            L2  出站/入站规则引擎 + 流式滑动窗口检测
│       ├── metering/          C   分词器估算、usage 比对
│       ├── meter/             价格归一化、优惠建模、报价
│       ├── route/             渠道择优、健康熔断、诚信降权
│       ├── audit/             防篡改审计账、锚点、校验
│       ├── store/             配额、周期重置、聚合视图
│       ├── intel/             L3  指纹 JS 散度、跑分套件与判分、价格采集
│       ├── discovery/         模型目录：上游发现结果与配置声明合并
│       └── gateway/           组装：HTTP 代理管线、流式、管理 API
├── src/customapi/web/         管理控制台（Vue 3 + Vite + TS，无 CDN、无外部字体）
├── deploy/
│   ├── rc.d/                  FreeBSD 服务脚本
│   ├── etc/                   配置模板与密钥模板
│   └── scripts/               安装器、部署驱动、验收测试、情报测试、mock 上游
├── lab/                       在 laboratory.lan 上驱动 libvirt 虚机的脚本
├── vm/                        libvirt 测试虚拟机定义与创建脚本
├── docs/                      部署、虚拟机、开发文档
└── dist/                      构建产物（发布目录 + SHA256SUMS）
```

---

## 测试

| 层次 | 内容 | 位置 |
|---|---|---|
| 单元测试 | 规则引擎、分词器标定、价格归一化、路由策略、审计链、SSE、配置 | `internal/*/*_test.go` |
| 集成测试 | 网关全管线：鉴权、配额、拦截、虚报检测、流式、故障、并发 | `internal/gateway/gateway_test.go` |
| 验收测试 | 89 项，在**真实 FreeBSD 上**对真实二进制运行 | `deploy/scripts/smoke-test.sh` |
| 情报测试 | 13 项，价格/指纹/跑分/评分闭环 | `deploy/scripts/intel-test.sh` |
| 前端测试 | 令牌处理逻辑，Node 直接跑真实模块 | `web/scripts/check-auth.mjs` |

验收测试除代理与计量外还覆盖：虚报检测、提示注入、恶意工具调用、滥用输入、
配额扣减与拒绝也记账、账本篡改检测、流式、密钥不泄漏、**提供商多 key 展开与按 key
故障转移**、**模型发现**、**三种协议**、**管理面可达性策略**。

```sh
./deploy/scripts/deploy.sh local-test    # 本机（含 -race）
./deploy/scripts/deploy.sh all           # 全链路 + FreeBSD 验收
ssh customapi-bsd 'sudo sh /usr/local/share/customapi/intel-test.sh'
cd src/customapi/web && npm run test     # 前端
```

---

## 与原始计划的差异（诚实记录）

| 计划 | 实现 | 原因 |
|---|---|---|
| 海关用 Go，可能引入 tiktoken 等库 | 纯标准库、零依赖 | 保证静态交叉编译与免代理部署；代价是分词为估算（见上文误差表与容差取舍） |
| 流式"边收边累计 + 分片缓冲匹配" | 不可信渠道默认**深度缓冲**，可信渠道 live | 深度缓冲才能真正做到"命中即不泄露"；live 模式命中时字节已转发 |
| `metering.tolerance` 未给出数值 | 默认 0.25 并说明推导 | 5% 类阈值会低于估算器噪声 |
| 模型指纹用 logprob + JS 散度 | 用响应长度分布 + JS 散度 | logprob 并非所有上游都开放；长度分布普遍可得且无需特权 |
| 用户/配额由 new-api 提供 | 网关**自带**独立配额账 | 计划要求"独立记账"；因此本系统即使不接 new-api 也能独立运行 |
| 未提及账本被替换 | 增加 dev/ino 检测与启动校验 | 实现过程中发现的真实缺口，已用验收测试固化 |
| 未提及上游协议差异 | 原生解析三种协议，同协议优先、翻译兜底 | 计划只提"OpenAI 兼容"；实际用户手里同时有 chat / responses / anthropic 三种客户端 |
| 未提及模型目录 | 增加模型发现与合并目录 | 多提供商下"有哪些模型、谁能供"必须可回答，否则没法选模型 |
| 未提及管理界面 | 自带一个九页控制台 | 计划只要求管理 API；没有界面等于每次发配额都要手写 curl |
| 未提及管理面可达性 | 监听 + 处理器两层收紧，远程需令牌 | 管理面能封号、能读审计账，把它绑到 0.0.0.0 不该是"顺手就发生"的事 |

---

## 状态

- 主机测试：`go vet` 干净，`gofmt` 干净，`go test -race` 全部包通过
- FreeBSD 验收：**89/89 通过**
- FreeBSD 情报闭环：**13/13 通过**
- 前端：构建通过，令牌处理逻辑单元测试全绿
- 服务托管：`customsd`、`benchd` 均由 `daemon(8)` 托管，降权为 `customapi` 用户，
  自带 pid 文件、日志与崩溃重启
- 控制台已在 laboratory.lan 的虚机上验证：LAN 内浏览器可打开九个页面，
  未带令牌时数据接口返回 401 并弹出令牌输入框

真实上游接入前请先阅读 [`docs/DEPLOYMENT-zh.md`](docs/DEPLOYMENT-zh.md) 的
「上线前检查清单」。

---

在已存在的 libvirt 主机（laboratory.lan）上部署的完整过程与踩坑记录见
[`docs/LAB-DEPLOYMENT-zh.md`](docs/LAB-DEPLOYMENT-zh.md)。
