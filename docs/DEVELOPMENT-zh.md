# 开发指南

## 1. 环境要求

| 用途 | 要求 |
|---|---|
| 构建网关 | Go 1.25+（实测 1.26.8）。**无第三方依赖**，不需要代理也能构建 |
| 构建 VM | libvirt、QEMU、`mkisofs`（或 `xorriso`）、`xz` |
| 验收测试 | 目标机上需要 `curl`、`jq`（或 `python3`）、`python3`（mock 上游） |
| 可选 | `pnpm`（本项目未使用；无前端构建步骤） |

国内镜像配置（本机）：

```sh
# Go 模块
go env -w GOPROXY=https://goproxy.cn,direct
go env -w GOSUMDB=sum.golang.google.cn
# FreeBSD 镜像与 pkg 源见 vm/create-vm.sh 与 docs/VM-zh.md
```

---

## 2. 代码结构

```
src/customapi/
├── cmd/
│   ├── customsd/     海关代理：两个监听器（用户面 + 管理面）
│   ├── benchd/       情报守护进程：prices / fingerprint / bench / score / run
│   └── customsctl/   运维 CLI
├── web/              管理控制台（Vue 3 + Vite + TS，独立 npm 工程）
│   ├── src/          main.ts / App.vue / router.ts / api.ts / auth.ts / store.ts
│   │                 components/（8 个展示组件）、views/（9 个页面）
│   └── scripts/      mock-admin.mjs（假管理 API）、check-auth.mjs（前端测试）
└── internal/
    ├── version/      构建标识（ldflags 注入）
    ├── protocol/     L0  三种线协议类型、SSE 读写、原地 JSON 改写、跨协议翻译
    ├── config/           配置、校验、env 文件、提供商展开、示例配置的回归测试
    ├── policy/       L2  出站/入站规则引擎、流式滑动窗口检测、脱敏
    ├── metering/     C   分词器估算、usage 比对（相对阈值 + 绝对下限）
    ├── meter/            价格归一化、优惠建模、报价
    ├── route/            渠道择优、健康熔断、诚信降权反馈
    ├── audit/            防篡改审计账、锚点、校验、替换检测、链重建
    ├── store/            配额、周期重置、聚合
    ├── discovery/        模型目录：上游发现结果与配置声明合并、缓存
    ├── intel/        L3  指纹 JS 散度、跑分套件与判分、价格采集、评分装配
    └── gateway/          组装层：HTTP 管线、流式、管理 API、限流、管理面可达性
```

### 分层依赖方向

```
protocol ← metering ← gateway
protocol ← policy   ← gateway
config   ← 所有层
meter    ← route    ← gateway
store, audit, discovery ← gateway
intel    ← cmd/benchd
```

`discovery` 只依赖 `config` 与 `protocol`：它做的判断是"这个模型名该不该出现在目录里"，
不需要知道价格、配额或安全策略，因此网关之外的调用者（管理 API、测试）也能直接用它。

**刻意避免的依赖**：`route` 不依赖 `metering`。若需要表达"用量偏差"，
`route` 自带一个 `route.Deviation` 值类型，由 `gateway` 在调用处做转换；
否则会形成 `metering → protocol`、`route → metering` 的耦合，把"选路"与
"分词"这两个本应独立的关注点绑在一起。

---

## 3. 本地开发循环

```sh
cd src/customapi

go build ./...                      # 全量构建
go vet ./...                        # 静态检查
gofmt -l .                          # 格式检查（应无输出）
go test ./internal/... -count=1     # 单元 + 集成测试
go test ./... -race -count=1        # 竞态检测（提交前必跑）
go test ./internal/policy/ -run TestCheckInbound -v

# 覆盖率
go test ./internal/... -cover -count=1
```

一键：

```sh
./deploy/scripts/deploy.sh local-test    # vet + race 测试 + 覆盖率
```

### 用 curl 手工打网关

```sh
cat > /tmp/dev.json <<'EOF'
{
  "server": {"listen":"127.0.0.1:8080","admin_listen":"127.0.0.1:8081",
             "audit_path":"/tmp/dev/audit.jsonl","state_path":"/tmp/dev/state.json",
             "price_path":"/tmp/dev/prices.json","log_level":"debug"},
  "channels": [{"name":"mock","base_url":"http://127.0.0.1:18080","protocol":"openai",
                "models":{"mock-basic":"mock-basic"}}],
  "users": [{"name":"dev","token":"dev-token","quota":0}],
  "prices": [{"channel":"mock","model":"mock-basic",
              "price":{"input_per_m":10,"output_per_m":30,"currency":"CNY"}}]
}
EOF
mkdir -p /tmp/dev

# 起一个 mock 上游（复用验收测试用的那个）
python3 deploy/scripts/mock-upstream.py 18080 &

go run ./cmd/customsd -config /tmp/dev.json &

curl -sS http://127.0.0.1:8080/v1/chat/completions \
  -H "Content-Type: application/json" -H "Authorization: Bearer dev-token" \
  -d '{"model":"mock-basic","messages":[{"role":"user","content":"hi"}]}' | jq .

go run ./cmd/customsctl audit tail -config /tmp/dev.json -n 5
go run ./cmd/customsctl audit verify -config /tmp/dev.json
```

mock 上游的行为可以用控制接口切换：

```sh
curl -X POST http://127.0.0.1:18080/admin/control -d '{"reply":"自定义回复"}'
curl -X POST http://127.0.0.1:18080/admin/control -d '{"force_status":500}'
```

模型名选择行为：`mock-basic` 诚实、`mock-inflate` 虚报 20 倍、
`mock-inject` 返回注入载荷、`mock-toolcall` 返回危险工具调用。

---

## 4. 增加一条检测规则

规则分两类，都在 `internal/policy/rules.go`：

```go
// 关键词规则：大小写不敏感的子串匹配
{
    id: "default.my_new_rule", dir: Inbound, sev: SevHigh, field: "response",
    detail: "一行给运维看的说明",
    keywords: []string{"触发短语", "another phrase"},
},

// 正则规则：需要容忍空白/变体时使用
{
    id: "default.my_regex_rule", dir: Inbound, sev: SevCritical, field: "response",
    detail: "...",
    re: mustCompile(`(?i)\bfoo\b[^\n]{0,80}\bbar\b`),
},
```

**规则 ID 是稳定契约**：它会原样出现在审计记录里，运维的日志查询依赖它，
重命名是破坏性变更。

然后：

1. 在 `internal/policy/policy_test.go` 的表驱动用例里加入**正例与反例**——
   反例（良性文本不应命中）和正例同样重要，否则规则会退化成"什么都拦"。
2. 若规则涉及流式，加一条 `TestStreamDetector...` 把短语**拆成多块**验证
   滑动窗口能重组。
3. 跑 `go test ./internal/policy/ -count=1`。

---

## 5. 增加一个供应商的价格形态

在 `internal/meter/price.go` 的 `Normalize` 里加一个 scheme 分支，并补测试。
归一化的目标是产出一对「每百万 token 的输入/输出价」——只有落到这个形状，
不同上游才可比。

```go
case "my_scheme":
    pm.InputPerM = 从原始字段换算(...) * rate
    pm.OutputPerM = pm.InputPerM * cr
```

要求：

- **无法可靠换算时返回 error，不要猜**。错误的价格会污染路由决策，
  比缺失价格危险得多（`TestCollectPricesSkipsUnknownQuotaType` 固化了这一点）。
- 保留 `Source` 与 `Scheme` 字段，让价格可追溯、可审计。

---

## 6. 测试策略与约定

| 层次 | 目的 | 位置 |
|---|---|---|
| 单元 | 纯函数、规则表、换算、判分 | `internal/<pkg>/*_test.go` |
| 集成 | 网关全管线，用 `httptest` 伪造上游 | `internal/gateway/gateway_test.go` |
| 前端 | 令牌处理（Node 跑真实模块，不装浏览器） | `web/scripts/check-auth.mjs` |
| 在线验收 | 真实 FreeBSD + 真实二进制（89 项） | `deploy/scripts/smoke-test.sh` |
| 情报闭环 | 取价/指纹/跑分/评分（13 项） | `deploy/scripts/intel-test.sh` |

> 前端测试用 `typescript`（已是 devDependency）把 `src/auth.ts` 剥类型后在 Node 里
> 加载，并注入 `sessionStorage` / `window.history` 等最小浏览器全局。
> 这一段代码只在部署后的控制台里跑，用浏览器做自动化成本高、还不稳定；
> 用 Node 跑真实模块，成本和稳定性都更好。

几条本仓库坚持的约定：

1. **安全属性要有专门的反向测试。** 例如"诚实上游不被误报"
   （`TestHonestUpstreamKeepsFullIntegrity`）与"20 倍虚报必被抓"
   （`TestInflationStillCaughtWithFloor`）成对存在。只测"能抓到"会诱使阈值越调越紧，
   最终把正常流量全部误伤。
2. **测试要能发现真问题，而不是复述实现。** 本次开发中，写入测试后被发现并修复的
   真实缺陷包括：`store` 回调重入死锁、`route` 的 `HealthTracker` 与 RNG 数据竞争、
   `Content.Parts` 字段遮蔽方法、无限偏差导致审计账无法序列化、`Content-Length`
   未随改写后的 body 更新、缓冲流式在校验前提交了 200 状态、`sed` 未处理行尾导致
   JSON 路径转换失效。
3. **改了存储格式就要有"旧数据仍可校验"的测试。** `Latency` 字段改名时，哈希是对
   **重新序列化的结构体**算的，于是 96 条历史记录全部无法验证。修复后补了
   `TestVerifiesALedgerWrittenByAnOlderSchema`、`TestTamperingIsStillDetectedAfterTheHashChange`
   与 `TestRemovingEntryHashIsDetected`：哈希改为对**存储的字节**计算，
   并且必须证明改名前后"篡改仍然能被发现"——只证明"现在能验证"是不够的。
4. **以 root 跑的运维动作要有归属与权限的测试。** `customsctl audit rehash` 重建文件时
   用临时文件 + rename，会把账本变成 root 所有，导致**服务下一次启动报权限拒绝**。
   `TestRehashPreservesLedgerOwnership` 会在非 root 下跳过、在 root 下验证属主与权限
   被保留（用 `sudo go test` 跑）。
3. **验收测试必须能在目标机上独立运行**，不依赖开发机、不依赖网络（用 mock 上游）。
4. **不要为了让测试通过而放宽断言。** 如果一条断言反复失败，先确认是被测代码错了
   还是断言错了——本次两者都发生过（`DetectProtocol` 的期望确实是测试写错了，
   而计量误报是代码错了）。
5. **安全相关的默认值要用测试钉住。** 管理面的远程访问默认关闭、空令牌不等于放行、
   伪造的 `X-Forwarded-For` 不能冒充环回——这些都在
   `internal/gateway/admin_access_test.go` 与 `TestAdminRemoteIsOffUnlessConfigured`
   里，改动这类代码时它们会先炸。

---

## 7. 交叉编译与部署

```sh
cd src/customapi/web && npm ci && npm run build   # 先构建前端，stage 才会带上它
cd ../../..
./deploy/scripts/deploy.sh build      # CGO_ENABLED=0 GOOS=freebsd GOARCH=amd64
./deploy/scripts/deploy.sh stage      # dist/customapi-<version>/ + SHA256SUMS
./deploy/scripts/deploy.sh ship       # scp 到 $CUSTOMAPI_TARGET
./deploy/scripts/deploy.sh install
./deploy/scripts/deploy.sh test
```

`stage` 会把 `web/dist` 一起打进发布包。**前端不参与 Go 构建**：网关从磁盘读
`web/dist`（默认在 `/usr/local/share/customapi/web`，可用 `CUSTOMS_WEB_DIR` 覆盖），
目录不存在时提供一个说明页而不是启动失败——所以干净检出也能 `go build`，
纯后端部署也能跑。

版本号来自 `internal/version/version.go` 的 `Version` 变量，commit 与构建时间由
`deploy.sh` 通过 `-ldflags -X` 注入。

**CGO 必须关闭**：目标是"单文件丢到目标机就能跑"，不引入任何 port 依赖。

---

## 8. 代码风格

- 注释解释**为什么**，不解释**是什么**。`// increment i` 是噪声；
  `// The floor is not optional: on a short reply one token is a large relative deviation`
  是信息。
- 导出的类型与函数必须有文档注释。
- 错误信息要能直接指导操作，例如
  `chown root:customapi ... && chmod 640 ...` 而不是 `permission denied`。
- 审计记录里**绝不写入用户原文或密钥**，只写加盐哈希与规则名。
- 结构性取舍（例如容差默认值的推导）写进文档，不要只留在代码注释里。

---

## 9. 调试技巧

```sh
# 最详细的日志
customsd -config ... -log-level debug

# 只看某类请求
customsctl audit tail -config ... -n 50 -verdict over_billed
customsctl audit tail -config ... -actor alice

# 审计记录里的样本（默认不下发，需显式请求）
curl 'http://127.0.0.1:8081/admin/audit?limit=5&include_samples=true'

# 路由为什么选了它
curl -s http://127.0.0.1:8081/admin/audit | jq -r '.records[0].route_reason'

# 分阶段延迟（全部毫秒，字段名自带单位：total_ms / outbound_audit_ms /
# upstream_ms / inbound_audit_ms / ttfb_ms）
curl -s http://127.0.0.1:8081/admin/audit | jq '.records[0].latency_ms'

# 这一次为什么被翻译了（客户端协议 vs 上游实际协议）
curl -s http://127.0.0.1:8081/admin/audit | jq '.records[] | select(.translated) | {protocol, upstream_protocol, model}'

# 提供商和它展开后的渠道
curl -s http://127.0.0.1:8081/admin/providers | jq '.providers[] | {name, supports, channels: [.channels[].channel]}'

# 模型目录（配置声明的与发现来的分别标记）
curl -s http://127.0.0.1:8081/admin/models | jq '.models[] | {model, configured, channels: [.channels[].channel]}'

# 在 FreeBSD 上看某次验收测试的全部产物
sudo ls -dt /tmp/customapi-e2e.* | head -1
sudo cat $(sudo ls -dt /tmp/customapi-e2e.* | head -1)/gateway.log
```

---

## 10. 已知的工程债

诚实记录，便于后续取舍：

| 项 | 现状 | 影响 | 建议 |
|---|---|---|---|
| 分词器为无词表估算 | 误差 −46%…+17% | 严格核验受限；靠绝对下限抑制误报 | 若要 5% 级核验，接入真实 BPE 词表（约 1.5 MB 数据） |
| 跨协议翻译是"降级可用"而非等价 | 三种协议都能收发；`openai → responses` 与 `openai → anthropic` 有逐事件的流式翻译，其余组合退化为整包缓冲后转换 | 工具调用、思考字段、服务端状态在跨协议时会退化；因此默认"先同协议" | 需要更高保真时，优先让上游讲同一种协议，而不是加强翻译 |
| 管理面外壳不受门禁 | HTML/JS/CSS 对未认证调用者可见，数据接口受门禁 | 暴露"这里有个控制台"，不暴露任何数据 | 有意设计：否则浏览器拿不到输入令牌的页面 |
| 平台级限流未做 | 用户级限流已做；跨进程/集群级未做 | 单实例假设 | 多实例部署时前置共享限流 |
| 指纹特征为响应长度 | 依赖 JS 散度于长度分布 | 对"刻意模仿长度"的替代模型不敏感 | 有 logprob 权限时可加 token 分布维度 |
| `benchd` 任务是串行的 | 逐渠道逐模型顺序执行 | 渠道多时一轮耗时长 | 需要时加并发（注意上游限速） |
| 无 Web UI | 管理/用户面均为 JSON API + CLI | 需要界面才能给非技术用户用 | 按计划 M5 补前端 |
