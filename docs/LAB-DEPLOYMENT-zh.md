# 实验室部署（laboratory.lan）

本文件记录在**已存在的 libvirt 主机** `laboratory.lan` 上部署本系统的实际步骤，
以及过程中踩到的、只在真实环境中才会暴露的坑。它与 `docs/DEPLOYMENT-zh.md`
的关系是：后者讲目标机上的安装与运维，本文件讲**如何把虚拟机建起来并交付到那一步**。

---

## 1. 网络设计：用既有的 macvtap，不要动宿主机的网卡

宿主机 `laboratory.lan` 已有一条现成的 libvirt 网络：

```
external-macvtap:  <forward dev='eno1' mode='bridge'>
                     <interface dev='eno1'/>
```

接入方式：`<interface type='network'><source network='external-macvtap'/></interface>`。
guest 直接出现在 `10.10.1.0/24` 上，从该网段的 DHCP 取地址。

**关键教训：不要为了让 guest 上网而把宿主机的主网卡桥接掉。**

一开始把 `eno1` 改成了 Linux bridge（`br-lan`）并让网桥继承 `eno1` 的 MAC。
结果是：

- 宿主机网络短暂中断（`br-lan` 必须拿到载波才能激活，而无端口的网桥没有载波）；
- 原先就规划好的 `external-macvtap` 被绕开，等于把宿主机的网络拓扑改了 ——
  **这是错的**，即便它确实达到了让 guest 拿到 `10.10.1.x` 的目的。

恢复方式（已执行）：删除 `br-lan` 与 `eno1-slave` 两个连接、重新激活原有的 `eno1`
连接、删除回滚用的 systemd timer 与 `/usr/local/sbin/lab-bridge-rollback`。
`eno1` 现为 `10.10.1.129/24`，直接承载地址，与改动前完全一致。

**macvtap 的代价（必须知道）**：macvtap 在 bridge 模式下，**宿主机自己无法与
guest 通信**。所以：

| 从哪儿 | 能否访问 guest |
|---|---|
| 宿主机 `laboratory.lan` | ❌ 不能（macvtap 的固有限制） |
| 同一网段的其他主机 | ✅ 能 |
| guest 出网 | ✅ 能（经网关 10.10.1.2） |

本项目的 guest 本来就是**串口专用**（设计如此），所以这个限制不影响运维；
但如果将来需要宿主机直接管理 guest，就必须改用真正的网桥或宿主侧路由。

---

## 2. 交付链路：guest 从同网段的工作站取包

由于宿主机碰不到 guest，而 guest 是串口专用的，安装包通过**同网段的 HTTP 服务**交付：

```
工作站 10.10.1.128  ──HTTP:8899──▶  guest 10.10.1.167
   (python3 -m http.server，仅发布 release 目录)
```

guest 侧只需要 `fetch`：

```sh
fetch -q -o /tmp/rel.tar.gz http://10.10.1.128:8899/customapi-release.tar.gz
tar xzf /tmp/rel.tar.gz
sh /tmp/customapi-0.1.0-dev/scripts/install.sh
```

> 注意：guest 访问不了宿主机的 8899（macvtap 限制），所以服务必须跑在**别的**
> 同网段主机上。这一点在第一次尝试时表现为「ping 宿主机完全丢包」，原因就在上表第一行。

---

## 3. 三个只在 FreeBSD 上才会遇到的坑

### 3.0 先确认控制台真的没输出——别把"读取方式错误"当成"guest 死了"

本次重建虚机时，我把 guest 反复判定为"控制台静默、系统卡死"，浪费了大量时间在
离线改镜像、换 seed、加串口上。真实原因有两个，都与 guest 无关：

1. **`virsh console` 在没有 TTY 时拒绝运行**（`stdin is not a terminal`），
   所以自动化里不能用它；
2. 用脚本读 pty 时，如果按**非阻塞短读**循环（`read 3` 之类），循环会瞬间跑完，
   期间 guest 的输出来不及被捕获 —— 于是"什么都没读到"被误判成"什么都没输出"。

实测：同一台被判"静默"的 guest，用**保持 fd 打开的跟随式读取**立刻拿到了
`login:` 提示符。

`lab/console-follow.py` 就是为此写的：打开一次 pty，用 `select` 轮询指定时长，
可选在某个时刻注入输入（用于应答 bootloader 提示），并可 `--until PATTERN` 提前结束。

```sh
# 在 libvirt 主机上
sudo python3 lab/console-follow.py -d customapi-freebsd --seconds 30 --at 5 --send '\n'
```

**判据**：先用它确认真实输出，再怀疑 guest。若确实无输出，再去查 guest 是否在打印到
另一个控制台（`/boot/loader.conf` 的 `console=`），而不是直接判定系统损坏。

### 3.0.1 FreeBSD 装完 sshd 仍无法登录：两个默认值

开启 sshd 后 `ssh root@<guest>` 报 `Permission denied (publickey)`，
`/var/log/auth.log` 里是 `ROOT LOGIN REFUSED FROM ...`。原因是镜像的两个默认值：

| 项 | 默认 | 处理 |
|---|---|---|
| `PermitRootLogin` | `no`（FreeBSD 默认，被注释但生效） | 设为 `prohibit-password` |
| `/etc/ttys` 里没有 `pts` 条目 | 伪终端视为 **insecure**，root 登录被拒 | 追加 `pts none unknown off secure` |

```sh
sed -i '' 's/^#*PermitRootLogin.*/PermitRootLogin prohibit-password/' /etc/ssh/sshd_config
echo "pts none unknown off secure" >> /etc/ttys
service sshd restart
```

用 `sshd -T | grep -i permitrootlogin` 可以确认**生效值**——配置文件里被注释掉的那行
不代表它没生效，默认值同样会拒绝登录。

### 3.1 镜像的首次启动会升级整个基本系统

FreeBSD 官方 VM 镜像在 `/etc/rc.conf` 里带 `firstboot_pkg_upgrade_enable=YES`，
首次启动会从 pkgbase 仓库把 **80 个基础系统包**（约 547 MiB）原地升级一遍。
在运行的系统上替换 userland 与内核模块的后果，实测两次都是：
**guest 还活着，但串口控制台静默、网络无响应**，只能销毁重建。

从 `rc.conf.local` 里设 `firstboot_pkg_upgrade_enable=NO` **拦不住**它 —— 该升级在读到
这个文件之前就已经排入执行。可靠的抑制办法是让它**拿不到包**：

```yaml
# 首次启动期间故意给一个不可用的 DNS
- path: /etc/resolv.conf
  content: |
    nameserver 127.0.0.1
# 首次启动结束后再恢复真实解析器
runcmd:
  - printf 'nameserver 10.10.1.2\n' > /etc/resolv.conf
  - sysrc -f /etc/rc.conf.local firstboot_pkg_upgrade_enable=NO
```

### 3.2 `nuageinit` 的 `runcmd` 只接受字符串

FreeBSD 的 `nuageinit` 不是完整的 cloud-init。它写 `runcmd` 的方式是：

```lua
f:write(c .. "\n")     -- /usr/libexec/nuageinit:514
```

所以 cloud-init 常见的**数组形式**（`- [ sh, -c, "..." ]`）会让 `c` 变成 table，
抛 `attempt to concatenate a table value (local 'c')` 并**中断整个脚本**。
因为 `runcmd` 是最后一段，失败是静默的：guest 正常启动、`write_files` 与 `chpasswd`
都已生效，**只有命令没跑** —— 看起来像一台正常的机器，直到发现该做的事没做。

正确写法是每项一个字符串：

```yaml
runcmd:
  - sysrc -f /etc/rc.conf.local sshd_enable=NO
  - touch /var/db/customapi-seed.done
```

### 3.3 多行值插进 YAML 块标量会破坏文档

把多行变量直接插进 `content: |` 时，只有第一行继承缩进，其余行会「逃出」块，
整个文档解析失败（`could not find expected ':'`）。必须**显式给每一行加缩进**：

```sh
RC_BLOCK=$(printf '%s\n' "${RC_CONF}" | sed 's/^/      /')
```

配合 `lab/validate-seed.py` 在生成 ISO **之前**校验：YAML 可解析、`write_files`
结构完整、`chpasswd` 存在、`runcmd` 各项是字符串。一次校验远比一台半配置的 guest 便宜。

### 3.4 宿主机的 QEMU 路径与发行版有关

域定义里写死 `<emulator>/usr/bin/qemu-system-x86_64</emulator>` 在 Fedora 上可用，
在 CentOS/RHEL 系上会直接失败：`无法检查 QEMU 二进制文件 ...: 没有那个文件或目录`
（实际路径是 `/usr/libexec/qemu-kvm`）。**省略 `<emulator>` 元素**，让 libvirt 用它
自己配置好的默认值，跨发行版都正确。

---

## 4. 复现步骤

```sh
# 1) 在 libvirt 主机上创建并启动 guest（不触碰宿主机网络）
./lab/create-lab-vm.sh --network external-macvtap --name customapi-freebsd \
    --ip dhcp --dns 10.10.1.2 --disk-gb 60
virsh -c qemu:///system start customapi-freebsd

# 2) 串口登录（guest 无 SSH，控制台是唯一入口）
python3 deploy/scripts/serial-console.py -d customapi-freebsd login root customapi

# 3) 在同网段工作站发布 release
python3 -m http.server 8899 --directory dist

# 4) guest 内取包并安装
fetch -q -o /tmp/rel.tar.gz http://<workstation>:8899/customapi-release.tar.gz
tar xzf /tmp/rel.tar.gz && sh /tmp/customapi-0.1.0-dev/scripts/install.sh

# 5) 生成密钥、启动、验证
vi /usr/local/etc/customapi/customsd.env
chown root:customapi /usr/local/etc/customapi/customsd.env
chmod 640 /usr/local/etc/customapi/customsd.env
service customsd start
sh /usr/local/share/customapi/smoke-test.sh    # 78 项
sh /usr/local/share/customapi/intel-test.sh    # 13 项
```

> 装完 `customsd` 起不来、日志只有一行 `permission denied`，几乎总是同一个原因：
> **有人以 root 身份跑过 `customsctl audit rehash`（或手写账本），把
> `/var/db/customapi/audit.jsonl` 变成了 root 所有**，于是降权后的服务读不到自己的
> 证据库。安装器每次安装都会校正这些运行时文件的属主与权限，所以重跑一次
> `install.sh` 即可；`audit rehash` 本身现在也会保留原属主。

---

## 5. 交付形态与默认监听

| 监听 | 默认 | 理由 |
|---|---|---|
| `listen`（用户面） | `0.0.0.0:8080` | 部署这个网关就是为了让客户端能连上；只监听回环等于部署了个不可用的东西 |
| `admin_listen`（管理面） | `127.0.0.1:8081` | 管理面能发配额、能读审计账，默认必须经 SSH 隧道或反向代理访问 |

### 在实验环境里让 LAN 直接打开控制台

本实验的 guest 在 libvirt 主机上看不见（macvtap 的已知限制），而 **guest 没有 SSH**，
所以"用隧道"这条常规建议在这里走不通——隧道要有一条能到 guest 的 SSH 通路。
于是本实验采用另一种做法：把管理监听放到 LAN，用令牌把数据接口保护起来。

```sh
# customs.json
sed -i '' 's|"admin_listen": "127.0.0.1:8081"|"admin_listen": "0.0.0.0:8081"|' \
    /usr/local/etc/customapi/customs.json

# env 文件（令牌放这里，配置文件里留空）
CUSTOMS_SERVER_ADMIN_REMOTE=yes
CUSTOMS_SERVER_ADMIN_TOKEN=$(openssl rand -hex 24)
service customsd restart
```

此后在同网段的浏览器里打开 `http://<guest-ip>:8081/`，控制台会弹出令牌输入框。
未带令牌的 `/admin/*` 请求返回 401，`X-Forwarded-For` 伪造无效，
不带令牌的 API 调用在验收测试 13 组里逐条验证。

**安全边界要说清楚**：这等于"保护到一个共享密钥"。LAN 上任何拿到令牌的人都能封禁
用户、改写配额、读取整本审计账。实验环境可以这么做；真实环境要么用 SSH 隧道，
要么把管理监听放在受控网段，并定期轮换令牌。

免手工输入令牌（令牌走 URL fragment，不进服务器日志）：

```
http://<guest-ip>:8081/#token=<server.admin_token>
```
