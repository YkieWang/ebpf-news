# QUIC 重启与性能问题：udpgrm 前来救援

> 原文：[QUIC restarts, slow problems: udpgrm to the rescue](https://blog.cloudflare.com/quic-restarts-slow-problems-udpgrm-to-the-rescue/)  
> 作者：Marek Majkowski  
> 译者：yuting wang（社区无偿翻译）  
> 版权归原作者所有，本文仅用于 eBPF 中文社区学习交流。

---

在 Cloudflare，我们尽力避免服务中断。我们频繁地部署新版本服务代码，因此需要在不中断服务的情况下重启服务进程，尤其是在支持 UDP 的服务器上实现优雅重启（zero downtime），却是个意外的难题。

之前我们写过关于 TCP 优雅重启的文章，那比 UDP 容易很多。直到最近 HTTP/3 与 QUIC 等协议变得重要，我们才开始解决 UDP 的重启问题。

这篇文章介绍了 [**udpgrm**](https://github.com/cloudflare/udpgrm)：一个轻量级守护进程，可以帮助我们在不丢失数据包的前提下重启 UDP 服务。

---

## 背景历史

早期的互联网中，UDP 通常用于无状态的请求-响应协议（如 DNS、NTP），这种情况下服务重启不会有太大问题。但现代协议如 QUIC、WireGuard、SIP，以及在线游戏等都依赖 **有状态连接**。

当服务进程重启时，连接状态会丢失，从而中断连接。虽然可以在进程之间迁移连接状态，但这极其复杂，且容易出错。

对于 TCP，通常的做法是让旧服务继续运行一段时间，等待连接自然关闭，而新连接交由新进程处理。这套方法也适用于 UDP，但实现更复杂，因为 UDP 缺乏内建的连接管理机制。

---

## reuseport 与 eBPF 的解决方案

之前我们使用过“established-over-unconnected”的方式来做流迁移，但这种方法存在竞态问题和可扩展性差的问题。

现在，我们找到了一种更好的方式：利用 Linux 的 **`SO_REUSEPORT`** 和 eBPF 技术，实现端到端的流级别粘性路由。这正是 **udpgrm** 的实现原理。

---

## 什么是 REUSEPORT 组？

Linux 中 `SO_REUSEPORT` 允许多个 socket 绑定到同一个 IP:port 元组，常用于将流量均衡分配到多个 CPU 核心。

这些共享同一地址的 socket 会被组织成一个 **reuseport group**：

```

┌───────────────────────────────────────────┐
│ reuseport group 192.0.2.0:443             │
│ ┌───────────┐ ┌───────────┐ ┌───────────┐ │
│ │ socket #1 │ │ socket #2 │ │ socket #3 │ │
│ └───────────┘ └───────────┘ └───────────┘ │
└───────────────────────────────────────────┘

````

内核提供多种方法在组内分发数据包，例如：

- 默认使用 4 元组哈希
- `SO_INCOMING_CPU`：将数据包分配到接收它的 CPU 核心对应的 socket
- `SO_ATTACH_REUSEPORT_CBPF` / `SO_ATTACH_REUSEPORT_EBPF`：允许自定义 BPF 程序决定路由逻辑

---

## 一个简单的 eBPF 路由程序示例

```c
SEC("sk_reuseport")
int udpgrm_reuseport_prog(struct sk_reuseport_md *md)
{
    uint64_t socket_identifier = xxxx;
    bpf_sk_select_reuseport(md, &sockhash, &socket_identifier, 0);
    return SK_PASS;
}
````

它使用 `bpf_sk_select_reuseport()` 从 eBPF map 中选择 socket，例如 `SOCKHASH`：

```c
struct {
	__uint(type, BPF_MAP_TYPE_SOCKHASH);
	__uint(max_entries, MAX_SOCKETS);
	__uint(key_size, sizeof(uint64_t));
	__uint(value_size, sizeof(uint64_t));
} sockhash SEC(".maps");
```

注意：该 map 需由用户态维护。udpgrm 就是为了解决这个难点诞生的。

---

## Socket generation 与 Working generation

为了实现 UDP 流的优雅重启，udpgrm 引入了 **socket generation（套接字代际）** 的概念。它指的是 reuseport 组中属于同一逻辑应用实例的一组 socket：

```
┌───────────────────────────────────────────────────┐
│ reuseport group 192.0.2.0:443                     │
│  ┌─────────────────────────────────────────────┐  │
│  │ socket generation 0                         │  │
│  │  ┌───────────┐ ┌───────────┐ ┌───────────┐  │  │
│  │  │ socket #1 │ │ socket #2 │ │ socket #3 │  │  │
│  │  └───────────┘ └───────────┘ └───────────┘  │  │
│  └─────────────────────────────────────────────┘  │
│  ┌─────────────────────────────────────────────┐  │
│  │ socket generation 1                         │  │
│  │  ┌───────────┐ ┌───────────┐ ┌───────────┐  │  │
│  │  │ socket #4 │ │ socket #5 │ │ socket #6 │  │  │
│  │  └───────────┘ └───────────┘ └───────────┘  │  │
│  └─────────────────────────────────────────────┘  │
└───────────────────────────────────────────────────┘
```

当服务需要重启时，新版本创建新的 generation，旧版本继续运行。我们将用以下逻辑处理路由：

* **新连接 → 当前 working generation**
* **老连接 → 对应旧 generation，直到自然断开**

---

## udpgrm 守护进程：管理员视角

### 启动方式

```bash
sudo udpgrm --daemon
```

输出：

```
[*] Tailing message ring buffer  map_id ...
```

要完整启用功能，还需挂载 cgroup 钩子：

```bash
sudo udpgrm --install --self
```

或

```bash
sudo udpgrm --install=/sys/fs/cgroup/system.slice
```

### 查看状态与指标

```bash
sudo udpgrm list
```

---

## 程序员如何使用 udpgrm

在程序中：

```python
sd = socket.socket(AF_INET, SOCK_DGRAM, 0)
sd.setsockopt(SOL_SOCKET, SO_REUSEPORT, 1)
sd.bind(("192.0.2.1", 5201))

# 检查 udpgrm 是否运行
work_gen = sd.getsockopt(IPPROTO_UDP, UDP_GRM_WORKING_GEN)

# 注册新 generation
sd.setsockopt(IPPROTO_UDP, UDP_GRM_SOCKET_GEN, work_gen + 1)

# 等待注册生效
...

# 设置新的 working generation
sd.setsockopt(IPPROTO_UDP, UDP_GRM_WORKING_GEN, work_gen + 1)
```

---

## systemd 配置：高级用法

为绑定低端口使用 `udpgrm_activate.py`：

```ini
[Service]
Type=notify
NotifyAccess=all
FileDescriptorStoreMax=128

ExecStartPre=/usr/local/bin/udpgrm_activate.py test-port 0.0.0.0:5201
```

为兼容 systemd 的单实例管理逻辑，使用 `mmdecoy` 脚本：

```ini
ExecStart=/usr/local/bin/mmdecoy your_server.py

Restart=always
KillMode=process
KillSignal=SIGTERM
```

完整模板：

```ini
[Service]
Type=notify
NotifyAccess=all
FileDescriptorStoreMax=128

ExecStartPre=/usr/local/bin/udpgrm --install --self
ExecStartPre=/usr/local/bin/udpgrm_activate.py --no-register test-port 0.0.0.0:5201
ExecStart=/usr/local/bin/mmdecoy your_server.py
```

---

## 三种内置流识别器（dissector）模式

### 1. DISSECTOR\_FLOW

* 使用 flow hash 建立流表（如 4 元组）；
* 流量达到 sendmsg 才加入表；
* 简单直观，适用于传统 UDP 协议；
* 流表容量有限。

### 2. DISSECTOR\_CBPF

* 每个包中包含“cookie”，由协议本身携带；
* e.g., QUIC 的 connection ID；
* 使用 cBPF 解析逻辑；
* 性能差一些，但不需要 udpgrm 自建状态表。

### 3. DISSECTOR\_NOOP

* 无状态模式；
* 适用于 DNS 等无连接服务；
* 可确保升级过程不丢包。

---

## 高级扩展：DISSECTOR\_BESPOKE

* 用户自定义逻辑；
* 当前已内建 QUIC dissector，可根据 TLS SNI 选择目标 socket generation；
* 性能最优，自由度最高。

---

## 总结

QUIC 和其他现代 UDP 协议的发展，要求我们能够优雅重启 UDP 服务。udpgrm 提供了一种可行的解决方案，结合：

* `setsockopt()` API；
* eBPF + REUSEPORT；
* 灵活可扩展的流识别逻辑；
* 与 systemd 的良好集成。

希望这些机制最终能推动 Linux 和 systemd 原生支持 UDP 优雅重启。
