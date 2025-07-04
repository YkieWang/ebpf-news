# eBPF 之谜：什么时候 IPv4 不是 IPv4？当它假装是 IPv6 的时候！

> 原文作者：GripDev （[https://blog.gripdev.xyz/2025/05/06/ebpf-mystery-when-is-ipv4-not-ipv4-when-its-ipv6/）](https://blog.gripdev.xyz/2025/05/06/ebpf-mystery-when-is-ipv4-not-ipv4-when-its-ipv6/）)
>
> 原文日期：2025年5月6日
>
> 本文翻译仅用于学习与交流，版权归原作者所有

---

这个故事始于一个非常简单的 eBPF 程序：我想要透明地重定向某个程序（或 Docker 容器）内的 DNS 请求（端口 53）。

为此，我使用了 `BPF_CGROUP_INET4_CONNECT` 钩子，它允许我在某个进程执行 `syscall.connect` 时拦截连接请求，并进行检查和重定向。以下是一个简化示例：

```c
int handle_connect_redirect(struct bpf_sock_addr *ctx, __be32 original_ip,
                            bool is_connect4, struct redirect_result *result) {
  __be32 new_ip = original_ip;
  __be16 new_port = ctx->user_port;

  if (ctx->user_port == bpf_htons(53)) {
    new_ip = const_mitm_proxy_address; // 中间人 DNS 代理服务器地址
    new_port = bpf_htons(const_dns_proxy_port);
  }

  result->is_redirected = did_redirect;
  result->ip = new_ip;
  result->port = new_port;
  return 1;
}

SEC("cgroup/connect4")
int connect4(struct bpf_sock_addr *ctx) {
  struct redirect_result r = {
      .ip = ctx->user_ip4,
      .port = ctx->user_port,
      .is_redirected = false,
  };
  handle_connect_redirect(ctx, ctx->user_ip4, true, &r);
  if (r.is_redirected) {
    ctx->user_ip4 = r.ip;
    ctx->user_port = r.port;
  }
  return 1;
}
```

由于这些机器不支持 IPv6，我当时以为这套方案已经足够完整。

为了防止有人绕过这个重定向、直接访问 IP，我还加了一个 `BPF_PROG_TYPE_CGROUP_SKB` 程序，大致长这样：

```c
SEC("cgroup_skb/egress")
int cgroup_skb_egress(struct __sk_buff *skb) {
  if (skb->family == AF_INET6) {
    struct event info = {
        .eventType = PACKET_IPV6_TYPE,
        ...
    };

    bpf_ringbuf_output(&events, &info, sizeof(info), 0);
    return EGRESS_DENY_PACKET;
  }
  // 然后检查目标地址是否允许，允许则放行
```

> 注：我在 eBPF 中使用 `bpf_ringbuf_output` 将事件输出到用户空间，这对排查 bug 非常有帮助。

事情发展得很好……直到有用户尝试使用 dotnet CLI。

他们运行 `dotnet add package x` 命令后，命令挂起，并持续输出大量 `PACKET_IPV6_TYPE` 的日志。

## 哦，dotnet 使用了 IPv6？

初步判断：可能是系统真的发出了 IPv6 请求。

于是我做了几个检查：

* ✅ 我的 `connect4` 程序**没有被触发**，我加了 `bpf_ringbuf_output` 日志验证了这一点。
* ✅ 用 Wireshark 抓包发现：dotnet 没有向外发出 IPv6 请求；而且机器也不能访问公网 IPv6。

此时我陷入迷惑：

* 抓包看到的是 IPv4 请求；
* `egress` 程序看到的是 IPv6；
* `connect4` 没有被触发；

这三者完全矛盾！

## 开始啃源码

这时候我意识到自己一定是遗漏了什么。

我开始深入阅读 kernel 源码、eBPF 行为和 dotnet 实现，看看 dotnet cli 是否做了什么特别的事情，因为其他工具并没有类似的问题。

于是我尝试添加 `connect6` 钩子，用来捕捉 IPv6 的 `connect` 系统调用。

```c
SEC("cgroup/connect6")
int connect6(struct bpf_sock_addr *ctx) {
  struct event info = {
      .eventType = IPV4_VIA_IPV6_REDIRECT_TYPE,
  };
  bpf_ringbuf_output(&events, &info, sizeof(info), 0);
  return 1;
}
```

然后我运行 `dotnet add package x`，`connect6` 立即被触发了！但 Wireshark 明明看到的是 IPv4 出站流量。

唯一可能的解释就是：**内核看到的是 IPv6，但最终发出的确实是 IPv4**。

这让我想起了“Dual Stack 网络”。深入阅读 dotnet 源码后，我找到了这一段：

> 从 .NET 5 起，我们在 `SocketsHttpHandler` 中使用 DualMode 套接字。这允许我们使用 IPv6 套接字发送 IPv4 请求。

它还有一个关闭开关！我尝试关闭 DualMode 选项，一切恢复正常！`connect4` 开始生效，`egress` 不再认为请求是 IPv6。🚀

## 什么是 IPv4 映射 IPv6 地址

这一句是关键：

> 使用 IPv6 套接字发送 IPv4 请求

继续查文档与源码后我发现：这其实是一种标准特性，叫 **IPv4-mapped IPv6 address**，用于在 IPv6 套接字中封装 IPv4 地址。

IPv4 映射地址的结构如下：

```
::ffff:1.1.1.1
```

前 96 位固定，后 32 位就是 IPv4 地址。

我更新了 `connect6` 程序来输出 IPv6 地址，果不其然，我看到了类似 `::ffff:1.1.1.1` 的 IPv4 映射地址。🤯🎉

这就是谜底了。

当 dotnet 使用 DualMode 套接字时，它实际会创建一个 IPv6 套接字，并将 `ctx->user_ip6` 填写为 IPv4 映射地址。

虽然你看到的是 IPv6 地址字段，其实最终仍是 IPv4 请求。Linux 内核支持这种行为，会在网络层转换回 IPv4 并发出。

也因此 Wireshark 没抓到 IPv6，eBPF 看到了 IPv6，而 `connect4` 没触发。

## 修复 eBPF：处理 IPv4 映射 IPv6 地址

为了让拦截逻辑正常生效，我们必须同时拦截 IPv4 和 IPv6 套接字连接。

我们更新 `connect6`，识别 `::ffff:x.x.x.x` 格式的地址，并提取出其中的 IPv4：

```c
SEC("cgroup/connect6")
int connect6(struct bpf_sock_addr *ctx) {
  if (ctx->user_ip6[0] != 0 || ctx->user_ip6[1] != 0 ||
      ctx->user_ip6[2] != bpf_htonl(0x0000ffff)) {
    return 1;
  }

  __be32 ipv4_address = ctx->user_ip6[3];

  struct event info = {
      .ip = bpf_ntohl(ipv4_address),
      .eventType = IPV4_VIA_IPV6_REDIRECT_TYPE,
  };
  bpf_ringbuf_output(&events, &info, sizeof(info), 0);

  struct redirect_result r = {
      .ip = ipv4_address,
      .port = ctx->user_port,
      .is_redirected = false,
  };
  handle_connect_redirect(ctx, ipv4_address, false, &r);
  if (r.is_redirected) {
    ctx->user_ip6[3] = r.ip;
    ctx->user_port = r.port;
  }
  return 1;
}
```

## 修复 egress 拦截程序

上面的修复对 connect 有效，但 egress 程序仍然误判其为 IPv6 而阻止发包。

问题出在这段代码：

```c
if (skb->family == AF_INET6) {
  return 0;
}
```

此处使用的是 `family` 字段，但 IPv4-mapped IPv6 依然会返回 `AF_INET6`。

于是我改用 `skb->protocol` 进行区分：

```c
if (skb->protocol == bpf_htons(ETH_P_IPV6)) {
  // 真正的 IPv6 才会命中这里
  return 0;
}
```

最终，完美运行 🎉

---

## 总结：什么时候 IPv4 不是 IPv4？

答案是：

> 当它通过 IPv4-Compatible IPv6 Address 被发送时 🤯
