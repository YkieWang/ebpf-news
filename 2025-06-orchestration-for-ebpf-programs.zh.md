# NetEdit 的构建：Meta 如何在大规模下管理 eBPF 程序

> 📝 原文标题：**Building NetEdit: Managing eBPF programs at scale at Meta**
> ✍️ 原作者：Theophilus A. Benson
> 📅 原文发布时间：2025 年 6 月 5 日
> 🌐 原文链接：[APNIC Blog](https://blog.apnic.net/2025/06/05/building-netedit-managing-ebpf-programs-at-scale-at-meta/?utm_source=hs_email&utm_medium=email&_hsenc=p2ANqtz--7rZ9I2o4fXp5AAF8geocFFUNBYylLPmjGJYDxXN6iNVcXEfNSUW1xxXPlAJG_ax73Q70Y)
> 🖼️ 原文插图：[图 1](https://img.ttkbd.com/i/2025/06/27/netedit-fig-1.png)、[图 2](https://img.ttkbd.com/i/2025/06/27/netedit-fig-2.png)
> 🔁 中文翻译：由社区爱好者翻译，仅供学习与技术交流之用
> 📌 说明：本文为 eBPF 前沿技术在大型互联网基础设施中的实际应用案例，介绍了 Meta 与卡耐基梅隆大学合作设计的 eBPF 管理平台 NetEdit 的架构与经验。

---

现代数据中心越来越依赖扩展 BPF（eBPF）来实现对网络、安全和诊断的精细化控制。然而，在大规模环境中部署和管理 eBPF 程序会遇到许多挑战，包括生命周期与内核的耦合、跨版本接口的不一致等。

Meta 最近与卡耐基梅隆大学合作，在 SIGCOMM 发表了一篇论文，详细记录了 Meta 如何应对这些挑战，并探讨了这样一个问题：**如何在大规模下轻松且快速地开发 eBPF 程序？**

在这篇博文中，作者介绍了 **NetEdit** 框架。它可以在数百万台服务器上编排 eBPF 程序，同时不影响性能或可用性。文中还介绍了该研究中提出的一些机制，以及这些机制在测试中的性能表现。

## 为什么 eBPF 具有价值

Meta 转向使用 eBPF，正是看中了其“专用性”所带来的巨大潜力。表 1 展示了他们在过去五年部署过程中所获得的一些性能收益：

| 调优功能                    | 基础设施收益         | 服务收益                  |
| ----------------------- | -------------- | --------------------- |
| 每连接初始拥塞窗口（Initial CWND） | 图像生成速度提升 30%   | 跨区域存储应用的 P99 延迟下降 30% |
| 每包 TCP 接收窗口             | 存储应用的重传率下降 90% | 存储读取速度提升 100%         |
| Jumbo MSS 调优            | 广告系统网络利用率下降 6% | 广告系统 CPU 使用率下降 6%     |
| 区域内连接使用基于 BPF 的 DCTCP   | 网络重传率下降 75%    | 商城与搜索应用的 P99 延迟提升 40% |

尽管这些收益令人印象深刻，但在开发这些程序时也遇到了不少重大挑战，例如文档缺失、eBPF 行为不一致、API 经常变动等。

## eBPF 在大规模部署中的挑战

理想情况下，eBPF 程序的开发应该复用当前云计算和数据中心中广泛使用的、经过严格验证的软件工程原则。eBPF 程序应具有高度可配置性，能适应大量服务的需求，并支持 CI/CD（持续集成与持续部署）。

但现实中，eBPF 程序的生命周期是通过内核暴露的接口来配置的，并由内核启发式算法管理——这种“命运绑定”关系限制了开发者的灵活性和敏捷性。

## NetEdit 的设计目标

当前 eBPF 生态系统虽然支持基础设施优化设计，但不易满足敏捷开发和快速演进的需求。尤其是 eBPF 直接访问内核这一特性，在大规模使用时带来如下挑战：

* **内核启发式管理**：eBPF 程序由内核管理，未被使用的程序可能被删除。但有些程序虽然看似“未使用”，实际上仍在为服务提供支持。
* **内核-BPF 接口变动频繁**：Meta 内部运行超过 10 个不同内核版本，这种接口差异使得管理更为复杂。
* **BPF-BPF 程序组合接口不稳定**：程序组合支持也受到内核接口不一致的影响。

## 用 BPFAdapter 将 eBPF 与内核解耦

为简化 BPF 与内核接口差异性问题，Meta 设计了 **BPFAdapter**：

* 提供统一的程序操作抽象（attach、配置等），隐藏 hookpoint 复杂性；
* 显式垃圾回收机制，避免依赖内核启发式逻辑；
* 支持重启后策略触发（如 bpf-iter）；
* 提供资源共享（共享 map）和惰性加载机制。

## PolicyEngine：动态策略控制核心

NetEdit 的 **PolicyEngine** 提供了一种灵活的配置机制，控制何时、如何为特定服务进行网络调优。

* 最小粒度为 tuningFeature（一组协同实现某一网络功能的 eBPF 程序）；
* 根据服务状态和连接集动态加载程序；
* 配置被写入到 BPF map 中，供程序使用；
* 设计上更关注系统稳定性和可调试性，而非性能最优。

这使 NetEdit 相比如 Cilium 这类静态部署管理器，在动态性上具备明显优势。

## 能力存储库：快速开发的加速器

NetEdit 提供了模块化能力库（capabilities）用于复用调试、策略和资源共享逻辑。

* 已实现 8+ 个能力模块；
* 三个 tuningFeature 的开发周期从 6 个月降至几周。

提升来源包括：

* 抽象设计加速核心逻辑开发；
* 通用组件（如连接解析器）复用；
* 自动化测试和发布机制。

> ![图1](https://img.ttkbd.com/i/2025/06/27/netedit-fig-1.png)
> 图 1 — tuningFeature 的开发速度对比

## 实践经验与研究挑战

在过去五年中，Meta 部署了 12 个以上的 tuningFeature，识别了若干工程问题与研究机会。

### hookpoint 选择问题

> ![图2](https://img.ttkbd.com/i/2025/06/27/netedit-fig-2.png)
> 图 2 — 每个 hookpoint 上运行的程序数量

选择 hookpoint 需考虑：

* 是否满足功能需求；
* 性能开销测试；
* 内核行为依赖分析。

### 程序组合问题（Program Composition）

多个程序部署在同一 hookpoint 上可能产生行为冲突，例如：

* 程序行为不一致；
* 相互覆盖动作导致结果错误；
* 程序未按需运行。

这凸显了构建组合感知框架的必要性。

### 测试框架不足

eBPF 程序需要更强大的测试框架（如 fuzzing）。由于其耦合特性，可能触发罕见的内核路径或全新交互。

### 自动化插桩工具缺失

动态验证需要更完善的插桩工具来自动记录日志信息。

## 总结与未来适用性

NetEdit 通过策略配置与执行解耦，在数据中心复杂环境中实现灵活网络调优。

这种设计思想也可能适用于其他使用 eBPF 的领域，如存储系统、调度器等。

---

> 原作者：Theophilus A. Benson（卡耐基梅隆大学电气与计算机工程系教授）
> 合作者：Prashanth Kannan、Prankur Gupta、Srikanth Sundaresan、Neil Spring、Ying Zhang

---

> 📎 原文链接：[https://blog.apnic.net/2025/06/05/building-netedit-managing-ebpf-programs-at-scale-at-meta](https://blog.apnic.net/2025/06/05/building-netedit-managing-ebpf-programs-at-scale-at-meta/?utm_source=hs_email&utm_medium=email&_hsenc=p2ANqtz--7rZ9I2o4fXp5AAF8geocFFUNBYylLPmjGJYDxXN6iNVcXEfNSUW1xxXPlAJG_ax73Q70Y)

> 📌 本文由社区爱好者翻译，内容版权归原作者与 APNIC 所有，若有侵权请联系删除。仅用于技术学习与传播。
