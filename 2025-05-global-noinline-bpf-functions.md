
# 全局非内联的 BPF 函数（Global No-Inline BPF Functions）

> 📅 原文日期：2025 年 5 月 11 日  
> ✍️ 原文作者：[Grant](https://www.grant.pizza)  
> 🌐 原文链接：[https://www.grant.pizza/blog/global-noinline](https://www.grant.pizza/blog/global-noinline/?utm_source=hs_email&utm_medium=email&_hsenc=p2ANqtz-_R-By50m7S18Pjz6cM53SvfvP278T8pPD7zLRWm3HUGMSgTuGcriIVec5WNZsQ_G14lLXN)  
> 🔁 中文翻译：由社区爱好者翻译，仅供学习与技术交流之用  
> 📌 本文介绍了 Linux 内核 BPF 校验器对函数内联与否的处理逻辑，以及使用 `static`、`__noinline` 和全局函数对验证行为、复杂度、堆栈使用的影响分析。

---

BPF 校验器（verifier）负责确保被加载的 BPF 程序能够在可预测的时间内终止并安全运行。它会遍历 BPF 指令的所有分支，将每一条指令都视为程序状态的一种变形。在遍历过程中，存在一个 **100 万条指令的限制**。

如果你写 BPF 程序已经有一段时间，或者接触过一些过时的示例，你可能熟悉 `static` 修饰符以及 `__always_inline` 宏。

在 Linux 内核 4.16（2018 年 4 月发布）之前，所有 BPF 程序中的函数确实都必须被内联。从该版本开始，BPF 支持所谓的 “BPF 到 BPF 函数调用”（bpf-to-bpf function calls）。本文将先介绍内联对程序的影响，以及为什么禁止内联可以扩展 BPF 程序的能力。

---

## 🧪 内联示例

```c
static __always_inline int print_map_value() {
    __u32 key = 0;
    __u64 *val = bpf_map_lookup_elem(&value_map, &key);
    if (!val) {
        return 1;
    }
    bpf_printk("val: %d", val);
    return 0;
}

SEC("uprobe/foobar")
int foobar(struct pt_regs *ctx) {
    __u64 val = 1;
    __u32 key = 0;
    bpf_map_update_elem(&value_map, &key, &val, 0);
    print_map_value();
    print_map_value();
    print_map_value();
    return 0;
}
````

在这个例子中，`__always_inline` 会将 `print_map_value()` 函数的内容复制三次，插入到主程序中。

你可以通过编译该程序后运行以下命令验证：

```bash
llvm-objdump -d <object_file>
```

使用内部工具执行 verifier 检查后得到结果：

```
Filename/Program: foo/foobar  
Stack Usage: 28  
Instructions Processed: 56  
Instructions Processed Limit: 1000000  
Max States per Instruction: 0  
Peak States: 4  
Total States: 4
```

---

## 🚫 改为禁止内联（`__noinline`）

```c
static __noinline int print_map_value() {
    ...
}

SEC("uprobe/foobar")
int foobar(struct pt_regs *ctx) {
    ...
    print_map_value();
    print_map_value();
    print_map_value();
    return 0;
}
```

输出结果变为：

```
Filename/Program: foo/foobar  
Stack Usage: 12  
Instructions Processed: 64  
Instructions Processed Limit: 1000000  
Max States per Instruction: 0  
Peak States: 6  
Total States: 6
```

✅ **栈使用下降（从 28 降到 12）**
⚠️ **指令数上升（从 56 升到 64）**

---

## ⚙️ Static vs Global 函数对 verifier 的影响

静态函数会继承调用者上下文，意味着参数的合法范围、类型等会被保留，但 verifier 必须在每次调用时都重新检查一遍。

全局函数不会继承调用上下文，因此只会被校验一次，但要求函数内部自己检查参数是否合法。

---

### ✅ 静态函数版本（校验器信任调用者已检查指针）

```c
static __noinline int print_dereferenced_value(__u32* foo_ptr) {
    __u32 foo;
    int i;
    for (i = 0; i < 100; i++) {
        foo = *foo_ptr;
        bpf_printk("foo+i = %d", foo+i);
    }
    return 0;
}
```

---

### 🧯 全局函数版本（需要自行做参数检查）

```c
__noinline int print_dereferenced_value(__u32* foo_ptr) {
    if (!foo_ptr) {
        bpf_printk("foo ptr is nil");
        return -1;
    }
    __u32 foo;
    int i;
    for (i = 0; i < 100; i++) {
        foo = *foo_ptr;
        bpf_printk("foo+i = %d", foo+i);
    }
    return 0;
}
```

---

### 📊 对比分析：

| 类型     | 指令数  | 状态总数 | 栈使用 |
| ------ | ---- | ---- | --- |
| Static | 1612 | 109  | 4   |
| Global | 1629 | 18   | 4   |

✅ 状态数明显下降
⚠️ 指令数略升（由于增加了 `if (!foo_ptr)` 的判断逻辑）

---

## 🔁 多次调用场景对比

```c
for (i = 0; i < 100; i++) {
    print_dereferenced_value(b);
}
```

| 类型     | 指令数    | 状态总数 |
| ------ | ------ | ---- |
| Static | 161305 | 1555 |
| Global | 2427   | 32   |

✅ 全局函数在多次调用下节省了大量验证器资源！

---

## ✅ 总结

* ✔️ `__noinline` 可以减少栈使用，但可能增加指令数。
* ✔️ 全局函数只需校验一次，适用于大量重复调用的情况。
* ⚠️ 全局函数必须自行验证参数合法性。
* ⚠️ 全局函数虽然验证器效率更高，但运行时有额外检查，可能略影响性能。

> 💡 BPF verifier 的目标是确保程序终止，而非限制复杂度本身。只要函数可独立证明其会终止，重复调用不会增加复杂度。

---

> 📘 本文翻译自 [Grant](https://www.grant.pizza) 于 2025 年 5 月发布的博文
> 📎 原文地址：[https://www.grant.pizza/blog/global-noinline](https://www.grant.pizza/blog/global-noinline/?utm_source=hs_email&utm_medium=email&_hsenc=p2ANqtz-_R-By50m7S18Pjz6cM53SvfvP278T8pPD7zLRWm3HUGMSgTuGcriIVec5WNZsQ_G14lLXN)
> 📌 本中文翻译仅用于学习与技术传播，如侵权请联系删除。
