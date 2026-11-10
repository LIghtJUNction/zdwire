# zdwire 0.1.0 交付与验证报告

日期：2026-11-10。

代码已提交到 [LIghtJUNction/zdwire](https://github.com/LIghtJUNction/zdwire)。
实现版本 [382059b](https://github.com/LIghtJUNction/zdwire/commit/382059b77a9d657b27ace05fc9cb08a11ba8667e)
的 [GitHub CI](https://github.com/LIghtJUNction/zdwire/actions/runs/42753211574)
已通过全部 13 个作业。本报告与基准数据在随后的文档提交中归档。

## 已交付的功能

发布 crate 始终使用 `#![no_std]`，仅引用 `core`，并通过
`#![forbid(unsafe_code)]` 禁止 unsafe。普通、开发、构建、可选及目标平台依赖均为零，
无 `build.rs`。MSRV 为 Rust 1.74，核心不使用堆分配。

实现包含 Header、Question、Answer / Authority / Additional、标签与名称压缩，
以及 A、AAAA、CNAME、NS、PTR、MX、TXT、SOA、SRV、CAA 和基础 EDNS OPT。
未知类型保留原始 RDATA；数值字段按网络字节序转换。

`MessageView` 借用原始报文。Question、Record、名称标签、TXT 字符串及 OPT 选项均有
迭代器。`Questions::into_records` 复用已消费位置，避免再次扫描问题区。
`parse` 检查报文长度与 Header；`parse_strict` / `validate` 检查整个报文。

`MessageBuilder` 写入调用方缓冲区，维护计数并检查分区顺序。
写入失败时，缓冲区、计数、分区状态、压缩字典和最近名称缓存均保持原样。
`BufferTooSmall { needed }` 返回当前操作需要的精确总容量，`finish()` 返回已使用的前缀。

实现及 API 说明：[README](https://github.com/LIghtJUNction/zdwire/blob/main/README.md)、
[解析器](https://github.com/LIghtJUNction/zdwire/blob/main/src/message.rs)、
[编码器](https://github.com/LIghtJUNction/zdwire/blob/main/src/encode.rs)。

## 验证结果

| 检查 | 实际结果 |
|---|---|
| 核心集成测试 | 39 项通过：13 编码、15 解析、11 安全 |
| 文档示例 | 3 项通过 |
| domain 差分测试 | 10 项通过 |
| 发布脚本集成测试 | 6 项通过 |
| Linux / Windows / macOS | 三个平台的 Rust 1.74.0 与 stable 均通过 |
| `rustfmt` / Clippy / rustdoc | 通过，CI 将诊断警告视为错误 |
| WASM | `wasm32-unknown-unknown` 编译通过 |
| 裸机 ARM | `thumbv7em-none-eabi` 编译通过 |
| Miri | 11 个安全测试通过 strict provenance 检查 |
| AddressSanitizer | GitHub CI 中 200,000 次确定性变异测试通过 |
| 打包与发布预检查 | `cargo package --locked` 与 `cargo publish --locked --dry-run` 通过 |
| 依赖约束 | 自动检查确认发布 crate 无任何种类的依赖或构建脚本 |

测试覆盖 RFC 1035 §4.1.4 原始压缩示例、全部支持的 RR、编码解码往返、精确错误偏移、
容量边界、失败后状态保持、255 字节名称、65,535 字节报文及恶意压缩指针。
差分工程还覆盖 512 个随机二进制名称查询、512 个生成响应、混合报文的所有截断位置、
10,000 个变异报文及两种压缩策略下的完整编码字节相等。

本地 ASan 的地址检测也已通过；托管环境中的 ptrace 限制要求关闭本地 LeakSanitizer。
GitHub runner 使用默认 sanitizer 配置并已通过。这里的 fuzz 为确定性变异测试，
没有声称使用覆盖率引导或完成穷尽验证。

证据：[CI 作业](https://github.com/LIghtJUNction/zdwire/actions/runs/42753211574)、
[核心测试](https://github.com/LIghtJUNction/zdwire/tree/main/tests)、
[差分测试](https://github.com/LIghtJUNction/zdwire/blob/main/comparison/tests/differential.rs)、
[fuzz 驱动](https://github.com/LIghtJUNction/zdwire/blob/main/fuzz/src/main.rs)。

## 性能结果

比较对象为固定版本 `domain 0.12.3`，关闭默认功能。两边使用相同报文和调用方缓冲区，
先检查完整语义及编码字节一致，再计时。解析分别比较原始记录访问、具体 RR 类型分派
和通用 `AllRecordData` 分派；下表采用具体 RR 类型路径，避免用通用枚举开销夸大收益。

固定 CPU 的复测使用 Rust 1.99.1、Intel Xeon Platinum 8573C、11 组中位数，
每组目标 50 ms。倍数为 `domain 耗时 / zdwire 耗时`，大于 1 表示 zdwire 更快。

| 场景 | zdwire / 报文 | domain / 报文 | 倍数 |
|---|---:|---:|---:|
| 压缩编码，64 Answers | 855.737 ns | 2,624.590 ns | 3.067× |
| 压缩编码，512 个重复名称 | 6,202.386 ns | 20,197.119 ns | 3.256× |
| 压缩编码，64 条 TXT | 1,440.644 ns | 3,479.542 ns | 2.415× |
| 普通查询解析 | 47.421 ns | 112.409 ns | 2.370× |
| 小型 Answer 解析 | 60.008 ns | 126.185 ns | 2.103× |
| 64 Answers 的具体类型解析 | 2,645.904 ns | 2,353.009 ns | 0.889× |
| 512 个重复名称的具体类型解析 | 21,274.403 ns | 19,210.757 ns | 0.903× |
| 单查询压缩编码 | 70.953 ns | 48.052 ns | 0.677× |

多个代表性压缩编码场景达到了 2×，其中两个超过 3×。优势集中在重复域名的压缩编码与小报文解析。
domain 的具体类型解析在部分大批量场景中领先；单查询及小型 EDNS 编码也仍有优势。
共享主机的部分样本波动很大，尤其 CNAME、TXT 解析和极小非法报文；完整报告同时保留
固定 CPU 与未固定 CPU 两次结果和 IQR，避免依赖单个波动值作结论。

性能收益来自减少名称临时数组、直接复制已有连续名称字节、8 字节压缩表项、
成功写入后更新的最近未压缩名称缓存，以及重复 owner 的直接指针输出。
所有压缩哈希命中仍核对原始字节。

完整方法与复现命令：[benchmark.md](https://github.com/LIghtJUNction/zdwire/blob/main/docs/benchmark.md)。
原始数据：[pinned.csv](https://github.com/LIghtJUNction/zdwire/blob/main/comparison/results/pinned.csv)、
[local.csv](https://github.com/LIghtJUNction/zdwire/blob/main/comparison/results/local.csv)。

```sh
cargo test --locked --manifest-path comparison/Cargo.toml
ZD_BENCH_MS=50 ZD_BENCH_SAMPLES=11 \
  cargo run --release --locked --manifest-path comparison/Cargo.toml --bin compare
```

## 安全处理边界

域名最长展开为 255 字节，每个标签最长 63 字节，每个名称最多跟随 32 个压缩指针。
指针必须向后引用；自引用、重复位置、越界和截断均返回带位置的错误。
合法但超过 32 跳的名称会返回 `PointerLimit`。编码器只引用已有的未压缩标签边界，
因此生成的名称最多一跳。

SRV target 不压缩。OPT 必须位于 Additional、具有字面根名称且只能出现一次。
未知 RDATA 保持原样；包含旧格式压缩指针的未知类型，跨报文复制时需要调用方了解类型。
这些边界写入 [SECURITY.md](https://github.com/LIghtJUNction/zdwire/blob/main/SECURITY.md)。

## bump 与自动发布

[Release 工作流](https://github.com/LIghtJUNction/zdwire/actions/workflows/release.yml)
提供 `patch`、`minor`、`major` 和 `current`。
`current` 用于首次发布当前 0.1.0 或恢复中断发布。

工作流使用仓库 Secret `CARGO_REGISTRY_TOKEN`。版本变更会同步根目录、comparison 和 fuzz
的 lockfile；随后针对精确 SHA 运行完整 CI，通过后创建 Git Tag、执行 cargo publish，
并生成 GitHub Release。默认分支与 Release 标签归属、版本一致性、重复上传和同一次
工作流重跑均有检查。发布在同一次运行中完成，不依赖 Token 创建事件后继续触发。

本次交付已完成发布预检查，未执行正式 crates.io 上传。

## 结论与证据对应

| 验收问题 | 证据与边界 |
|---|---|
| 基础 wire 功能是否实现？ | 所有请求的记录类型、分区、名称与 OPT 均有实现和往返测试。 |
| 安全与内存约束是否落实？ | core-only、safe Rust、显式限制、Miri、恶意输入和 ASan 结果。 |
| 性能结果能否复现？ | 固定依赖、独立工程、完整命令、确定性样本、两份 CSV 与环境记录。 |
| 性能目标在哪些场景达成？ | 多个压缩编码和小报文解析超过 2×，批量具体类型解析仍有落后项。 |
| 发布链是否已准备可用？ | 工作流、信任检查、版本脚本和完整 CI 通过；正式上传尚未触发。 |
