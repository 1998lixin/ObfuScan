# ObfuScan

[English](#english) | [中文](#中文)

[![GitHub release (latest by date)](https://img.shields.io/github/v/release/1998lixin/ObfuScan)](https://github.com/1998lixin/ObfuScan/releases)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
![Platform](https://img.shields.io/badge/platform-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey)
![Language](https://img.shields.io/badge/language-C%2B%2B17%20%7C%20Python3-blue)

---

## 中文

ObfuScan 是面向 **Android APK 与 HarmonyOS HAP Native SO 预筛选** 的静态分析工具。它扫描 APK 的 `lib/arm64-v8a/`、HAP 的 `libs/arm64-v8a/` 以及 `assets/` 下的 SO，结合 ELF、指令、保护特征和 VMP 结构证据排序风险，帮助逆向与安全审计人员先定位高价值目标。它不是反编译器，也不把启发式结论包装成最终定性。

---

### 快速开始

#### 方法一：Web 界面（推荐）

Web 端当前使用 Python 标准库，建议使用 Python 3.9–3.12；Python 3.13 已移除其使用的 `cgi` 模块。

```bash
cd ObfuScan
python web_server.py
```

访问 http://127.0.0.1:8080，确认扫描引擎已就绪，再拖入 APK 分析。页面会分开显示通用风险与 VMP 状态；`PARTIAL`、`REJECTED`、`ERROR` 会展示诊断，不会伪装成“0 个结果”。健康检查可使用 `curl http://127.0.0.1:8080/status`。

`ERR_CONNECTION_REFUSED` 表示本地 Python 进程未运行。`127.0.0.1` 不是公网地址，进程退出或电脑关机后页面就会停止。

#### Web 服务配置与上线边界

常用默认值是 `127.0.0.1:8080`、请求体上限 `512 MiB`（APK 需为 multipart 边界留出少量空间）、扫描超时 `900s`、32 个连接、2 个扫描槽、临时盘保留 `512 MiB`、stdout/stderr `32/1 MiB`。可通过同名 `OBFUSCAN_*` 环境变量覆盖；`OBFUSCAN_EXECUTABLE` 指定引擎，公网环境应设置 `OBFUSCAN_EXPOSE_ENGINE_PATH=0` 且把扫描并发降为 `1`。完整配置见 `web_server.py` 顶部。

内置服务器已经具备有界多线程、连接空闲超时、并发扫描上限、Windows 独占端口、上传/临时盘/输出限制和基础安全响应头；但它**不提供 TLS、用户系统、验证码、账号配额或 DDoS 防护，不能直接绑定 `0.0.0.0` 裸露公网**。

#### 方法二：命令行

```bash
ObfuScan.exe <apk_or_hap_path>
ObfuScan.exe <apk_or_hap_path> --en
ObfuScan.exe app.apk > result.json
```

命令行输出 JSON。自动化调用必须读取顶层 `scan_status`；有效命令即使安全拒绝恶意 APK，也会输出合法 JSON，不能只看进程退出码。

---

### 从源码编译

需要 CMake ≥ 3.15、支持 C++17 的编译器，以及用于获取 Capstone 依赖的 Git。

```bash
git clone --recurse-submodules https://github.com/1998lixin/ObfuScan.git
cd ObfuScan
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build --config Release
```

单配置生成器通常输出 `build/ObfuScan[.exe]`，多配置生成器输出 `build/Release/ObfuScan[.exe]`。

运行完整 CTest 回归：

```bash
ctest --test-dir build -C Release --output-on-failure
```

测试覆盖 VMP 数据流、ELF `PT_DYNAMIC` 恢复、跨 SO 关联、APK 资源策略，以及在找到 Python 时启用的恶意 ZIP/APK 端到端限制回归。

如果本地存在仓库测试用 APK，可运行 SHA-256 固定的端到端 verdict 回归（按实际生成器调整可执行文件路径）：

```bash
python tests/corpus_regression.py --scanner build/ObfuScan.exe --fixtures . --require-all
```

Unix 单配置构建将扫描器路径换为 `./build/ObfuScan`。这些 APK 是本地 SHA-256 固定语料，不随仓库提交。MinGW 构建会自动加入静态链接选项，但不同工具链仍需单独验证运行库依赖；CLion 可直接打开目录并选择 Release 构建。

---

### 工作原理（评分模型）

ObfuScan 不依赖单一特征签名，而是采用多因子启发式评分：

| 检测因子 | 用途 |
|---------|------|
| 段熵、可写入口、大块高熵数据 | 加密、压缩或自修改代码迹象 |
| 分支、间接转移、算逻指令密度 | 控制流复杂度与代码膨胀信号 |
| `.init_array`、导入/导出和动态依赖 | 异常初始化、loader 与跨 SO 关系 |
| 自定义 ELF Loader 能力轴与 Linker 加固闭环 | 区分组件能力与保护结论 |
| VMP 结构和 ZIP 伪装 SO | 独立的结构判定与二次容器分析 |

`CUSTOM_LOADER_COMPONENT` 仅表示发现较完整的 ELF 装载能力，尚未证实用于加固；只有装载闭环同时具备受保护 payload、解密装载等独立证据时，才判为 `LIKELY_CUSTOM_LINKER_PROTECTION`。Hook/Trampoline 框架使用 `mmap`、`mprotect`、`dlsym` 或读取 ELF 元数据属于 ELF introspection，不等于自定义 Linker 加固。

最终风险等级由 packer、OLLVM/强混淆、已证实的 Linker 加固、VMP 状态等多条门控共同决定，不再把一个总分直接当概率或用单一阈值覆盖所有类型。

完整判定逻辑可参阅 `custom_linker_detector.cpp` 的 Loader/加固多轴门控、`main.cpp` 中的 `analyze_so()` 集成，以及 `vmp_detector.cpp` 的 VMP 多轴判定。

---

### VMP 多轴识别

VMP 判断不再依赖“间接跳转很多”这一类单点阈值。扫描器会覆盖 ELF 的所有可观察可执行 `PT_LOAD` 区域，对间接转移点去重，并在候选点附近验证：

- VPC / VIP 的取指与推进关系
- opcode 到 handler 目标的寄存器数据依赖
- dispatcher 回边、共享 VM 上下文和候选聚类
- direct-threaded、call-threaded、return-threaded、条件分发和线程化跳板等形态
- 普通 switch 跳表、vtable / 函数指针调用、ABI 跳板和已知运行时等替代解释

每个 SO 会按适用条件输出以下维度；Web 页面与中英文 JSON 使用同一语义：

| 输出 | 含义 |
|------|------|
| `vmp_outcome`、`vmp_confidence`、`vmp_profile`、`vmp_score` | 最终分类、置信等级、主导分发形态和证据总强度 |
| `vm_structure_score`、`protection_intent_score`、`alternative_penalty` | VM 结构、保护意图与普通替代解释三条决策轴 |
| `vmp_scan_coverage`、`vmp_observable`、`vmp_limitation` | 静态机器码的覆盖率、可观测性与结论限制 |
| `vmp_metrics`、`vmp_candidates` | 间接转移、候选聚类以及候选点局部寄存器数据流 |
| `runtime_alternative` | 合法解释器/运行时家族、独立证据类别和确认状态 |
| `vmp_provider_evidence` | provider、精确 `DT_NEEDED` 依赖及导入/导出符号交集 |

跨 SO 关联采用严格三边门控，只有同时满足以下条件才会把客户端标记为 `VMP_PROTECTED_CLIENT`：

1. provider 自身已经是 `LIKELY_VMP` 且整体为高风险；
2. 客户端存在与 provider basename 精确匹配的 `DT_NEEDED`；
3. 客户端导入符号与 provider 导出符号至少存在一个真实交集。

这是一条“客户端由高置信 VMP runtime 驱动”的依赖结论，不宣称客户端本地存在 dispatcher；客户端的本地 VMP 结构分数和候选点不会被依赖关系虚增。

合法运行时替代解释由 SO 家族名、身份字符串、特征导入 API 三类独立证据确认：1 类仅作弱提示，至少 2 类才参与强替代解释。原始命中次数不等于证据类别；已确认的合法运行时也不会抹掉保护元数据或闭合 dispatcher 等独立证据。

> **重要：这些分数是静态证据强度，不是概率。** `0.90` 不代表“有 90% 的概率是 VMP”。最终应优先读取状态码，再结合结构分、保护意图、替代解释、覆盖率与限制进行判断。

主要状态码：

| 状态码 | 应如何理解 |
|--------|------------|
| `LIKELY_VMP` | 结构性数据流与保护语境达到当前判定门槛，建议优先人工确认 |
| `VMP_PROTECTED_CLIENT` | 自身未宣称存在 dispatcher；但由高置信 provider、精确 `DT_NEEDED` 和共享符号三重证据确认其由 VMP runtime 驱动 |
| `VM_LIKE_INTERPRETER` | 确有 VM/解释器结构，但更像 QuickJS、Lua、Hermes、FFmpeg 等合法运行时或媒体处理组件，不应直接当作 VMP |
| `SUSPICIOUS_VM_STRUCTURE` | 存在可疑 VM 结构，但保护意图或候选一致性不足 |
| `INCONCLUSIVE_PACKED` | 打包、加密或运行时解密使静态机器码不可充分观察；这是“无法判定”，不是“没有 VMP” |
| `PARTIAL_ANALYSIS` | 扫描覆盖不完整，结论受限 |
| `NO_VMP_EVIDENCE` | 在已报告覆盖范围内未找到足够结构性证据；不代表动态解密后的代码也没有 VMP |
| `NO_EXECUTABLE_CODE` | 文件中没有可观察的可执行代码 |
| `ANALYSIS_ERROR` | 分析失败，应先处理错误再解释结果 |

---

### 扫描安全边界与状态

扫描器会先审计 APK/ZIP 元数据，再决定是否解压攻击者可控的内容。无论中文还是英文输出，顶层都会提供：

| 字段 | 含义 |
|------|------|
| `scan_status` | `OK`、`PARTIAL`、`REJECTED` 或 `ERROR` |
| `scan_limits` | 对外报告的主要资源硬限制 |
| `scan_observed` | APK 字节数、ZIP 条目、候选/已分析/跳过 SO 数、累计解压量和元数据峰值 |
| `scan_diagnostics` | 稳定诊断码、本地化消息、条目名、压缩/解压大小及受限原因 |

状态语义：

- `OK`：所有相关候选均在预算内完成处理；
- `PARTIAL`：结果可用，但有条目因加密、不支持的压缩、异常压缩比、大小/累计预算或解压失败被跳过；
- `REJECTED`：APK 整体越过硬限制，扫描器在大规模解压前安全拒绝；
- `ERROR`：输入打不开、格式错误、内存分配失败或内部异常。

扫描器的主要默认硬限制如下；Web 的 `512 MiB` 请求体上限是更外层的一道限制：

| 资源 | 默认硬限制 |
|------|------------|
| APK 文件 | `1 GiB` |
| ZIP 元数据分配 | `64 MiB` |
| ZIP 总条目 | `20,000` |
| `lib/arm64-v8a/` + `assets/` SO 候选 | `256` |
| 单个 SO 解压后大小 | `128 MiB` |
| 相关 SO 累计解压量 | `512 MiB` |
| 异常压缩比 | 解压后至少 `1 MiB` 时最高 `200:1` |
| 内层 ZIP | 元数据 `16 MiB`、条目 `1,024`、单条目 `128 MiB`、累计 `256 MiB` |
| 返回的安全诊断 | 最多 `64` 条，额外数量单独计数 |

自动化系统必须先检查 `scan_status`，再解释 `汇总` / `summary` 与 SO 结果；不要把 `PARTIAL` 当完整阴性，也不要把 `REJECTED` 的空结果当作“未发现风险”。

---

### 当前支持的能力

| 能力 | 当前实现 |
|------|----------|
| APK/HAP 枚举 | APK 的 `lib/arm64-v8a/*.so`、HAP 的 `libs/arm64-v8a/*.so` 与 `assets/*.so` |
| ELF 恢复 | 文件头、段/节、熵、符号、依赖、`DT_INIT[_ARRAY]`、relocation；节表缺失时从 `PT_DYNAMIC` 恢复 |
| PLT 排除 | 依据 `R_AARCH64_JUMP_SLOT` 排除真实 PLT 间接跳转，不猜地址范围 |
| 指令统计 | Capstone AArch64 分支、间接转移、算术/逻辑/比较密度 |
| VMP | 多轴结构识别、合法运行时替代、跨 SO provider/client 关联、覆盖率与候选证据 |
| ZIP 伪装 SO | 识别 `PK\x03\x04`，在独立预算内提取并继续分析内层 ELF |
| 入口预览 | ELF entry、`.init_array`、`JNI_OnLoad`、`Java_*` 与 init/load/register 导出 |
| 安全边界 | 解压前检查条目、加密/压缩、大小和压缩比；异常输入返回稳定 JSON 诊断 |

---

### 输出结果怎么看

| 风险 | 用法 |
|------|------|
| 高 | 优先人工复核，常见于壳/loader、强混淆、异常初始化或保护层 |
| 中 | 有可疑度但证据不足，结合业务背景决定是否深入 |
| 低 | 更像基础库、普通发布构建或轻度混淆，不代表绝对安全 |

---

### 关于准确率的说明

新版 VMP 检测已从重叠窗口计数升级为候选去重、局部寄存器数据流和多轴决策，但 ObfuScan 的目标仍是**把值得逆向的 SO 排到前面**，不是给出数学证明或脱离语料集的“准确率百分比”。

- `LIKELY_VMP` 表示证据越过当前高精度门槛，仍应在 IDA / Ghidra 或运行时轨迹中确认 dispatcher、bytecode 与 handler 的闭环。
- `VMP_PROTECTED_CLIENT` 表示跨 SO 依赖闭环成立，不代表客户端自身找到了 dispatcher；应同时查看 `vmp_provider_evidence`。
- `VM_LIKE_INTERPRETER` 明确保留 VM 结构事实，同时避免把合法解释器、媒体运行时或数据库虚拟机直接误报为保护型 VMP。
- `INCONCLUSIVE_PACKED`、`PARTIAL_ANALYSIS` 和 `NO_EXECUTABLE_CODE` 都属于“静态证据不足”，不能降格解释成阴性结论。
- `NO_VMP_EVIDENCE` 只约束报告中的已扫描、可观察范围；运行时解密、自修改代码和未覆盖架构仍可能改变结论。

评估识别能力时，应使用含已确认 VMP、普通 C/C++、switch/vtable、合法解释器和 packed 样本的标注集，分别报告 precision、recall、混淆矩阵与不可判定比例。实际分析可先看高风险结果和入口预览，再用 IDA、Ghidra、Frida 或运行时轨迹确认。

---

### 当前已知局限

- 主要面向 Android 64 位 AArch64 SO（暂不支持 32 位 ARM）
- 不是反编译器；OLLVM / 强混淆判断仍是启发式
- VMP 数据流验证限定在静态可观察的局部候选窗口，不等价于完整 CFG、跨函数污点分析或 bytecode 语义恢复
- 对运行时解密、自修改代码、非常规壳、自研 VM 和深度伪装样本仍可能漏报或只能给出不可判定
- 合法解释器/运行时识别依赖结构和上下文证据，未知或改名的第三方运行时仍可能进入可疑队列
- 跨 SO provider/client 识别依赖静态 `DT_NEEDED` 与动态符号；运行时 `dlopen`/`dlsym`、加密符号或自定义绑定可能无法建立关系
- 内置 Web 服务用于本地分析与受控反向代理后端，不应替代生产级鉴权、WAF、账号配额、任务队列或解析器沙箱

---

### 贡献指南

欢迎通过 Issue / Pull Request 报告问题、改进代码或文档；提交前请通过编译与测试。

---

### 许可证

本项目采用 [MIT 许可证](LICENSE)。

---

### 致谢

感谢以下项目 / 工具：

- **GPT** - 辅助开发与文案优化
- **Capstone** - 轻量级多架构反汇编引擎
- **miniz** - 单文件 ZIP 解压库
- **LibChecker-Rules** - 原生库识别规则

---

## English

### ObfuScan

ObfuScan is a static **Android APK and HarmonyOS HAP Native SO pre-screening** tool. It scans SO files under `lib/arm64-v8a/` (APK), `libs/arm64-v8a/` (HAP), and `assets/`, then combines ELF, instruction, protection, and VMP-structure evidence to prioritize high-value targets for reverse engineering and security audits. It is not a decompiler and does not present heuristic findings as final attribution.

---

### Quick Start

#### Method 1: Web Interface (Recommended)

The Web layer currently uses Python's standard library. Use Python 3.9–3.12; Python 3.13 removed the `cgi` module used by this server.

```bash
cd ObfuScan
python web_server.py
```

Open http://127.0.0.1:8080, confirm that the analysis engine is ready, and drop in an APK. Generic risk and VMP outcomes are shown separately; `PARTIAL`, `REJECTED`, and `ERROR` display diagnostics instead of looking like an empty successful scan. Health check: `curl http://127.0.0.1:8080/status`.

`ERR_CONNECTION_REFUSED` means that the local Python process is not running. `127.0.0.1` is not public; exiting the process or shutting down the machine stops the page.

#### Web Configuration and Deployment Boundary

Common defaults are `127.0.0.1:8080`, a `512 MiB` request-body limit (the APK must leave a little room for multipart framing), a `900s` scan timeout, 32 connections, 2 scan slots, `512 MiB` disk reserve, and `32/1 MiB` stdout/stderr limits. Override them with the corresponding `OBFUSCAN_*` variables; `OBFUSCAN_EXECUTABLE` selects the engine. Public deployments should set `OBFUSCAN_EXPOSE_ENGINE_PATH=0` and reduce scan concurrency to `1`. See the top of `web_server.py` for the complete list.

The built-in server has bounded threading, idle timeouts, scan concurrency limits, exclusive Windows port binding, upload/disk/output limits, and baseline security headers. It still **does not provide TLS, user accounts, CAPTCHA, quotas, or DDoS protection; do not bind it directly to `0.0.0.0` on the public Internet**.

#### Method 2: Command Line

```bash
ObfuScan.exe <apk_or_hap_path>
ObfuScan.exe <apk_or_hap_path> --en
ObfuScan.exe app.apk > result.json
```

The CLI emits JSON. Automation must inspect the top-level `scan_status`: a valid invocation still returns well-formed JSON when an unsafe APK is rejected, so the process exit code alone is insufficient.

---

### Build from Source

Requires CMake ≥ 3.15, a C++17 compiler, and Git for fetching Capstone.

```bash
git clone --recurse-submodules https://github.com/1998lixin/ObfuScan.git
cd ObfuScan
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build --config Release
```

Single-config generators normally output `build/ObfuScan[.exe]`; multi-config generators use `build/Release/ObfuScan[.exe]`.

Run the complete CTest suite:

```bash
ctest --test-dir build -C Release --output-on-failure
```

The suite covers VMP data flow, ELF `PT_DYNAMIC` recovery, cross-SO linkage, APK resource policy, and—when Python is available—end-to-end malicious ZIP/APK limit regression.

If the local hash-pinned APK fixtures are available, run the end-to-end verdict regression (adjust the executable path for your generator):

```bash
python tests/corpus_regression.py --scanner build/ObfuScan.exe --fixtures . --require-all
```

For a single-config Unix build, use `--scanner ./build/ObfuScan`. These APKs are local, SHA-256-pinned fixtures and are not committed. MinGW builds add static-link flags automatically, but runtime dependencies still need toolchain-specific verification; CLion users can open the directory and select a Release build.

---

### How It Works (Scoring Model)

ObfuScan uses multi-factor heuristic scoring rather than relying on a single signature:

| Factor | Use |
|--------|-----|
| Segment entropy, writable entry, large high-entropy data | Encryption, compression, or self-modifying-code signals |
| Branch, indirect-transfer, and arithmetic/logic density | Control-flow complexity and code-bloat signals |
| `.init_array`, imports/exports, and dynamic dependencies | Abnormal initialization, loader, and cross-SO relationships |
| Custom ELF-loader capability axes and linker-protection closure | Separate component capability from protection conclusions |
| VMP structure and ZIP-disguised SO | Independent structural classification and nested-container analysis |

`CUSTOM_LOADER_COMPONENT` means that a reasonably complete ELF-loading capability was found, but does not establish protection. `LIKELY_CUSTOM_LINKER_PROTECTION` additionally requires independent evidence such as a protected payload or decrypt-and-load behavior. ELF introspection by Hook/Trampoline frameworks—including `mmap`, `mprotect`, `dlsym`, and ELF metadata access—is not custom-linker protection by itself.

The final risk level is selected through separate packer, OLLVM/strong-obfuscation, established linker-protection, and VMP gates. A single aggregate number is neither treated as a probability nor used as one universal threshold for every protection family.

See the loader/protection gates in `custom_linker_detector.cpp`, their `analyze_so()` integration in `main.cpp`, and the multi-axis VMP verdict logic in `vmp_detector.cpp`.

---

### Multi-Axis VMP Detection

VMP classification no longer depends on a single threshold such as “many indirect branches.” ObfuScan scans every observable executable `PT_LOAD` region, deduplicates indirect-transfer sites, and validates the following evidence around each candidate:

- VPC/VIP opcode fetch and advance relationships
- Register data dependencies from opcode to handler target
- Dispatcher back edges, shared VM context, and candidate clustering
- Direct-, call-, and return-threaded dispatch, conditional dispatch, and threaded trampolines
- Alternative explanations such as ordinary switch tables, vtable/function-pointer calls, ABI thunks, and known runtimes

Each SO reports the applicable dimensions below; the Web UI and JSON use the same semantics:

| Field | Meaning |
|-------|---------|
| `vmp_outcome`, `vmp_confidence`, `vmp_profile`, `vmp_score` | Final classification, confidence, dominant dispatch profile, and total evidence strength |
| `vm_structure_score`, `protection_intent_score`, `alternative_penalty` | VM structure, protection intent, and ordinary-alternative decision axes |
| `vmp_scan_coverage`, `vmp_observable`, `vmp_limitation` | Static-code coverage, observability, and conclusion limits |
| `vmp_metrics`, `vmp_candidates` | Transfer/candidate clustering and local register-data-flow evidence |
| `runtime_alternative` | Legitimate runtime family, independent evidence classes, and confirmation state |
| `vmp_provider_evidence` | Provider, exact `DT_NEEDED` edge, and import/export symbol intersection |

Cross-SO propagation uses a strict three-edge gate. `VMP_PROTECTED_CLIENT` is emitted only when all of the following hold:

1. the provider is already `LIKELY_VMP` and high risk;
2. the client has an exact `DT_NEEDED` match for the provider basename; and
3. at least one client import is actually exported by that provider.

This means “the client is driven by a high-confidence VMP runtime,” not “a local dispatcher was found in the client.” Dependency linkage intentionally does not inflate the client's local VMP structure score or candidate list.

Legitimate-runtime alternatives use three independent evidence classes: SO family name, identity strings, and runtime-specific imports. One class is only a weak hint; at least two are required for a confirmed alternative. Raw hit counts do not create extra evidence classes, and a confirmed runtime does not erase independent protection metadata or closed-dispatcher evidence.

> **Scores are evidence strength, not probabilities.** A score of `0.90` does not mean a 90% probability of VMP. Read the outcome first, then interpret the score with structure, protection intent, alternative explanations, coverage, and limitations.

Key outcomes:

| Outcome | Interpretation |
|---------|----------------|
| `LIKELY_VMP` | Structural data flow and protection context pass the current decision threshold; prioritize manual confirmation |
| `VMP_PROTECTED_CLIENT` | No local dispatcher is claimed; a high-confidence provider, exact `DT_NEEDED` edge, and shared symbols jointly identify a VMP-runtime-driven client |
| `VM_LIKE_INTERPRETER` | A VM/interpreter structure exists, but a legitimate runtime such as QuickJS, Lua, Hermes, FFmpeg, or a similar component explains it better |
| `SUSPICIOUS_VM_STRUCTURE` | VM-like structure exists, but protection intent or candidate consistency is insufficient |
| `INCONCLUSIVE_PACKED` | Packing, encryption, or runtime unpacking prevents adequate static observation; this is inconclusive, not negative |
| `PARTIAL_ANALYSIS` | Scan coverage is incomplete |
| `NO_VMP_EVIDENCE` | No sufficient structural evidence was found inside the reported coverage; dynamically revealed code remains out of scope |
| `NO_EXECUTABLE_CODE` | No observable executable code is present |
| `ANALYSIS_ERROR` | Analysis failed; fix the error before interpreting the sample |

---

### Scan Safety Boundaries and Status

The scanner audits APK/ZIP metadata before extracting attacker-controlled content. Both language modes expose these top-level fields:

| Field | Meaning |
|-------|---------|
| `scan_status` | `OK`, `PARTIAL`, `REJECTED`, or `ERROR` |
| `scan_limits` | Main resource limits exposed by the scanner |
| `scan_observed` | APK size, ZIP entries, candidate/analyzed/skipped SO counts, decompression totals, and metadata peak |
| `scan_diagnostics` | Stable code, localized message, entry name, compressed/uncompressed size, and rejection detail |

Status semantics:

- `OK`: every relevant candidate completed within budget;
- `PARTIAL`: useful results exist, but one or more entries were skipped because of encryption, unsupported compression, extreme ratio, size/cumulative budgets, or extraction failure;
- `REJECTED`: the APK crosses a whole-input hard limit and is rejected before large-scale extraction;
- `ERROR`: the input cannot be opened, is malformed, allocation fails, or an internal exception occurs.

The main scanner defaults are listed below. The Web layer's `512 MiB` request-body limit is an additional outer boundary:

| Resource | Default hard limit |
|----------|--------------------|
| APK file | `1 GiB` |
| ZIP metadata allocation | `64 MiB` |
| ZIP entries | `20,000` |
| SO candidates under `lib/arm64-v8a/` + `assets/` | `256` |
| Single uncompressed SO | `128 MiB` |
| Total relevant uncompressed SO bytes | `512 MiB` |
| Extreme compression ratio | at most `200:1` when output is at least `1 MiB` |
| Nested ZIP | metadata `16 MiB`, entries `1,024`, single entry `128 MiB`, total `256 MiB` |
| Returned safety diagnostics | first `64`, with additional count reported separately |

Automation must check `scan_status` before interpreting `summary` and `results`. Do not treat `PARTIAL` as a complete negative result, or an empty `REJECTED` result as “no risk found.”

---

### Currently Supported Capabilities

| Capability | Current implementation |
|------------|------------------------|
| APK/HAP enumeration | `lib/arm64-v8a/*.so` (APK), `libs/arm64-v8a/*.so` (HAP), and `assets/*.so` |
| ELF recovery | Headers, segments/sections, entropy, symbols, dependencies, `DT_INIT[_ARRAY]`, and relocations; `PT_DYNAMIC` fallback when section tables are missing |
| PLT exclusion | Uses `R_AARCH64_JUMP_SLOT` rather than guessed address ranges |
| Instruction statistics | Capstone AArch64 branch, indirect-transfer, and arithmetic/logical/comparison density |
| VMP | Multi-axis structure, legitimate-runtime alternatives, cross-SO provider/client linkage, coverage, and candidate evidence |
| ZIP-disguised SO | Detects `PK\x03\x04`, then extracts and analyzes inner ELF inside separate budgets |
| Entry previews | ELF entry, `.init_array`, `JNI_OnLoad`, `Java_*`, and init/load/register exports |
| Safety boundaries | Pre-extraction entry/encryption/compression/size/ratio checks with stable JSON diagnostics |

---

### How to Interpret Output Results

| Risk | Use |
|------|-----|
| High | Prioritize manual review; often packing/loaders, strong obfuscation, abnormal initialization, or protection layers |
| Medium | Suspicious but incomplete evidence; decide with application context |
| Low | More consistent with libraries, ordinary release builds, or light obfuscation; not a guarantee of safety |

---

### About Accuracy

The VMP detector now uses deduplicated candidates, local register data flow, and multi-axis decisions instead of overlapping-window counts. ObfuScan still aims to **prioritize SOs worth reversing**, not provide a mathematical proof or a corpus-independent “accuracy percentage.”

- `LIKELY_VMP` crosses the current high-precision evidence threshold, but the dispatcher/bytecode/handler loop should still be confirmed in a disassembler or runtime trace.
- `VMP_PROTECTED_CLIENT` is a cross-SO dependency conclusion, not proof of a local client dispatcher; inspect `vmp_provider_evidence` with it.
- `VM_LIKE_INTERPRETER` preserves the fact that VM structure exists while avoiding a direct VMP claim for legitimate interpreters, media runtimes, or database VMs.
- `INCONCLUSIVE_PACKED`, `PARTIAL_ANALYSIS`, and `NO_EXECUTABLE_CODE` mean insufficient static evidence; they are not negative findings.
- `NO_VMP_EVIDENCE` applies only to the reported scanned and observable range. Runtime-decrypted, self-modifying, or unsupported-architecture code may change the conclusion.

Evaluate changes on a labeled corpus containing confirmed VMP, ordinary C/C++, switch/vtable dispatch, legitimate interpreters, and packed samples; report precision, recall, a confusion matrix, and the inconclusive rate separately. In practice, review high-risk results and entry previews first, then confirm them in IDA, Ghidra, Frida, or runtime traces.

---

### Current Known Limitations

- Focuses on Android 64-bit AArch64 SO (32-bit not supported)
- Not a decompiler; OLLVM / strong-obfuscation detection remains heuristic
- VMP data-flow validation is local to statically observable candidate windows; it is not full CFG recovery, interprocedural taint analysis, or bytecode-semantic reconstruction
- Runtime-decrypted code, self-modifying code, unconventional packers, custom VMs, and deep disguises may be missed or remain inconclusive
- Legitimate-runtime classification uses structural and contextual evidence; unknown or renamed runtimes may still enter the suspicious queue
- Cross-SO provider/client detection depends on static `DT_NEEDED` and dynamic symbols; runtime `dlopen`/`dlsym`, encrypted symbols, or custom binding may remain invisible
- The built-in Web server is intended for local analysis or as a controlled reverse-proxy backend, not as a replacement for production authentication, WAF, account quotas, job queues, or parser sandboxing

---

### Contributing

Issues and pull requests for code or documentation are welcome; please build and test changes before submission.

---

### License

This project is licensed under the [MIT License](LICENSE).

---

### Acknowledgments

- **GPT** - Development assistance and documentation
- **Capstone** - Lightweight multi-architecture disassembly engine
- **miniz** - Single-file ZIP decompression library
- **LibChecker-Rules** - Native library identification rules
