# ObfuScan

[English](#english) | [中文](#中文)

[![GitHub release (latest by date)](https://img.shields.io/github/v/release/1998lixin/ObfuScan)](https://github.com/1998lixin/ObfuScan/releases)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
![Platform](https://img.shields.io/badge/platform-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey)
![Language](https://img.shields.io/badge/language-C%2B%2B17%20%7C%20Python3-blue)

---

## 中文

ObfuScan 是 Android APK / HarmonyOS HAP 的 Native SO 静态预筛选工具。它枚举包内 arm64 SO，结合 ELF 结构、指令统计、保护痕迹和 VMP 数据流证据做风险排序，帮你在逆向之前先锁定值得人工分析的库。

它是预筛选器，不是反编译器：输出用来排优先级，不当最终定性。

### 快速开始

**Web 界面（推荐）** —— 只用 Python 标准库，建议 3.9–3.12（3.13 移除了它依赖的 `cgi` 模块）：

```bash
python web_server.py
```

打开 http://127.0.0.1:8080 ，拖入 APK / HAP 即可。通用风险与 VMP 状态分开展示；`PARTIAL`、`REJECTED`、`ERROR` 会给出具体诊断，不会伪装成"0 个结果"。健康检查：`curl http://127.0.0.1:8080/status`。页面打不开（`ERR_CONNECTION_REFUSED`）就是本地 Python 进程没在跑。

**命令行** —— 输出 JSON：

```bash
ObfuScan.exe <apk_or_hap> [--en]
ObfuScan.exe app.apk > result.json
```

自动化调用必须读顶层 `scan_status`：安全拒绝恶意包时同样返回合法 JSON，只看进程退出码不可靠。

Web 服务默认 `127.0.0.1:8080`，请求体上限 512 MiB、扫描超时 900s、2 个并发扫描槽，均可用同名 `OBFUSCAN_*` 环境变量覆盖，完整列表见 `web_server.py` 顶部；`OBFUSCAN_EXECUTABLE` 指定引擎路径。服务器具备有界多线程、连接空闲超时、并发上限、上传/临时盘/输出限制和基础安全响应头，但**没有 TLS、鉴权和配额，不要直接绑定 `0.0.0.0` 暴露公网**；确需对外时应放在受控反向代理之后，并设置 `OBFUSCAN_EXPOSE_ENGINE_PATH=0`、扫描并发降为 `1`。

### 从源码编译

需要 CMake ≥ 3.15、支持 C++17 的编译器和 Git（用于拉取 Capstone）：

```bash
git clone --recurse-submodules https://github.com/1998lixin/ObfuScan.git
cd ObfuScan
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build --config Release
```

单配置生成器输出 `build/ObfuScan[.exe]`，多配置在 `build/Release/` 下。MinGW 构建自动静态链接运行库。

```bash
# 完整回归：VMP 数据流、ELF PT_DYNAMIC 恢复、跨 SO 关联、ZIP/APK 资源限制
ctest --test-dir build -C Release --output-on-failure

# 本地存在 SHA-256 固定测试语料时（不随仓库提交）的端到端 verdict 回归
python tests/corpus_regression.py --scanner build/ObfuScan.exe --fixtures . --require-all
```

### 检测维度

不看单一签名，按多因子启发式评分：

| 维度 | 依据 |
|------|------|
| 熵与结构 | 段熵、可写入口、大块高熵数据 → 加密、压缩、自修改迹象 |
| 指令统计 | Capstone AArch64 分支 / 间接转移 / 算逻比较密度 → 控制流复杂度 |
| 初始化与依赖 | `.init_array`、导入导出、`DT_NEEDED` → 异常初始化与跨 SO 关系 |
| Loader / Linker | 自定义 ELF Loader 能力轴 + Linker 加固闭环（见下） |
| VMP 结构 | 多轴数据流判定（见下节） |
| 容器伪装 | SO 实为 ZIP（`PK\x03\x04`）时，在独立预算内提取内层 ELF 继续分析 |

实现要点：

- ELF 恢复覆盖文件头、段/节、熵、符号、依赖、`DT_INIT[_ARRAY]`、relocation；节表被剥时从 `PT_DYNAMIC` 恢复。
- PLT 排除依据 `R_AARCH64_JUMP_SLOT` relocation，不猜地址范围。
- 入口预览：ELF entry、`.init_array`、`JNI_OnLoad`、`Java_*` 及 init/load/register 导出。

**Loader 与加固是两道门。** `CUSTOM_LOADER_COMPONENT` 只表示发现了较完整的 ELF 装载能力，不声称加固；装载闭环之外还须具备受保护 payload、解密装载等独立证据，才判 `LIKELY_CUSTOM_LINKER_PROTECTION`。Hook/Trampoline 框架的 `mmap`、`mprotect`、`dlsym` 和读取 ELF 元数据属于正常 ELF introspection，不算自定义 Linker 加固。

最终风险（高/中/低）由 packer、OLLVM/强混淆、Linker 加固、VMP 多条门控独立决定，不存在一个总分阈值一刀切：高风险优先人工复核；中风险证据不足，结合业务背景判断；低风险更像普通发布构建或轻度混淆，不代表绝对安全。

### VMP 多轴判定

覆盖所有可观察的可执行 `PT_LOAD`，对间接转移点去重后，在候选点附近做局部寄存器数据流验证：

- VPC/VIP 取指与推进关系、opcode → handler 目标的寄存器数据依赖；
- dispatcher 回边、共享 VM 上下文、候选聚类；
- direct- / call- / return-threaded 分发、条件分发、线程化跳板；
- 替代解释：普通 switch 跳表、vtable / 函数指针调用、ABI 跳板、已知运行时。

每个 SO 输出最终分类（`vmp_outcome`）、置信度（`vmp_confidence`）、主导分发形态（`vmp_profile`）、三轴分数（`vm_structure_score` / `protection_intent_score` / `alternative_penalty`）、扫描覆盖率（`vmp_scan_coverage`）、可观测性与限制（`vmp_observable` / `vmp_limitation`）、候选明细（`vmp_candidates`）与跨 SO 证据（`vmp_provider_evidence`）。

**分数是证据强度，不是概率。** `0.90` 不表示"90% 是 VMP"。先读状态码，再结合三轴分数、覆盖率与限制判断。

| `vmp_outcome` | 含义 |
|---------------|------|
| `LIKELY_VMP` | 结构数据流与保护语境越过判定门槛，优先人工确认 |
| `VMP_PROTECTED_CLIENT` | 自身无 dispatcher；由三边证据确认的 VMP runtime 驱动客户端 |
| `VM_LIKE_INTERPRETER` | 确有 VM 结构，但更像 QuickJS、Lua、Hermes、FFmpeg 等合法运行时 |
| `SUSPICIOUS_VM_STRUCTURE` | 有可疑 VM 结构，保护意图或候选一致性不足 |
| `INCONCLUSIVE_PACKED` | 打包/加密使静态代码不可充分观察——不可判定 ≠ 没有 VMP |
| `PARTIAL_ANALYSIS` | 扫描覆盖不完整，结论受限 |
| `NO_VMP_EVIDENCE` | 已报覆盖范围内证据不足；运行时解密后的代码不在此列 |
| `NO_EXECUTABLE_CODE` | 没有可观察的可执行代码 |
| `ANALYSIS_ERROR` | 分析失败，先处理错误再解释结果 |

**跨 SO 关联**采用严格三边门控，同时满足才把客户端标为 `VMP_PROTECTED_CLIENT`：

1. provider 自身已是 `LIKELY_VMP` 且整体高风险；
2. 客户端存在与 provider basename 精确匹配的 `DT_NEEDED`；
3. 客户端导入符号与 provider 导出符号至少有一个真实交集。

这是"客户端由高置信 VMP runtime 驱动"的依赖结论，不声称客户端本地存在 dispatcher，也不会虚增客户端本地的结构分与候选数。

**合法运行时替代**由三类独立证据确认：SO 家族名、身份字符串、特征导入 API。一类只算弱提示，至少两类才构成确认；已确认的运行时也不会抹掉保护元数据或闭合 dispatcher 等独立证据。

### 扫描安全边界

先审计 ZIP 元数据，再决定是否解压攻击者可控的内容：

| `scan_status` | 含义 |
|---------------|------|
| `OK` | 所有相关候选均在预算内完成 |
| `PARTIAL` | 结果可用，但有条目因加密、压缩方式、压缩比、大小/累计预算或解压失败被跳过，见 `scan_diagnostics` |
| `REJECTED` | 整体越过硬限制，大规模解压前安全拒绝 |
| `ERROR` | 输入打不开、格式错误、内存分配失败或内部异常 |

默认硬限制（Web 层的 512 MiB 请求体是更外层的一道）：

| 资源 | 上限 |
|------|------|
| 包文件 | 1 GiB |
| ZIP 元数据 | 64 MiB；条目 ≤ 20,000 |
| SO 候选 | 256 个（`lib/arm64-v8a/` + `libs/arm64-v8a/` + `assets/`） |
| 单个 SO 解压 | 128 MiB；相关累计 512 MiB |
| 压缩比 | 解压后 ≥ 1 MiB 时最高 200:1 |
| 内层 ZIP | 元数据 16 MiB；条目 ≤ 1,024；单条目 128 MiB；累计 256 MiB |
| 返回诊断 | 前 64 条，额外数量单独计数 |

自动化系统先查 `scan_status` 再解释结果：`PARTIAL` 不是完整阴性，`REJECTED` 的空结果也不代表"未发现风险"。

### 已知局限

- 只支持 64 位 AArch64，不支持 32 位 ARM；只看 Native SO，包内字节码与资源（如 HAP 的 `ets/modules.abc`）不在范围内。
- OLLVM / 强混淆判断是启发式；VMP 数据流验证限于静态可观察的候选窗口，不等价于完整 CFG、跨函数污点分析或 bytecode 语义恢复。
- 运行时解密、自修改代码、非常规壳、自研 VM 和深度伪装样本可能漏报或只能给出不可判定。
- 未知或改名的合法运行时仍可能进入可疑队列；`dlopen`/`dlsym`、加密符号、自定义绑定的跨 SO 关系不可见。
- 内置 Web 服务面向本地分析，不是生产级鉴权/WAF/任务队列替代品。

评估检出能力应使用标注语料（已确认 VMP、普通 C/C++、switch/vtable、合法解释器、packed 样本），分别报告 precision、recall、混淆矩阵与不可判定比例。实际分析时先看高风险结果和入口预览，再用 IDA、Ghidra、Frida 或运行时轨迹确认。

### 贡献

欢迎 Issue / Pull Request，提交前请通过编译与 `ctest`。

### 许可证

[MIT](LICENSE)

### 致谢

- **Capstone** —— 轻量级多架构反汇编引擎
- **miniz** —— 单文件 ZIP 解压库
- **LibChecker-Rules** —— 原生库识别规则
- **GPT** —— 辅助开发与文案优化

---

## English

ObfuScan is a static pre-screening tool for native libraries in Android APK and HarmonyOS HAP packages. It enumerates the arm64 SO files inside a package and ranks them by risk using ELF structure, instruction statistics, protection traces, and VMP data-flow evidence, so reverse engineers and security auditors can pick the libraries worth manual analysis first.

It is a triage tool, not a decompiler: treat the output as prioritization, not final attribution.

### Quick Start

**Web UI (recommended)** — Python standard library only; use 3.9–3.12 (3.13 removed the `cgi` module it relies on):

```bash
python web_server.py
```

Open http://127.0.0.1:8080 and drop in an APK or HAP. Generic risk and VMP outcomes are shown separately; `PARTIAL`, `REJECTED`, and `ERROR` surface concrete diagnostics instead of looking like an empty successful scan. Health check: `curl http://127.0.0.1:8080/status`. If the page refuses to connect (`ERR_CONNECTION_REFUSED`), the local Python process simply is not running.

**Command line** — emits JSON:

```bash
ObfuScan.exe <apk_or_hap> [--en]
ObfuScan.exe app.apk > result.json
```

Automation must read the top-level `scan_status`: a rejected malicious package still produces valid JSON, so the process exit code alone is unreliable.

The web server defaults to `127.0.0.1:8080` with a 512 MiB request-body limit, a 900s scan timeout, and 2 concurrent scan slots — all overridable via the matching `OBFUSCAN_*` environment variables (full list at the top of `web_server.py`; `OBFUSCAN_EXECUTABLE` selects the engine). It ships bounded threading, idle timeouts, concurrency caps, upload/disk/output limits, and baseline security headers, but **no TLS, authentication, or quotas — do not bind it to `0.0.0.0` on the public Internet**. If you must expose it, put it behind a controlled reverse proxy, set `OBFUSCAN_EXPOSE_ENGINE_PATH=0`, and reduce scan concurrency to `1`.

### Build from Source

Requires CMake ≥ 3.15, a C++17 compiler, and Git (for fetching Capstone):

```bash
git clone --recurse-submodules https://github.com/1998lixin/ObfuScan.git
cd ObfuScan
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build --config Release
```

Single-config generators produce `build/ObfuScan[.exe]`; multi-config generators use `build/Release/`. MinGW builds link the runtime statically.

```bash
# Full regression: VMP data flow, ELF PT_DYNAMIC recovery, cross-SO linkage, ZIP/APK resource limits
ctest --test-dir build -C Release --output-on-failure

# End-to-end verdict regression against local SHA-256-pinned fixtures (not committed to the repo)
python tests/corpus_regression.py --scanner build/ObfuScan.exe --fixtures . --require-all
```

### Detection Dimensions

No single signatures — multi-factor heuristic scoring:

| Dimension | Evidence |
|-----------|----------|
| Entropy & structure | Section entropy, writable entry point, large high-entropy blocks → encryption, compression, self-modifying code |
| Instruction statistics | Capstone AArch64 branch / indirect-transfer / arithmetic-logic density → control-flow complexity |
| Initialization & dependencies | `.init_array`, imports/exports, `DT_NEEDED` → abnormal initialization and cross-SO relationships |
| Loader / Linker | Custom ELF-loader capability axes plus the linker-protection closure (below) |
| VMP structure | Multi-axis data-flow classification (next section) |
| Disguised containers | An SO that is actually a ZIP (`PK\x03\x04`) is opened under separate budgets and the inner ELF is analyzed |

Implementation notes:

- ELF recovery covers headers, segments/sections, entropy, symbols, dependencies, `DT_INIT[_ARRAY]`, and relocations; stripped section tables fall back to `PT_DYNAMIC` recovery.
- PLT exclusion uses `R_AARCH64_JUMP_SLOT` relocations rather than guessed address ranges.
- Entry preview: ELF entry, `.init_array`, `JNI_OnLoad`, `Java_*`, and init/load/register exports.

**Loading capability and protection are separate gates.** `CUSTOM_LOADER_COMPONENT` means a reasonably complete ELF-loading capability was found — nothing more. `LIKELY_CUSTOM_LINKER_PROTECTION` additionally requires independent evidence such as a protected payload or decrypt-and-load behavior. `mmap`, `mprotect`, `dlsym`, and ELF-metadata reads by hook/trampoline frameworks are ordinary ELF introspection, not custom-linker protection.

The final risk level (high/medium/low) is decided by independent packer, OLLVM/strong-obfuscation, linker-protection, and VMP gates — there is no single aggregate threshold. High risk: prioritize manual review. Medium: incomplete evidence, decide with application context. Low: consistent with ordinary release builds or light obfuscation, not a guarantee of safety.

### Multi-Axis VMP Classification

Every observable executable `PT_LOAD` region is scanned. Indirect-transfer sites are deduplicated, then validated with local register data-flow analysis around each candidate:

- VPC/VIP fetch-and-advance relationships and register data dependencies from opcode to handler target;
- dispatcher back edges, shared VM context, and candidate clustering;
- direct-, call-, and return-threaded dispatch, conditional dispatch, and threaded trampolines;
- alternative explanations: ordinary switch tables, vtable/function-pointer calls, ABI thunks, and known runtimes.

Each SO reports its final classification (`vmp_outcome`), confidence (`vmp_confidence`), dominant dispatch profile (`vmp_profile`), three decision axes (`vm_structure_score` / `protection_intent_score` / `alternative_penalty`), scan coverage (`vmp_scan_coverage`), observability and limitations (`vmp_observable` / `vmp_limitation`), candidate details (`vmp_candidates`), and cross-SO evidence (`vmp_provider_evidence`).

**Scores are evidence strength, not probabilities.** `0.90` does not mean a 90% chance of VMP. Read the outcome first, then interpret the axes, coverage, and limitations together.

| `vmp_outcome` | Meaning |
|---------------|---------|
| `LIKELY_VMP` | Structural data flow and protection context pass the decision threshold; prioritize manual confirmation |
| `VMP_PROTECTED_CLIENT` | No local dispatcher; a VMP-runtime-driven client confirmed by three-edge evidence |
| `VM_LIKE_INTERPRETER` | VM structure exists, but a legitimate runtime such as QuickJS, Lua, Hermes, or FFmpeg explains it better |
| `SUSPICIOUS_VM_STRUCTURE` | Suspicious VM structure with insufficient protection intent or candidate consistency |
| `INCONCLUSIVE_PACKED` | Packing/encryption prevents adequate static observation — inconclusive, not negative |
| `PARTIAL_ANALYSIS` | Scan coverage is incomplete; conclusions are limited |
| `NO_VMP_EVIDENCE` | Insufficient evidence within the reported coverage; runtime-decrypted code is out of scope |
| `NO_EXECUTABLE_CODE` | No observable executable code |
| `ANALYSIS_ERROR` | Analysis failed; fix the error before interpreting results |

**Cross-SO linkage** uses a strict three-edge gate. A client is marked `VMP_PROTECTED_CLIENT` only when all of the following hold:

1. the provider is already `LIKELY_VMP` and high risk;
2. the client has an exact `DT_NEEDED` match for the provider basename;
3. at least one client import is actually exported by that provider.

This is a dependency conclusion — "the client is driven by a high-confidence VMP runtime" — not a claim that a local dispatcher exists, and it does not inflate the client's own structure score or candidate list.

**Legitimate-runtime alternatives** are confirmed by three independent evidence classes: SO family name, identity strings, and runtime-specific import APIs. One class is only a weak hint; at least two are required for confirmation. A confirmed runtime never erases independent evidence such as protection metadata or a closed dispatcher.

### Scan Safety Boundaries

ZIP metadata is audited before any attacker-controlled content is extracted:

| `scan_status` | Meaning |
|---------------|---------|
| `OK` | Every relevant candidate finished within budget |
| `PARTIAL` | Results are usable, but some entries were skipped (encryption, compression method, extreme ratio, size/cumulative budget, or extraction failure) — see `scan_diagnostics` |
| `REJECTED` | The input crosses a hard limit and is rejected before large-scale extraction |
| `ERROR` | The input cannot be opened, is malformed, allocation fails, or an internal exception occurs |

Default hard limits (the web layer's 512 MiB request-body cap is an additional outer boundary):

| Resource | Limit |
|----------|-------|
| Package file | 1 GiB |
| ZIP metadata | 64 MiB; ≤ 20,000 entries |
| SO candidates | 256 (across `lib/arm64-v8a/`, `libs/arm64-v8a/`, and `assets/`) |
| Single uncompressed SO | 128 MiB; 512 MiB cumulative |
| Compression ratio | At most 200:1 when output is ≥ 1 MiB |
| Nested ZIP | 16 MiB metadata; ≤ 1,024 entries; 128 MiB per entry; 256 MiB total |
| Returned diagnostics | First 64, with the remainder counted |

Check `scan_status` before interpreting results: `PARTIAL` is not a complete negative, and an empty `REJECTED` result does not mean "no risk found."

### Known Limitations

- 64-bit AArch64 only (no 32-bit ARM); native SOs only — package bytecode and resources (e.g. a HAP's `ets/modules.abc`) are out of scope.
- OLLVM / strong-obfuscation detection is heuristic; VMP data-flow validation is local to statically observable candidate windows, not full CFG recovery, interprocedural taint analysis, or bytecode-semantic reconstruction.
- Runtime-decrypted code, self-modifying code, unconventional packers, custom VMs, and deep disguises may be missed or remain inconclusive.
- Unknown or renamed legitimate runtimes may still enter the suspicious queue; cross-SO relationships established via `dlopen`/`dlsym`, encrypted symbols, or custom binding are invisible.
- The built-in web server is for local analysis, not a replacement for production authentication, WAF, or job queues.

Evaluate detection quality on a labeled corpus (confirmed VMP, ordinary C/C++, switch/vtable dispatch, legitimate interpreters, packed samples) and report precision, recall, a confusion matrix, and the inconclusive rate separately. In practice, review high-risk results and entry previews first, then confirm in IDA, Ghidra, Frida, or runtime traces.

### Contributing

Issues and pull requests are welcome; please build and pass `ctest` before submitting.

### License

[MIT](LICENSE)

### Acknowledgments

- **Capstone** — lightweight multi-architecture disassembly engine
- **miniz** — single-file ZIP decompression library
- **LibChecker-Rules** — native library identification rules
- **GPT** — development assistance and documentation
