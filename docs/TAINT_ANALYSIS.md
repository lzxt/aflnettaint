# 污点分析增强 Fuzzing 功能使用说明

## 概述

本功能通过 `-T taint` 参数启用，实现了基于污点分析（Taint Analysis）的增强 fuzzing。该功能包含四个主要阶段：

1. **静态分析与插桩**：识别 CMP 指令，插桩污点源和传播
2. **运行时 Byte-to-CMP 映射**：建立输入字节到比较操作的映射关系
3. **Dual-Feedback 种子选择**：结合控制流和数据流反馈
4. **定向翻转变异**：基于映射表进行精准变异

## 使用方法

### 1. 编译 AFL LLVM 模式

```bash
cd llvm_mode
make
cd ..
```

这将编译：
- `afl-clang-fast` / `afl-clang-fast++`
- `afl-llvm-pass.so`（包含污点分析插桩）
- `afl-llvm-taint-rt.o`（污点分析运行时库）

### 2. 编译目标程序（启用污点分析）

```bash
export AFL_TAINT_ANALYSIS=1  # 可选：显式启用（运行时也会自动设置）

CC=./afl-clang-fast \
CXX=./afl-clang-fast++ \
make your_target
```

### 3. 运行 Fuzzing（启用污点分析模式）

```bash
afl-fuzz -i in -o out -T taint -- ./your_target [args...]
```

## 功能说明

### 第一阶段：静态分析与插桩

**识别目标 Sink (Candidate CMPs)**：
- 自动识别以下类型的比较指令：
  - `ICmpInst`（整数比较）
  - `SwitchInst`（switch 语句）
  - `memcmp`, `strcmp`, `strncmp`, `strcasecmp`, `strncasecmp`, `bcmp` 函数调用
- 为每个 CMP 分配唯一的 `CMP_ID`（最大 4096 个）

**污点源插桩 (Source)**：
- 在以下函数调用后标记输入缓冲区：
  - `recv`, `read`, `recvfrom`, `recvmsg`, `readv`
- 每个字节维护一个 16-bit 标签，代表其在输入流中的偏移量

**轻量级传播 (Propagation)**：
- 在 Load/Store 指令处传播污点标签
- 仅在操作数带有污点标签时才计算结果的标签

**关键 Sink 记录 (Sink)**：
- 在预识别的 Candidate CMPs 处插入回调：
  ```c
  __afl_check_taint(CMP_ID, val1, val2)
  ```

### 第二阶段：运行时 Byte-to-CMP 映射

**Taint Bitmap 结构**：
- 建立 `Map[CMP_ID]`，每个 CMP_ID 对应一个位图
- 位图记录哪些输入字节（Offsets）参与了该 CMP 的运算
- 共享内存大小：`MAX_CMP_ID * (MAX_FILE / 8)` 字节

**触发逻辑**：
- 当程序运行到 Candidate CMP 时，运行时库检查两个操作数的污点标签
- 如果有标签，将标签对应的 Offset 记录在 `Map[CMP_ID]` 中

### 第三阶段：Dual-Feedback 种子选择与调度

**判定逻辑**：

1. **控制流优先 (CFG Priority)**：
   - 若发现新边（New Edge），该种子直接入队，赋予高优先级
   - 这是 AFL 的正常逻辑

2. **数据流增量判定 (ValidDF)**：
   - 如果没有发现新边，但触发了 Candidate CMP
   - 检查该种子在 `Map[CMP_ID]` 中关联的 Offset 集合是否发生了变化（DF_change）
   - 如果 DF_change 为真，将该种子保存为"数据流潜力种子"，标记为 `DF_Interesting`

3. **调度策略**：
   - **正常阶段**：优先处理 CFG 种子，使用 AFLnet 的状态机变异
   - **瓶颈阶段**：如果 Fuzzer 在过去的 60min 内没有发现任何 New Edge，则强制激活一轮 DF_Interesting 种子

### 第四阶段：定向翻转变异（待完善）

**定位关键字节**：
- 从队列中取出一个 DF_Interesting 种子
- 查询该种子对应的 `Map[CMP_ID]`
- 假设 CMP_ID #42（通往未覆盖分支）受输入偏移 [0x10, 0x11, 0x15] 影响

**局部分析与翻转**：
- 变异引擎不再遍历全文件
- 集中火力：仅针对关键位置（如 0x10, 0x11, 0x15）进行 bitflip, arithmetic, interest values 等变异
- 同步状态：在变异时，保持协议状态机（AFLnet 的 State）一致

## 技术细节

### 共享内存布局

- **标准覆盖率位图**：`MAP_SIZE` 字节（通过 `__AFL_SHM_ID` 环境变量）
- **污点映射表**：`TAINT_MAP_SIZE` 字节（通过 `__AFL_TAINT_MAP_SHM_ID` 环境变量）

### 环境变量

- `AFL_TAINT_ANALYSIS=1`：启用污点分析（由 `-T taint` 自动设置）
- `__AFL_TAINT_MAP_SHM_ID=<id>`：污点映射表的共享内存 ID（自动设置）
- **输入字节偏移与 AFLNet 种子对齐**：`recv` / `recvfrom` 使用**跨多次调用的累积偏移**，与 AFLNet 将多条请求拼接成单个种子文件的布局一致；单包 DNS 与多包 RTSP/FTP 等均能正确映射到队列文件中的字节位置。
- `AFL_TAINT_STREAM_READ=1`：若被测服务用 `read()` 从套接字按流读入（而非 `recv`），可设置此项，使 `read()` 也使用与 `recv` 相同的累积偏移。若目标在收包前用 `read()` 读配置文件，**不要**开启，否则偏移会与种子错位。
- `AFL_TAINT_DIRECTED=0`：关闭额外的 `taint-directed` 局部变异阶段，但保留 DF 种子保存与调度信息。用于判断覆盖率下降是否由定向变异预算压制 AFLNet 原生 region/state 探索造成。
- `AFL_TAINT_AGGRESSIVE=1`：恢复更激进的 DF 策略，放宽 DF 种子质量门控，并提高关键字节数量和每字节变异次数。建议只在 DNS 或短单包协议上尝试；RTSP/FTP/SMTP 等多报文长会话默认使用保守混合策略。
- `AFL_TAINT_REGION_SELECT=0`：关闭 DF 驱动的 AFLNet region 选择。默认开启时，DF 种子会优先选择包含最多 taint 关键偏移的消息作为 M2；这对 FTP 命令序列、DTLS record、HTTP/DAAP 请求这类多消息协议尤其重要，因为 taint 偏移来自整条 seed，而 AFLNet 实际变异的是某个 M2 子序列。

### 数据结构

在 `queue_entry` 结构中新增字段：
- `df_interesting`：标记该种子是否为数据流潜力种子

## 限制与注意事项

1. **CMP 数量限制**：最多支持 4096 个 CMP_ID
2. **输入大小限制**：最大输入文件大小为 `MAX_FILE`（默认 1MB）
3. **性能开销**：污点分析会增加一定的运行时开销
4. **兼容性**：需要 LLVM/Clang 支持（通常 >= 3.8）

## 未来改进方向

1. **完整的污点传播**：实现完整的 shadow memory 机制
2. **定向变异优化**：完善基于映射表的精准变异策略；当前实现已加入保守混合策略，对多报文/长会话种子降低 DF 局部变异预算，避免压制 AFLNet 的状态机和 region-level 变异。
3. **调度算法优化**：改进 DF_Interesting 种子的调度优先级
4. **多线程支持**：支持多线程程序的污点分析

## 示例

```bash
# 编译 miniupnp（启用污点分析）
export AFL_PATH=$(pwd)
cd /path/to/miniupnp
CC=$AFL_PATH/afl-clang-fast make

# 运行 fuzzing
afl-fuzz -i in -o out -T taint -N tcp://127.0.0.1/5000 -P UPNP -- ./miniupnpd
```

## 相关文件

- `afl-fuzz.c`：主 fuzzer 逻辑，包含调度和变异
- `llvm_mode/afl-llvm-pass.so.cc`：LLVM Pass，负责静态插桩
- `llvm_mode/afl-llvm-taint-rt.o.c`：运行时库，负责污点跟踪

