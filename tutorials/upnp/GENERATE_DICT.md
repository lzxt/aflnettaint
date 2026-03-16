# 为 miniupnp 自动生成协议字典

本指南说明如何使用 AFL LLVM 插件的自动字典生成功能，在编译 miniupnp 时提取协议关键字和魔数。

## 前置条件

1. **确保已安装 LLVM/Clang**
   - 需要支持 LLVM Pass 的 clang 版本（通常 >= 3.8）
   - 检查：`clang --version` 或 `llvm-config --version`
   - 在 Windows 上，可以使用 WSL 或 MSYS2/MinGW

2. **编译 AFL LLVM 模式（生成 afl-clang-fast）**
   
   如果项目根目录下还没有 `afl-clang-fast` 和 `afl-clang-fast++`，需要先编译：
   
   ```bash
   cd llvm_mode
   make
   cd ..
   ```
   
   编译成功后，会在项目根目录生成：
   - `afl-clang-fast` - C 编译器包装器
   - `afl-clang-fast++` - C++ 编译器包装器（符号链接）
   - `afl-llvm-pass.so` - LLVM Pass 插件（包含字典生成功能）
   - `afl-llvm-rt.o` - 运行时库
   
   **注意**：如果编译失败，检查：
   - `llvm-config` 是否在 PATH 中
   - LLVM 版本是否兼容（可能需要设置 `LLVM_CONFIG=llvm-config-XX`）
   - 在 Windows 上建议使用 WSL 或 MSYS2 环境

## 步骤 1：设置环境变量

设置 `AFL_AUTO_DICT` 环境变量，指定字典输出文件路径：

```bash
export AFL_AUTO_DICT=$(pwd)/tutorials/upnp/upnp_auto.dict
```

或者使用绝对路径：
```bash
export AFL_AUTO_DICT=/path/to/your/upnp_auto.dict
```

## 步骤 2：确认 afl-clang-fast 已存在

编译 llvm_mode 后，确认文件已生成：

```bash
# 在项目根目录检查
ls -la afl-clang-fast afl-clang-fast++ afl-llvm-pass.so

# 如果文件不存在，先编译：
cd llvm_mode
make
cd ..
```

## 步骤 3：编译 miniupnp（使用 afl-clang-fast）

假设你正在编译 miniupnp 项目，使用 AFL 的编译器包装器：

```bash
# 进入 miniupnp 源码目录（假设你已经下载了 miniupnp）
cd /path/to/miniupnp/miniupnpd

# 设置 AFL 路径（根据你的实际路径调整）
# 假设 aflnetupnpllm 在 /path/to/aflnetupnpllm
export AFL_PATH=/path/to/aflnetupnpllm

# 使用 afl-clang-fast 编译
CC=$AFL_PATH/afl-clang-fast \
CXX=$AFL_PATH/afl-clang-fast++ \
make

# 或者如果使用 configure：
# CC=$AFL_PATH/afl-clang-fast ./configure
# make

# 或者直接指定完整路径：
# CC=/path/to/aflnetupnpllm/afl-clang-fast \
# CXX=/path/to/aflnetupnpllm/afl-clang-fast++ \
# make
```

**重要**：编译过程中，插件会自动：
- 遍历所有源文件的全局字符串常量（如 "POST", "GET", "AddPortMapping" 等）
- 扫描指令中的 16/32 bit 整型常量（可能的魔数）
- 将发现的 token 追加写入 `AFL_AUTO_DICT` 指定的文件

## 步骤 4：查看生成的字典

编译完成后，查看生成的字典文件：

```bash
cat $AFL_AUTO_DICT
# 或
cat tutorials/upnp/upnp_auto.dict
```

字典文件格式示例：
```
"POST"
"GET"
"AddPortMapping"
"DeletePortMapping"
"GetStatusInfo"
"urn:schemas-upnp-org:service:WANIPConnection:1"
"\x12\x34"
"\x34\x12"
"\x12\x34\x56\x78"
"\x78\x56\x34\x12"
```

## 步骤 5：使用字典进行 Fuzzing

在运行 `afl-fuzz` 时，使用 `-x` 参数指定字典文件：

```bash
afl-fuzz -i tutorials/upnp/in-upnp \
         -o out-upnp \
         -x tutorials/upnp/upnp_auto.dict \
         -N tcp://127.0.0.1/5000 \
         -P UPNP \
         -D 10000 \
         -W 5 \
         -w 1000 \
         -E -R \
         -- /path/to/miniupnpd [args...]
```

## 注意事项

1. **字典文件会追加写入**：如果多次编译，同一个 token 不会重复写入（插件内部去重）。

2. **字典质量**：自动生成的字典可能包含一些噪音（非协议相关的字符串），建议：
   - 手动审查字典文件
   - 删除明显无关的条目
   - 保留协议特有的关键字（如 SOAP 方法名、HTTP 方法、UPnP URN 等）

3. **如果字典文件为空**：
   - 检查 `AFL_AUTO_DICT` 环境变量是否正确设置
   - 确认使用的是 `afl-clang-fast` 而不是普通 `clang`
   - 检查编译日志是否有错误

4. **多文件编译**：如果项目有多个源文件，插件会为每个 `.c` 文件分别处理，最终合并到同一个字典文件中。

## 示例：基于 knowledge_base/code 中的代码生成字典

如果你直接编译 `knowledge_base/code` 目录下的 miniupnp 代码：

```bash
cd knowledge_base/code

# 设置环境变量
export AFL_AUTO_DICT=$(pwd)/../upnp_auto.dict
export AFL_PATH=/path/to/aflnetupnpllm

# 编译（假设有 Makefile）
CC=$AFL_PATH/afl-clang-fast make

# 查看字典
cat ../upnp_auto.dict
```

## 预期提取的关键字类型

基于 miniupnp 代码，字典可能包含：

- **HTTP 方法**：`"POST"`, `"GET"`, `"SUBSCRIBE"`, `"UNSUBSCRIBE"`
- **SOAP 方法名**：`"GetStatusInfo"`, `"AddPortMapping"`, `"DeletePortMapping"`, `"GetExternalIPAddress"` 等
- **UPnP URN**：`"urn:schemas-upnp-org:service:WANIPConnection:1"` 等
- **XML 标签/属性**：`"xml version"`, `"scpd xmlns"`, `"root xmlns"` 等
- **协议状态字符串**：`"TCP"`, `"UDP"`, `"Connected"`, `"Disconnected"` 等
- **魔数**：16/32 bit 的协议相关常量（如端口号范围、错误码等）

