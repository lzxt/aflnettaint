## AFLNet 对 UPnP（SOAP-over-HTTP）进行 fuzz 的使用说明

### 适用范围

UPnP 典型的“控制面”是 **SOAP over HTTP(TCP)**：客户端向设备/服务的 control URL 发送 `POST`，body 是 XML(SOAP)。

本仓库已新增 `-P UPNP`：

- **请求分帧**：按 `\r\n\r\n` 找到 header 结束，并根据 `Content-Length` 把 **header+body** 作为一个完整消息发送，避免只发 header 导致服务端一直等 body 而无响应。
- **Content-Length 自动修复**：发送前会尽量把 `Content-Length` 的数字重写成真实 body 长度（不改变报文长度，只覆盖原有数字位宽），降低变异后 `Content-Length` 不一致造成的 hang。

### 生成一个最小 seed（包含正确的 CRLF）

执行下面脚本会生成 `tutorials/upnp/in-upnp/seed1.raw`：

```bash
python tutorials/upnp/make_seed.py
```

你需要根据被测 UPnP 服务修改 `Host`、端口以及 `POST` 的路径（control URL）。

### fuzz 命令示例

以 TCP 方式 fuzz（把 `127.0.0.1/5000` 改成你的 UPnP 控制端口）：

```bash
afl-fuzz -d -i tutorials/upnp/in-upnp -o out-upnp -N tcp://127.0.0.1/5000 -P UPNP -D 10000 -W 5 -w 1000 -E -R -- /path/to/your_upnp_server [args...]
```

提示：

- 如果你的服务对 `Content-Length` 很严格，建议 seed 里把 `Content-Length` 写成 **固定宽度数字**（脚本默认 10 位），这样发送前的自动修复更稳定。
- UPnP 设备发现（SSDP / UDP 1900）属于另一条链路；本 `UPNP` 主要面向 **HTTP 控制接口** 的 fuzz。



