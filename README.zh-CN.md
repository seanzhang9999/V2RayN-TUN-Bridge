# V2RayN TUN Bridge

Windows x64 出站保护控制台。v2rayN 持有节点、路由和系统代理 `127.0.0.1:1081`。Bridge 为普通 IPv4 应用建立 Mihomo TUN，并用 Windows Filtering Platform（WFP）约束物理出口。界面显示最近观察到的 20 个应用及目标、Xray 直连规则、热点登录请求和工作日志。[English](README.md)

## 网络拓扑

```mermaid
flowchart LR
    A["普通应用 / OpenSSH"] --> T["Windows IPv4 路由 → Mihomo TUN"]
    T -->|"普通进程 · MATCH"| V["v2rayN 管理的 Xray · 127.0.0.1:1081"]
    S["使用系统代理的应用"] --> V
    M["显式使用 1082 的应用或诊断"] --> P["Mihomo mixed · 127.0.0.1:1082"]
    P -->|"普通进程"| V
    V -->|"代理规则 · 连接 VPN 节点"| G["WFP 检查物理出站"]
    V -->|"直连 socket 已选择物理接口"| G
    V -->|"Xray 出站 socket 再次进入 TUN"| T
    T -->|"进程完整路径命中当前 xray.exe"| R["本机 VLESS → 辅助 Xray freedom · 绑定物理接口"]
    R --> G
    G -->|"节点 IP + 协议 + 端口"| N["VPN 节点 → 远端服务"]
    G -->|"Xray 目标 IP 命中允许网段"| D["允许直连的目标"]
    G -->|"其他物理公网连接"| B["阻断"]
```

- **入口。** 普通 SSH 使用 Windows 路由进入 TUN，无需改 SSH 配置。Mihomo 将普通流量送往 1081，由 v2rayN 决定代理或直连。1082 是 Mihomo 对外提供的本机诊断入口。系统代理应用可直接使用 1081。
- **避免回环。** 当 Xray 已经分流的连接又被 Windows 送回 TUN，Mihomo 按 Xray 可执行文件的完整路径选中物理出口。Bridge 使用同一安装目录里的 Xray 启动辅助进程，监听随机回环端口，使用每次运行生成的 VLESS 身份，并以 `sockopt.interface` 绑定启动时的物理网卡。物理 WFP 规则继续检查目标地址。普通 SSH 访问与 VPN 节点相同的 IP 时仍可进入 TUN，该节点的整条 IP 不做路由排除。
- **DNS 和地址族。** TUN 配置劫持 53 端口并使用 fake-IP，默认上游是经代理访问的 DoH。辅助 Xray 需要解析域名时，经 1081 访问 DoH。主 Xray 仍使用 v2rayN 生成的 DNS 配置。WFP 同时默认阻断 IPv4 和 IPv6 物理出站。当前 TUN 转发和节点发现按 IPv4 配置，IPv6 的保护与 IPv6 代理转发是两项独立能力。
- **直连边界。** 节点放行限定 Xray 程序、节点 IP、传输协议和端口。纯 IP 直连规则中的 IP、CIDR、`geoip:cn` 转成 Xray 专用 WFP 例外。域名及复合条件保留在界面供查看，由 Xray 分流；只有目标 IP 也符合 WFP 条件，物理直连才能成功。网段规则按 IP 放行，DNS 服务商分类只用于显示。
- **局域网和热点。** 局域网例外限定当前物理接口、本地源地址及批准的在链地址范围，排除常用 DNS 端口。用户可以按 Wi-Fi 选择记住局域网配置。热点登录使用独立 Edge 配置和本机 PortalRelay，只有中继获得专用 DNS 和已批准目标 IP、端口的物理例外。关闭本次登录会话后收回这些例外。

## 启动与恢复

1. 下载并解压 Windows x64 发行包。安装带 Tk 的 **64 位 Python 3.11 或更新版本**，确保 `python` 在 PATH 中。热点登录需 Microsoft Edge。[发行版](https://github.com/seanzhang9999/V2RayN-TUN-Bridge/releases)
2. 先启动 v2rayN，使用 Xray 核心并确认本机 mixed/SOCKS 代理 1081 可用。双击 `guard-console.pyw`，或运行 `python -X utf8 guard-console.pyw`。首次选择包含 `v2rayN.exe`、`bin/Xray/xray.exe` 和 `binConfigs/config.json` 的安装目录。
3. 点「开启保护并启动 TUN」，批准 Windows 管理员提示。规则先安装，随后启动 TUN 并等待 WFP 确认新接口。点「停止 TUN」后物理出站保护继续生效；需要恢复正常 Windows 出站时再点「关闭保护」。关闭窗口后后台保护可以继续运行。
4. 通过「最近 20 个 TUN 目标」和「TUN 工作日志」核对连接。显式走 1081 的流量可能完全绕过 TUN 采样。故障时可重新打开控制台操作开关；会话状态和日志位于当前用户的 `%LOCALAPPDATA%\v2rayn-tun-controller`。

## 当前验证范围

已在 Windows 上通过隔离 TUN 使用系统 OpenSSH 与两台真实服务器协商密钥，两个指纹都与各自基线一致。另行确认了 Xray 路径匹配及绑定物理网卡的辅助出口。该次测试保留了原有 SSH 会话和 1081。带全机 WFP 的长期运行、IPv6 端到端转发、Antigravity 完整登录尚未作为本候选版的验收项通过。
