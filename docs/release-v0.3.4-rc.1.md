## Windows 出站保护控制台 · 发布候选版

普通 SSH 和其他 IPv4 应用经 Mihomo TUN 进入 v2rayN 的 1081；系统代理应用可直接进入 1081。1082 属于 Mihomo。再次进入 TUN 的 Xray 连接按可执行文件路径送到绑定物理网卡的辅助 Xray。WFP 同时约束 IPv4 和 IPv6 物理出站。局域网与热点登录使用单独的接口级例外。

[中文拓扑图、DNS、启动与恢复](https://github.com/seanzhang9999/V2RayN-TUN-Bridge/blob/v0.3.4-rc.1/README.zh-CN.md) · [English packet paths and setup](https://github.com/seanzhang9999/V2RayN-TUN-Bridge/blob/v0.3.4-rc.1/README.md)

解压 Windows x64 发行包后运行 `guard-console.pyw`。需要安装 64 位 Python 3.11+（含 Tk）和已有的 v2rayN/Xray。停止 TUN 后，出站保护继续生效，点「关闭保护」可恢复普通物理出站。

已验证两台 SSH 服务器经隔离 TUN 的密钥协商与指纹，以及 Xray 物理出口规则。全机保护的长期运行和 Antigravity 完整登录仍待验证。
