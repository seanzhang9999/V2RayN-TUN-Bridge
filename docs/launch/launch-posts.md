# Launch posts

Publish only after the `v0.1.0` release ZIP and checksum are available.

## LinkedIn

I built a small Windows networking tool after repeatedly hitting a strange
problem: v2rayN's normal proxy worked, but TUN mode made every connection time
out.

The result is V2RayN TUN Bridge. It reads the profiles and routing rules already
stored by v2rayN, then runs a guarded independent TUN—without asking users to
copy subscriptions or credentials into another client.

It also separates recent connections captured by TUN from connections entering
through the local mixed proxy, while showing proxy versus direct routing. The
history stays in memory only.

The first public release supports Hysteria2 and common VLESS transports on
Windows 11 x64. It is experimental, open source, and comes with a portable
download plus reproducible build workflow.

I would value feedback from people who have encountered Windows TUN routing,
DNS, or loopback failures.

Repository link in the first comment.

## X thread

1. v2rayN proxy works. Enable TUN. Everything times out. I ran into this enough
   times that I built a focused Windows workaround. 🧵
2. V2RayN TUN Bridge reuses the profiles + routing rules already stored by
   v2rayN, then runs an independently managed TUN. No subscription re-entry.
3. The important fix: pin the real proxy endpoint, exclude it from TUN, and bind
   direct traffic to the physical interface so the core cannot route into itself.
4. The GUI separates recent TUN connections from local mixed-proxy connections,
   with targets, traffic, and proxy/direct routing. History stays in memory.
5. First release: Windows 11 x64, Hysteria2 + common VLESS transports, portable
   ZIP, open source. Feedback and redacted bug reports welcome:
   https://github.com/seanzhang9999/V2RayN-TUN-Bridge

## Telegram

发布了一个 Windows TUN 小工具：V2RayN TUN Bridge。

它直接读取现有 v2rayN 的节点和路由，再由独立内核建立 TUN，不需要重新导入
订阅。主要用于“普通代理正常，但 TUN 打开后全部超时/DNS 异常/出现回环”的
情况。

GUI 分别显示最近的 TUN 连接和 1081 本地代理连接，包括目标地址、流量及
代理/直连出口。监控数据只保存在内存中。

首发支持 Windows 11 x64、Hysteria2 和常见 VLESS 传输，提供免 Python 的
便携 ZIP。项目仍属实验版本，欢迎提交脱敏后的测试结果：
https://github.com/seanzhang9999/V2RayN-TUN-Bridge
