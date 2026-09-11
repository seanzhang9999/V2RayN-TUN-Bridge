# V2RayN TUN Bridge launch kit

Current release: `v0.1.4`

- Repository: https://github.com/seanzhang9999/V2RayN-TUN-Bridge
- Download: https://github.com/seanzhang9999/V2RayN-TUN-Bridge/releases/latest
- Primary audience: Windows 11 users whose v2rayN local proxy works but TUN
  causes timeouts, DNS failures, or routing loops.
- Honest limitations to retain in launch posts: unsigned Windows build, IPv4
  TUN only, XHTTP not yet supported, and v2rayN 7.x is the tested storage
  layout.

Do not publish identical text to several communities on the same day. Adapt the
opening to the community, disclose that you built the project, and stay
available to answer questions after posting.

## Core positioning

One-line product description:

> V2RayN TUN Bridge reuses an existing v2rayN profile and routing policy, then
> runs a separately managed Mihomo TUN without requiring the user to re-enter a
> subscription or credentials.

One-line development story:

> A Windows TUN failure that repeatedly disconnected the AI helping debug it
> became a human-in-the-loop experiment—and eventually a working open-source
> desktop tool.

The project should not be described as a replacement for v2rayN, Clash Verge,
or Mihomo. It is a focused companion for people who want to keep v2rayN as the
configuration source while using an independently controlled TUN path.

## LinkedIn — recommended English post

I asked Codex to solve a networking problem that could disconnect Codex itself.

My normal v2rayN proxy worked, but enabling TUN caused timeouts, DNS failures,
and sometimes a routing loop. The obvious debugging workflow had a paradox:
each realistic TUN test could cut off the connection to the model doing the
debugging.

So we changed the workflow.

I provided the goal, made the product decisions, approved system-level tests,
and performed the online checks. Codex inspected the configurations, designed
guardrails, wrote the controller and GUI, and analyzed redacted logs after I
restored connectivity.

The cycle became:

1. Prepare the next test without touching the working proxy.
2. Record enough local evidence to survive a failed network test.
3. Let me switch and validate the real connection.
4. Restore v2rayN, reconnect Codex, and analyze the result.
5. Turn each finding into automated tests and safer recovery logic.

We eventually traced the important failures to routing, DNS, physical-interface
selection, and the risk of sending the proxy server's own connection back into
the TUN.

The result is V2RayN TUN Bridge: an open-source Windows utility that reads the
profile and routing policy already stored by v2rayN, then runs a separately
managed Mihomo TUN. It supports Hysteria2 and common VLESS transports, includes
a local mixed proxy, reacts to Wi-Fi changes, and shows recent TUN and proxy
connections.

The interesting lesson was not that an AI agent could magically fix networking.
It was that a human and an agent could design a recovery-aware workflow around
a failure that interrupted their own collaboration.

The Windows build is still early and unsigned. I would especially value
feedback from people who have seen v2rayN work in normal proxy mode but fail in
TUN mode.

Repository and portable release in the first comment.

### LinkedIn first comment

Source and portable Windows release:
https://github.com/seanzhang9999/V2RayN-TUN-Bridge

Current scope: Windows 11 x64, IPv4 TUN, Hysteria2 and VLESS over TCP/raw, gRPC,
or WebSocket. XHTTP is not supported yet. Please remove server addresses and
credentials before sharing logs.

## LinkedIn — Chinese version

我让 Codex 解决了一个可能让 Codex 自己掉线的网络问题。

当时 v2rayN 的普通代理可以使用，但一打开 TUN，就会出现全部超时、DNS
异常，甚至代理流量回到 TUN 的循环。这里有一个很现实的悖论：真正测试 TUN
时，负责协助排查的 Codex 也可能因此失去网络连接。

所以我们重新设计了协作方式。

我负责确定目标、选择方案、批准系统级测试，并在断网风险下完成真实网络验证；
Codex 负责读取和比较配置、设计保护机制、开发控制器与 GUI，以及在网络恢复后
分析脱敏日志。

整个循环变成了：

1. 在不破坏现有代理的前提下准备下一轮测试；
2. 让测试证据保存在本机，即使断网也不会丢失；
3. 由我切换运行状态并验证真实连接；
4. 恢复 v2rayN，让 Codex 重新联网分析结果；
5. 把每次发现转成自动化测试和更可靠的恢复逻辑。

最后，我们把问题逐步收敛到 Windows 路由、DNS、物理网卡选择，以及代理服务
器自身流量被再次送回 TUN 等环节。

这次排查最终变成了一个开源工具：V2RayN TUN Bridge。它直接读取 v2rayN
已经保存的节点和路由策略，再用独立管理的 Mihomo 建立 TUN，不需要重新录入
订阅或账号。目前支持 Hysteria2 和常见 VLESS 传输，也提供本地 mixed 代理、
Wi-Fi 切换检测，以及 TUN/代理连接查看。

这件事最有意思的地方，并不是“AI 自动解决了一切”，而是人和 AI 如何为一个
会中断双方协作的问题，设计出可恢复、可验证的工作流程。

目前 Windows 版本仍处于早期阶段，并且尚未进行商业代码签名。如果你也遇到过
“普通代理正常，但 TUN 一开就断网”，欢迎帮我测试。

项目和便携版下载地址放在第一条评论。

### LinkedIn 中文首评

源码与 Windows 便携版：
https://github.com/seanzhang9999/V2RayN-TUN-Bridge

当前范围：Windows 11 x64、IPv4 TUN、Hysteria2，以及 TCP/raw、gRPC、
WebSocket 传输的 VLESS。暂不支持 XHTTP。反馈日志前请删除服务器地址和凭据。

## Reddit — r/dumbclub

Suggested title:

> I built a Windows TUN bridge for v2rayN after normal proxy mode worked but TUN kept breaking connectivity

Post body:

I kept running into a Windows problem where v2rayN worked normally as a local
proxy, but enabling TUN caused timeouts, DNS failures, or a routing loop.

I built an open-source companion called V2RayN TUN Bridge. It reads the selected
profile and active routing policy from the local v2rayN database, converts the
supported settings, and runs a separately managed Mihomo TUN. You do not need
to re-enter a subscription or credentials.

The main safeguards are resolving and excluding the real proxy endpoint from
TUN, binding direct traffic to the physical interface, rebuilding after Wi-Fi
changes, and cleaning up only the adapter and process created by this run.

The GUI also exposes a mixed SOCKS/HTTP endpoint on 127.0.0.1:1081 and separates
the last ten TUN connections from the last ten mixed-proxy connections. The
monitoring history remains in memory.

Current support:

- Windows 11 x64
- Hysteria2
- VLESS over TCP/raw, gRPC, or WebSocket
- IPv4 TUN

Current limitations:

- XHTTP is not supported
- the portable build is unsigned
- v2rayN 7.x is the tested database layout

Source and release:
https://github.com/seanzhang9999/V2RayN-TUN-Bridge

I am the author. I would appreciate compatibility reports, especially from
people who can use v2rayN's normal proxy but not its TUN mode. Please redact
server addresses and credentials from logs.

## X — English thread

### Post 1

v2rayN proxy worked. TUN broke every connection.

The awkward part: each real test could also disconnect the Codex agent helping
me debug it. So we built a recovery-aware workflow—and eventually a Windows
app. A short build story 🧵

### Post 2

I handled goals, decisions and real network tests. Codex prepared guarded test
runs, wrote the controller/GUI, and analyzed local logs after I restored the
working proxy.

Human-in-the-loop was not optional here; it was part of the architecture.

### Post 3

The important fixes were unglamorous but critical:

- exclude the real proxy endpoint from TUN
- bind direct traffic to the physical interface
- keep DNS routing consistent
- rebuild safely when Wi-Fi changes
- clean up only resources created by this run

### Post 4

The result: V2RayN TUN Bridge.

It reuses the profile + routes already stored by v2rayN, then runs an
independently managed Mihomo TUN. No subscription re-entry.

Hysteria2 + common VLESS transports, Windows 11 x64.

### Post 5

It also provides a local mixed proxy on 127.0.0.1:1081 and separate views for
recent TUN and proxy connections.

Early, unsigned and open source. Testers welcome:
https://github.com/seanzhang9999/V2RayN-TUN-Bridge

## X — single Chinese post

我和 Codex 一起解决了一个很有意思的悖论：v2rayN 普通代理正常，但开启 TUN
就断网，而断网后 Codex 也无法继续协助排查。

我们把测试改成“本地留证据 → 我手动验证 → 恢复网络 → Codex 分析 → 自动化
下一轮”，最后做成了 V2RayN TUN Bridge：读取现有 v2rayN 节点和路由，独立
运行 Mihomo TUN，支持 Hysteria2、常见 VLESS 传输和 1081 mixed 代理。

开源项目，欢迎测试：
https://github.com/seanzhang9999/V2RayN-TUN-Bridge

## Hacker News — Show HN

Suggested title:

> Show HN: A Windows TUN bridge that reuses v2rayN profiles and routing rules

Post body:

I built V2RayN TUN Bridge after repeatedly seeing local proxy mode work while
TUN mode caused DNS failures, timeouts, or a routing loop on Windows.

The app reads the selected profile and active routing policy from v2rayN's local
database, translates the supported subset, and runs a separately controlled
Mihomo TUN. The key engineering work was endpoint exclusion, physical-interface
binding, DNS behavior, safe recovery, and rebuilding the route when the network
interface changes.

The debugging process had an unusual constraint: a failed TUN test could cut
off the Codex agent helping me develop it. We used guarded local test stages and
redacted evidence files, then restored the known-good proxy before analyzing
each result.

The current release is a portable, unsigned Windows 11 x64 build. It supports
Hysteria2 and VLESS over TCP/raw, gRPC, or WebSocket, plus IPv4 TUN and a local
mixed proxy. XHTTP is not supported yet.

Source and download:
https://github.com/seanzhang9999/V2RayN-TUN-Bridge

I would be interested in feedback on the failure model, Windows route handling,
and compatibility with other v2rayN 7.x installations.

## v2rayN issue or discussion reply

Use this only where the reported symptoms genuinely match. Do not paste it
across unrelated issues.

> I encountered a similar case where normal proxy mode worked but enabling TUN
> caused timeouts/DNS failures. In my case, the investigation focused on the
> proxy endpoint being captured by TUN, physical-interface binding, and DNS
> routing. I turned the workaround into a small open-source companion that reads
> the existing v2rayN profile and route and runs a separately managed Mihomo
> TUN:
> https://github.com/seanzhang9999/V2RayN-TUN-Bridge
>
> I maintain this project, so this is a disclosure rather than an official
> v2rayN recommendation. The current build targets Windows 11 x64 and supports
> Hysteria2 plus common VLESS transports. It may be useful as a comparison or
> workaround if the symptoms match. Please back up the v2rayN data directory and
> redact credentials before sharing diagnostics.

## GitHub repository discussion

Suggested title:

> Compatibility reports: which v2rayN profiles and Windows builds work?

Body:

Thanks for testing V2RayN TUN Bridge. To help expand compatibility without
collecting sensitive configuration, please report:

- Windows version
- v2rayN version and install type
- transport type only (for example Hysteria2 or VLESS/gRPC)
- whether TUN started
- whether a direct site and a proxied site worked
- whether behavior changed after switching Wi-Fi
- the exact non-sensitive error text

Never post subscription URLs, UUIDs, passwords, server addresses, SNI/Host
values, or an unredacted database/configuration file.

## Visual asset checklist

Prepare these before the first post:

1. One 16:9 screenshot of the main GUI with all destinations, process names,
   node names, IP addresses, and identifiers replaced by neutral examples.
2. One simple architecture diagram:
   `Apps -> TUN / 1081 -> Mihomo -> DIRECT or selected v2rayN profile`.
3. An optional 15–25 second screen recording: select a profile, start TUN,
   show diagnostic results, switch between the TUN and 1081 connection tabs,
   then stop cleanly.
4. A release card containing only the project name, one-line description,
   Windows 11 x64, open-source status, and GitHub repository path.

Do not show real node names, server domains, IP addresses, UUIDs, subscription
URLs, local usernames, or the full v2rayN installation path.

## Suggested publication order

1. Add the sanitized GUI screenshot to the README and release notes.
2. Publish the Reddit text post in `r/dumbclub`; answer comments the same day.
3. Publish the X thread with the screenshot or architecture diagram.
4. Add one transparent reply to a genuinely matching v2rayN issue/discussion.
5. Publish LinkedIn the next working day as the human–Codex collaboration
   story; place the repository link in the first comment.
6. After initial compatibility feedback, publish Show HN and remain available
   to discuss the implementation.
