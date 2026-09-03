# V2RayN TUN Bridge Public Release Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Publish a clean Windows application that reads v2rayN profiles and routing rules, runs an independent TUN, and shows which applications and connections use it.

**Architecture:** Ship a PyInstaller onedir application with a GUI/supervisor dual entry point. Bundle a pinned upstream core and geodata only in release artifacts, never in Git. The GUI reads the password-protected loopback controller and keeps traffic history in memory only.

**Tech Stack:** Python 3.11, Tkinter, PowerShell, Mihomo REST API, PyInstaller, GitHub Actions.

---

### Task 1: Create a clean production source tree

**Files:** `src/tun_bridge/`, `src/tun_controller/`, `src/tun_gui/`, root control scripts

1. Copy only the production Mihomo path and its direct dependencies.
2. Add a frozen-app resource resolver and a GUI/supervisor entry point.
3. Remove machine-specific v2rayN defaults and discover common install locations.
4. Test imports and offline profile parsing.

### Task 2: Add application-level TUN visibility

**Files:** `src/tun_gui/monitor.py`, `src/tun_gui/app.py`, `src/tun_controller/mihomo_builder.py`

1. Add failing tests for inbound classification and per-process aggregation.
2. Enable strict process discovery in the generated core configuration.
3. Return active application rows plus recent connection rows from the accumulator.
4. Render both views without persisting destinations or process history.
5. Run focused monitor and builder tests.

### Task 3: Make the portable application self-contained

**Files:** `V2RayN-TUN-Bridge.spec`, `packaging/fetch-runtime.ps1`, `.github/workflows/release.yml`

1. Add a dual-mode executable entry point.
2. Update the elevated control script to relaunch the packaged executable as supervisor.
3. Fetch a pinned upstream Windows core and geodata during builds.
4. Include third-party notices and licenses in the distribution.
5. Build an onedir ZIP and verify the executable starts without a Python command on PATH.

### Task 4: Create public-facing project documentation

**Files:** `README.md`, `README.zh-CN.md`, `SECURITY.md`, `CONTRIBUTING.md`, `LICENSE`, `THIRD_PARTY_NOTICES.md`

1. Explain the problem and one-minute setup above the fold.
2. Document supported protocols, privacy, administrator access, and limitations.
3. Explain upstream independence and trademark status.
4. Add build, test, security-reporting, and contribution instructions.

### Task 5: Verify and publish v0.1.0

1. Run all unit tests and PowerShell parser checks.
2. Scan tracked content for credentials, endpoints, local usernames, and machine paths.
3. Build the portable package locally and smoke-test its imports and config validation.
4. Commit and push `main`.
5. Tag `v0.1.0`, wait for GitHub Actions, and verify the downloadable ZIP.
6. Set repository description and discovery topics.

### Task 6: Prepare launch communication

**Files:** `docs/launch/launch-posts.md`

1. Write a technical LinkedIn story, a concise X thread, and a Telegram announcement.
2. List only relevant upstream discussions/issues where a technical reference is appropriate.
3. Do not post externally until the release artifact and documentation are verified.
