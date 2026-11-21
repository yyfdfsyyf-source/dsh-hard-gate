# dsh-hard-gate 效果测评与 DSH 0.2.2 兼容性报告

日期：2026-11-21
插件版本：0.2.0（本次由 0.1.0 升级）
目标 DSH 版本：0.2.2-rc.5（本机 D:/deepseek-h/resources/app.asar/dsh/package.json）

## 1. 结论摘要

- 核心闸门 API 在 DSH 0.2.2-rc.5 中仍然存在，插件可直接加载，钩子签名无需改动。
- 规则层 M1 扩充后：60 条代表性命令探针 60/60 符合预期；101 个测试 100 通过、1 跳过。
- 主要剩余风险是脚本间接执行、词法混淆、run_code 外层不审查、读取完整性默认 fail-open，以及 Auto 审查是模型层而非确定性层。

## 2. DSH 0.2.2-rc.5 兼容性验证

| 插件使用的能力 | DSH 0.2.2 实现位置 | 结论 |
| --- | --- | --- |
| ctx.on('tools/pre-execute', ..., { prepend: true }) | dsh-tools/lib/pipeline.js:386 ctx.waterfall(carrier, 'tools/pre-execute', exec, ...) | 兼容 |
| ctx.on('tools/result', ...) | dsh-tools/lib/pipeline.js:593-597 ctx.events.dispatch('emit', [..., 'tools/result', exec, result]) | 兼容 |
| ctx.tools.guard(fn) | dsh-tools/lib/index.js:649-661 guard(guard) / checkGuards(exec) | 兼容；guard 在 pre-execute 与审批之后执行 |
| ctx.workingDirectory.get(session) | dsh-working-directory/lib/index.js:98 get(session) | 兼容 |
| permissionPresets.registerAuto(admit) | dsh-permission-presets/lib/index.js:264 | 兼容 |
| approval.request(req) | dsh-user-approval/lib/index.js:153 | 兼容；never 策略会拒绝 ask |
| Config schema (schemastery) | schemastery 3.19.0 随 DSH 打包；本地链接插件的 createRequire(import.meta.url) 解析不到时 Config 退化为 undefined | 闸门不受影响，设置表单可能不显示（已知限制） |

审批流程细节：pipeline.js:387-402 中 ask 先经 serviceAsk 解析为 allow/deny，随后 `decision.kind === 'allow'` 时才调用 checkGuards。因此硬闸的 ask 会走人工审批，deny 直接生成错误结果。

## 3. 效果测评

### 3.1 测试结果

- node --test：101 tests，100 pass，1 skip，0 fail，约 0.5s。
- 60 条命令探针：60/60 达到预期 level/rule。
- 性能：10,000 次 classifyCommand 约 68-94ms。

### 3.2 规则覆盖

- Git 历史破坏：force push、force-with-lease、mirror/delete、checkout -f、restore、branch/tag 删除、update-ref -d、reflog expire、gc --prune=now、git -C 前缀。
- 工作区外写入：copy/move/cpi/mi/sc、sed -i、perl -pi、curl -o、wget -O、Invoke-WebRequest -OutFile、tar -C、7z -o、dd of=。
- 隐藏执行与持久化：powershell -enc、mshta、rundll32、regsvr32、wscript/cscript、schtasks、Register-ScheduledTask、New-Service、sc create、reg add、setx、wmic process call create。
- 服务/进程/全局安装：Stop-Service、taskkill /F、npm i -g、winget/choco/scoop/cargo/go/pip 全局或用户级安装。
- 凭据：secret-read、secret-exfil。
- 误报修复：dry-run、WhatIf、robocopy /L、可再生成目录。

### 3.3 剩余风险

1. 脚本间接执行：bash x.sh / python x.py / node x.js 内部的文件操作不可见。
2. 词法混淆：alias、Invoke-Expression、Base64、字符串拼接可能绕过；未知删除会降级为 ask。
3. run_code 外层不审查；内部 PTC 调用走同一闸门；直接 fs 操作依赖 PROGRAM_DANGER 正则。
4. unknownReadIsComplete: true 默认 fail-open，整文件覆盖仍有丢内容风险；严格场景建议设为 false。
5. Auto 审查是模型层第二道闸，失败关闭但不提供确定性保证。

## 4. 本次迭代

- 版本号 0.1.0 -> 0.2.0，标记规则层扩充完成。
- 新增本报告，明确 DSH 0.2.2-rc.5 兼容性边界。
- 复核 DSH 0.2.2-rc.5：五个闸门 API（pre-execute / result / guard / workingDirectory / permissionPresets / approval）与 schemastery 3.19.0、cordis 4.1.0 均未变化，插件继续兼容，无需改代码。
- 核心规则代码与 61 条矩阵测试已在 commit 5dcc10f 推送到 GitHub。

## 5. 后续建议

- 加审计 JSONL 以统计真实会话中 ask/deny 触发频率（此前该改动被拒绝，未实现）。
- 为脚本文件增加静态扫描（低优先级，复杂度高）。
- 在 profile 中显式设置 unknownReadIsComplete: false 以降低整文件覆盖风险。
- CI workflow 需要带 workflow scope 的凭据才能推送（GitHub OAuth App 限制）。
