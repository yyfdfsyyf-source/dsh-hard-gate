# dsh-hard-gate

[![CI](https://github.com/yyfdfsyyf-source/dsh-hard-gate/actions/workflows/ci.yml/badge.svg)](https://github.com/yyfdfsyyf-source/dsh-hard-gate/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://github.com/yyfdfsyyf-source/dsh-hard-gate/blob/main/LICENSE)

给 DeepSeek Harness 加一道**独立于系统 ACL 的最后闸门**：更严格的权限审查 + 一个在 `danger-full-access` 下依然生效的工作区沙箱。

它不替换内置沙箱，而是在内置沙箱之上补齐三个结构性缺口。

---

## 1. 为什么需要它

DSH 现有的安全模型是「**路径围栏 + 仅升级时审批**」，它有三个缺口，叠在一起就构成"大规模误杀"的完整路径：

| 缺口 | 后果 |
| --- | --- |
| 工作区内写入**零审批** | 核心没有 `tools/pre-execute` 策略监听（`dsh-tool-bash` 里还留着 TODO）；审批只在请求升级时触发 |
| `write` 是**整文件替换**，而授权依据是"版本新鲜度"而非"视图完整性" | 一次被 `2000 行 / 51200 字节` 截断的窗口读，就足以授权覆盖整个文件，中间没读到的内容直接丢失 |
| Windows ACL 沙箱在需要 `WRITE_OWNER` 的目录上失败 | 整体退回 `danger-full-access` + `never`，此时**没有任何路径限制** |
| 默认 10 路并行 + agent-team 共享检出 + 结果修剪 | 批次化的普通写操作被放大；`tool-result-pruner` 还会把 read 结果截成头尾，进一步降低模型对文件全貌的掌握 |

`dsh-hard-gate` 针对的正是「**很多次看起来都很正常的操作**」，而不是单次明显的恶意命令。

## 2. 它做什么

插件核心只注册三样东西，不注册服务；另外在宿主提供 LLM/权限服务时，附带一个可选的 Auto 审查集成：

| 挂载点 | 作用 |
| --- | --- |
| `tools/pre-execute`（`prepend: true`） | 在其它策略（含 LLM 审查器）之前给出 `deny` / `ask`，deny 不会被后续监听器翻案 |
| `tools/result` | 读取每个 `read` 结果的 `meta`（`offset` / `lines` / `totalLines`）并回退到页脚，按**区间并集**判断整个文件是否真的读到了 EOF |
| `ctx.tools.guard()` | 同步、只允许拒绝、**单调不可覆盖**的兜底：受保护路径与工作区包含关系在任何权限模式下都成立 |

> 为什么不用 `fs/write-intent`：该槽位是**单决策者**，已被 `dsh-fs-observation-policy` 占用（先注册者胜），第三方插件写进去不会生效。所以文件变更策略只能落在 `tools/pre-execute` + `tools.guard`。

## 3. 规则一览

### 3.1 文件工具（`write` / `edit` / `str_replace_editor`）

| 规则 id | 级别 | 触发条件 |
| --- | --- | --- |
| `protected-path` | **拒绝** | 目标落在受保护根、`.git/.hg/.svn` 段、或 `id_rsa` 等敏感文件名下（任何权限模式） |
| `outside-workspace` | **拒绝** | 目标在会话工作区之外（即使 `danger-full-access`；`extraRoots` / `allowPaths` 可放行） |
| `full-view-missing` | **拒绝** | `write` 要覆盖一个已存在且非空的文件，但本会话从没读过它 |
| `full-view-partial` | **拒绝** | `write` 要整文件覆盖，但会话读过的行**没有覆盖到文件末尾**：窗口读、字节截断，或者多次读之间留下空档（例如读了 1–200 又读 401–600） |
| `full-view-stale` | **拒绝** | 读完之后文件在磁盘上又变了（大小或 mtime 不同） |
| `large-full-rewrite` | **拒绝** | 整文件覆盖超过 `largeFileBytes`（默认 5 MiB）的文件 |
| `file-tool-escalation` | **拒绝** | 文件工具请求 `sandbox_permissions` 升级（写入被限制在工作区内，本就不需要升级） |
| `mutation-budget` | 先问后拒 | 10 分钟窗口内第 26 次变更起询问，第 61 次起拒绝；同一文件第 6 次写入起询问 |

`edit`（精确字面替换）**不受整文件规则约束**——它只改指定片段，不是误杀路径。

### 3.2 Shell（`pwsh` / `bash`）

**直接拒绝**

| 规则 id | 例子 |
| --- | --- |
| `catastrophic-target` | `Remove-Item -Recurse -Force C:\`、`rm -rf /`、`rm -rf ~`、`del /s /q D:\` |
| `outside-workspace-delete` | `Remove-Item -Recurse C:\Users\me\Documents`（明确目标在工作区外） |
| `outside-workspace-write` | `Move-Item a C:\Windows\x`、`echo x > C:\Windows\x` |
| `disk-destructive` | `format C:`、`diskpart`、`clear-disk`、`vssadmin delete shadows`、`bcdedit` |
| `security-tamper` | `icacls … /reset`、`sc delete`、`reg delete HKLM`、`Set-MpPreference`、`Set-ExecutionPolicy` |
| `git-clean-x` | `git clean -fdx`（连 `.env`、构建产物一起永久删除） |
| `power-state` | `shutdown`、`Restart-Computer`、`logoff` |
| `raw-device` | `dd if=`、`mkfs`、`fdisk`、`\\.\C:` |

**需要人工确认**

| 规则 id | 触发条件 |
| --- | --- |
| `recursive-delete` | 递归删除（`node_modules`/`dist`/`build`/`target`/`.cache` 等可再生成目录除外） |
| `wildcard-delete` | 带 `*` 的删除 |
| `pipeline-delete` | `Get-ChildItem … \| Remove-Item` —— 目标在管道里，闸门看不见 |
| `find-delete` | `find … -delete`、`find … -exec rm` —— 目标由谓词决定，闸门看不见 |
| `rsync-delete` | `rsync --delete` —— 会删除目标端多余文件 |
| `unverifiable-target` | 删除目标含无法静态展开的变量 |
| `git-clean` / `git-destructive` | `git clean -fd`、`git reset --hard`、`git checkout -- .`、`git push --force` |
| `mirror-copy` | `robocopy … /MIR`（会删除目标端多余文件） |
| `inline-code` | `node -e`、`python -c`、`cmd /c`、`-EncodedCommand` |
| `download-execute` | `iwr … \| iex`、`curl … \| sh` |
| `publish` / `archive-force` / `elevate` | `npm publish`、`Expand-Archive -Force`、`sudo` / `-Verb RunAs` |

普通读命令、`git status`、`npm test`、工作区内单文件删除、可再生成目录的递归删除都直接放行，只计入变更预算。

### 3.3 程序化工具（`run_code` / 任意带 `code` 参数的工具）

源码里出现 `rmSync`、`unlink`、`writeFile`、`child_process`、`execSync` 等直接文件系统/进程操作时询问——因为闸门看不到这些操作的**目标**。

### 3.4 自动模式（Auto）：无上下文模型审查

当 profile 里存在 `approval` / `llm` / `permissionPresets` / `sessions` 服务时，插件会注册 DSH 的 `auto` 权限预设，并用一个**只看见待执行动作**的审查器替换内置的上下文审查：

- 审查请求只包含：工具名、工具描述/参数 schema、参数、会话工作目录；**不包含**对话历史、用户消息、项目指令或之前的工具调用。
- 低风险（读、搜索、构建、测试、非破坏性 Git、工作区内单文件编辑）直接放行；中风险（删除、批量覆盖、移动、工作区外写入、force push、发布、外部发送、系统/权限修改等）一律拒绝并转人工确认；高风险（凭据外传、磁盘/安全控制破坏等）直接拒绝。
- `read` / `glob` / `grep` / `list` / `search` 等只读工具默认跳过模型调用（`reviewReadOnly: true` 可强制审查），以降低延迟和 token。
- 文件正文不会整段发给审查器：`write` 的 `content`、`edit` 的 `old_string`/`new_string` 等只发送有界预览（头 600 字符 + 尾 200 字符），因此大文件写入的审查请求仍然很小。
- 审查器默认复用当前会话的 provider/model；也可以指定一个更便宜/更快的专用模型：

  ```yaml
  - id: hard-gate
    config:
      reviewProvider: workbuddy-global
      reviewModel: deepseek-v4.1-flash
      reviewReasoningEffort: low
  ```

- 审查失败、超时、输出不是合法 JSON、或模型试图放行中/高风险动作时，一律**失败关闭**（拒绝），不会静默放行。
- Auto 仍然先经过硬闸：审查器返回 `allow` 后，`tools/pre-execute` 继续调用硬闸；硬闸的 `deny` / `ask` 永远优先。审查器只能增加摩擦，不能绕过硬闸。
- 插件卸载/重载时，仍处于 Auto 的会话会被切到 `workspace-write`，而不是静默保留 Full access。

> 内置的 `@deepseek-ai/dsh-experimental-auto-review` 也注册同一个 `auto` 预设；两者不能同时启用。安装本插件后，请从 profile 的 `dsh.profile.bundles` 中移除内置项，否则本插件会记录一条警告并让内置审查器继续工作。

### 3.5 还原点（改动前自动备份）

在真正执行前，闸门先把这次操作的目标打包成 zip：

| 操作 | 备份范围 |
| --- | --- |
| `write` 覆盖已存在文件 | 整个旧文件 |
| `edit` / `str_replace_editor` 修改 | 整个旧文件（`backupEdits: false` 可关） |
| Shell 删除 / 覆盖（`Remove-Item`、`rm`、`Set-Content`、重定向等） | 命令里能静态解析出的路径；目录递归打包 |

- 存放位置：`~/.dsh/hard-gate/backups/<日期>/<id>.zip`，附 `index.jsonl` 索引（操作、规则 id、会话、文件数、压缩前后大小）。
- Windows 上还会把压缩包**副本**异步送进系统回收站（`recycleBin: auto`），Explorer 里可直接还原；权威副本始终留在插件仓库，供命令行还原。
- 超过 `backupMaxBytes`（默认 64 MiB）或 `backupMaxFiles`（默认 2000）时不会静默跳过：转成一次明确询问（`backup-failed`），由你决定是否在没有还原点的情况下继续。`backupFailure: deny` 则直接拒绝。
- 可再生成目录（`node_modules`、`dist` 等）与 `.git/.hg/.svn` 不打包：它们要么可重建，要么由版本控制负责。
- 保留期默认 14 天、总量默认 512 MiB，超出后从最旧的开始清理。
- 仓库目录本身被加入受保护路径，agent 无法写入或删除它。

还原：

```powershell
cd D:\dev\dsh配置\plugins\dsh-hard-gate
node lib/restore.js list
node lib/restore.js restore last --dry-run
node lib/restore.js restore last --force
node lib/restore.js purge --days 7
```

`restore` 默认拒绝覆盖现有文件（`--force` 才覆盖），并且只还原清单里记录在工作区根内的路径。

> Shell 备份是**尽力而为**：路径解析仍是词法级，`find -delete`、管道删除、`node -e` 这类"目标在命令内部"的操作没有可打包的显式路径，仍只靠询问拦截；`git clean` / `git reset --hard` 见下一条。文件工具的备份是精确的。
>
> `git clean` / `git reset --hard` / `git checkout -- .` 这类"目标在 Git 索引里"的操作，无法从命令行枚举目标，会退化为**整个会话工作区**的快照（同样受 `backupMaxBytes` / `backupMaxFiles` 限制）；超大工作区会转为询问。

## 4. 配置

安装后的默认值已经偏向"更严格但仍可用"。所有键都可以在 profile 的 `cordis.patch.yml` 里覆盖：

```yaml
- id: hard-gate
  config:
    extraRoots: ['D:\dev\shared-lib']
    shellOutsideWorkspace: ask
    maxMutationsPerWindow: 40
```

> 覆盖是**整对象替换**：patch 中命中同一 `id` 会替换完整 `config`，需要保留的键请一并写出。

| 键 | 默认 | 说明 |
| --- | --- | --- |
| `enforceWorkspaceOnly` | `true` | 文件工具不得写出工作区（Full access 下同样生效） |
| `extraRoots` | `[]` | 额外可写根，支持 `~` |
| `allowPaths` | `[]` | 豁免"工作区包含"检查的根；**不能**豁免受保护路径 |
| `protectedPaths` | 平台默认 | 追加受保护根 |
| `replaceProtectedPaths` | `false` | 置 `true` 则用 `protectedPaths` 完全替换平台默认 |
| `protectedNames` | `['.git','.hg','.svn']` | 任何层级出现即拒绝 |
| `protectedBasenames` | `['id_rsa','id_ed25519','.netrc','.npmrc','.pypirc','.git-credentials']` | 敏感文件名 |
| `requireFullRead` | `true` | 整文件覆盖前必须读到 EOF |
| `allowPartialOverwrite` | `[]` | 正则源码；命中的路径跳过整文件规则 |
| `denyLargeFullRewrite` / `largeFileBytes` | `true` / `5 MiB` | 大文件禁止整文件覆盖 |
| `unknownReadIsComplete` | `true` | read 结果既没有可识别的 `meta`、也没有可识别的页脚时，按"已读完"处理（失败开放，避免死锁） |
| `shellOutsideWorkspace` | `deny` | 也可设为 `ask` |
| `regenerable` | `['node_modules','dist','build','out','target','obj','coverage','.cache','.next','.nuxt','.turbo','.output','tmp']` | 可无询问递归删除的目录名 |
| `maxMutationsPerWindow` / `hardMutationCap` | `25` / `60` | 软/硬预算；`0` 关闭 |
| `windowMs` | `600000` | 预算窗口 |
| `maxWritesPerFile` | `5` | 单文件每窗口写入次数，超过询问 |
| `requireEscalationJustification` | `true` | 升级必须带 ≥12 字符的具体理由 |
| `allowFileToolEscalation` | `false` | 是否允许文件工具请求升级 |
| `askOnProgramMutation` | `true` | 程序化工具直接改文件系统时询问 |
| `autoReview` | `true` | 注册 Auto 预设并使用无上下文审查器 |
| `reviewProvider` / `reviewModel` | `''` / `''` | 专用审查模型；必须成对设置，留空复用会话路由 |
| `reviewReasoningEffort` | `low` | 审查器 reasoning effort；留空用模型默认 |
| `reviewReadOnly` | `false` | 是否也审查只读工具 |
| `reviewTimeoutMs` | `30000` | 审查超时；超时失败关闭，`0` 关闭 |
| `backupEnabled` | `true` | 改动前自动打还原点 |
| `backupDir` | `~/.dsh/hard-gate/backups` | 还原点仓库（不要放进工作区） |
| `backupMaxBytes` / `backupMaxFiles` | `64 MiB` / `2000` | 单次还原点上限，超过转为询问 |
| `backupRetentionDays` / `backupMaxTotalBytes` | `14` / `512 MiB` | 保留期与仓库总量 |
| `backupFailure` | `ask` | 备份失败时：`ask` / `deny` / `allow` |
| `backupEdits` | `true` | `edit` 是否也备份 |
| `recycleBin` | `auto` | `auto`（仅 Windows）/ `always` / `never` |
| `recycleBinMaxBytes` | `16 MiB` | 送入回收站的压缩包上限；`0` 关闭 |
| `mutationTools` | `{write:'file_path', edit:'file_path', str_replace_editor:'path'}` | 追加"工具名 → 路径参数名"映射 |

平台默认受保护根（运行期计算）：`~/.ssh`、`~/.dsh`、`~/.aws`、`~/.azure`、`~/.gnupg`、`~/.kube`、`~/.config/gh`、`~/AppData`、`%WINDIR%`、`%ProgramFiles%`、`%ProgramFiles(x86)%`、`%ProgramData%`、各盘 `System Volume Information` 与 `$Recycle.Bin`（POSIX 下为 `/etc`、`/usr`、`/bin`、`/sbin`、`/boot`、`/dev`、`/proc`、`/sys`、`/var/lib`）。

平台临时目录（`os.tmpdir()`）是唯一例外：DSH 的 `workspace-write` 本来就允许写临时目录，所以只豁免"根"规则，`.git` 与敏感文件名仍然生效。

## 5. 安装

从 GitHub 公开源安装：

```
plugin_manager
  action: install_bundle
  target: github:yyfdfsyyf-source/dsh-hard-gate
```

或直接用官方 CLI：

```powershell
dsh plugin --profile desktop add github:yyfdfsyyf-source/dsh-hard-gate
```

然后读返回值：`application: applied` 才算生效，`warnings` 非空要逐条看。新增行可以用 `cordis_inspect_query` 确认（不需要审批）。

本机源码开发（链接检出）时，把 target 换成绝对目录即可：

```powershell
dsh plugin --profile desktop add D:\dev\dsh配置\plugins\dsh-hard-gate
```

- 首次安装新 bundle 可以走 HMR 生效；**替换**已安装的同名包需要重启 DSH 才会加载新的 JS。
- GitHub 源码安装不会触发 `allowBuilds`：本插件没有任何依赖和构建脚本，`node_modules` 也不需要。
- 本地目录是"链接检出"安装，`@deepseek-ai/schemastery` 可能解析不到，此时 `Config` 不导出、**设置面板里没有表单**，但闸门照常工作，配置仍然通过 patch 生效。把包装进 profile 的 `node_modules`（而不是链接）即可恢复表单。
- 不要手写 profile 的 `package.json` / `cordis.patch.yml`，也不要手动跑 pnpm；`install_bundle` 会维护这些状态。
- **启用无上下文 Auto 审查时**，检查 profile 的 `dsh.profile.bundles`，确保没有 `@deepseek-ai/dsh-experimental-auto-review`；否则内置审查器会先占用 `auto` 预设，本插件只记录一条警告并退回内置行为。内置包在 app.asar 里，不需要卸载依赖，只需从 bundles 数组移除。用插件管理器安装或更新其他插件后要复查这一条：管理器会重写 profile 的 `package.json`，可能把内置 bundle 加回来。

### 装完这样验证

1. 让 agent 执行 `Remove-Item -Recurse -Force C:\Windows\Temp\hard-gate-test` → 应返回 `hard-gate [outside-workspace-delete]` 拒绝。
2. 对一个 500 行的文件 `read` 时加 `limit: 50`，再对它 `write` → 应返回 `hard-gate [full-view-partial]`。
3. 执行 `Remove-Item -Recurse -Force node_modules` → 应直接放行（可再生成目录）。
4. 执行 `git clean -fdx` → 应被拒绝。
5. 打开设置 → 插件列表，确认标题「硬闸 / Hard Gate」与图标正常显示。
6. 切换到 Auto 预设，执行 `Remove-Item -Recurse -Force .\tmp-test` → 硬闸会拦截并生成还原点；因为硬闸的 ask 优先，UI 上通常显示 `hard-gate: recursive-delete`。执行 `Get-ChildItem` → 应直接放行（只读命令不送审）。要单独验证无上下文审查器，用 `web_fetch` 请求 `https://example.com/?token=sk-test-secret` → 应显示「硬闸自动审查拒绝了此调用」。

## 6. 已知限制（重要）

- **不是内核沙箱。** 闸门检查的是"命令字符串"和"文件工具参数"。`node build.js`、`python script.py`、`cargo run` 这类命令内部删了什么，闸门看不到——那部分只能靠 OS 沙箱。本插件补的是沙箱退化到 `danger-full-access` 之后的缺口，**不替代沙箱**。
- **PowerShell 解析是词法级的**，不是真正的语法树。别名、`Invoke-Expression`、Base64、拼接变量都可能隐藏真实目标；因此"无法静态解析的删除"一律**询问**而不是放行，但无法保证 100% 覆盖。
- `write` 的整文件规则依赖 `read` 结果附带的 `meta`（`offset` / `lines` / `totalLines`），并回退到页脚文本。若 DSH 改了这两处的形状，`unknownReadIsComplete`（默认 `true`）决定退化为"视为读完"还是"要求重读"。
- 闸门只判断"是否读到 EOF"，不判断单行内容是否完整：`read` 会把超长单行截到 2000 字符，这类文件的"完整视图"仍可能缺行内内容。超长行文件请用 `edit`，不要整文件 `write`。
- 受保护路径是**绝对规则**：如果工作区本身位于受保护根内（临时目录除外），文件工具将无法写入该工作区。请用 `extraRoots` / `replaceProtectedPaths` 调整。
- `enforceWorkspaceOnly` 会拦住"合理地改工作区外文件"的场景，这是有意的默认值；需要时用 `extraRoots` 放行具体目录，而不是整条关掉。
- 变更预算是**按会话**统计；不同 session 各自计数。agent-team 的并发子代理若共享同一会话会被合并计数，否则各自计数。
- `tools.guard` 兜底使用**词法路径**（同步、无 I/O）。符号链接指向工作区外时由 `pre-execute` 的 realpath 检查负责；两层同时失效的概率很低，但不是零。
- Auto 审查器是**第二层判断**，不是沙箱；它只看见单个动作，无法知道用户是否授权了某个中风险操作，所以中风险一律转人工。它也不能替代硬闸的路径/备份规则。
- 内置 Auto 审查器会看过滤后的对话历史；本插件的审查器刻意不看。两者只能启用一个。
- `run_code` 外层不送审，内层 PTC 调用逐个送审；`run_code` 里直接 `fs.rm` 这类操作由硬闸的 `program-fs-mutation` 询问兜底。
- 首次 `install_bundle` 与任何 `plugin_manager` 调用本身可能触发审批，这是 DSH 的行为，与本插件无关。

## 7. 开发

```powershell
cd D:\dev\dsh配置\plugins\dsh-hard-gate
node --test
```

- 无 schemastery 时：99 通过、1 跳过（`Config` 相关）。
- 验证 schema：

```powershell
$env:HARD_GATE_NODE_MODULES = "C:\Users\YYF\.dsh\profiles\desktop\node_modules"
node --test
```

目录结构：

```
lib/paths.js          路径身份（大小写折叠、扩展前缀、realpath 祖先、受保护匹配）
lib/commands.js       Shell 命令分类（规则表 + 操作数提取）
lib/read-tracker.js   read 覆盖区间（meta + 页脚回退、区间合并、缺口计算）
lib/state.js          按会话的变更预算
lib/gate.js           三道挂载点的决策逻辑（纯逻辑，可在无 DSH 环境下测试）
lib/auto-review.js    无上下文 Auto 审查（可选，ctx.inject 激活）
lib/backup.js         还原点仓库、zip 打包、回收站副本、还原
lib/zip.js            无依赖 ZIP 写入/读取 + CRC32
lib/restore.js        还原点命令行（list / restore / purge）
lib/index.js          Cordis 插件入口（Config schema + apply）
test/                 100 个用例，覆盖规则表、路径边界、预算、覆盖区间、备份/还原与挂载
```

设计原则：**可解释的拒绝**。每条拒绝都带稳定规则 id 和一句"下一步该怎么做"，让模型能自行纠正，而不是反复重试同一条命令。
