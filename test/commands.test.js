import test from 'node:test'
import assert from 'node:assert/strict'
import { classifyCommand } from '../lib/commands.js'

const workspace = 'D:\\work\\project'
const base = {
  cwd: workspace,
  workspaceRoots: [workspace],
  regenerable: new Set(['node_modules', 'dist', 'build', '.cache']),
}

const levelOf = (command, options = {}) => classifyCommand(command, { ...base, ...options }).level
const ruleOf = (command, options = {}) => classifyCommand(command, { ...base, ...options }).rule

test('empty command is allowed', () => {
  assert.equal(levelOf('   '), 'allow')
  assert.equal(ruleOf('   '), 'empty')
})

test('ordinary commands are allowed and reads are never blocked', () => {
  assert.equal(levelOf('npm test'), 'allow')
  assert.equal(levelOf('git status'), 'allow')
  assert.equal(levelOf('Get-ChildItem C:\\'), 'allow', 'reading outside the workspace is not a mutation')
  assert.equal(levelOf('rg TODO src'), 'allow')
  assert.equal(levelOf('Remove-Item foo.txt'), 'allow')
})

test('refuses drive roots, filesystem roots, and the home directory', () => {
  assert.equal(levelOf('Remove-Item -Recurse -Force C:\\'), 'deny')
  assert.equal(ruleOf('Remove-Item -Recurse -Force C:\\'), 'catastrophic-target')
  assert.equal(levelOf('rm -rf /'), 'deny')
  assert.equal(levelOf('rm -rf ~'), 'deny')
  assert.equal(levelOf('del /s /q D:\\'), 'deny')
})

test('refuses disk, security-control, and power-state commands', () => {
  assert.equal(ruleOf('format C: /q'), 'disk-destructive')
  assert.equal(ruleOf('echo x; format C: /q'), 'disk-destructive', 'a later command still counts')
  assert.equal(levelOf('git commit -m "docs: format c: drive"'), 'allow', 'prose is not a disk format')
  assert.equal(ruleOf('diskpart /s script.txt'), 'disk-destructive')
  assert.equal(ruleOf('icacls C:\\work /reset'), 'security-tamper')
  assert.equal(ruleOf('sc delete SomeService'), 'security-tamper')
  assert.equal(ruleOf('shutdown /s /t 0'), 'power-state')
  assert.equal(ruleOf('mkfs.ext4 /dev/sda1'), 'raw-device')
})

test('git clean: dry run is fine, -x is not', () => {
  assert.equal(levelOf('git clean -ndx'), 'allow')
  assert.equal(ruleOf('git clean -fdx'), 'git-clean-x')
  assert.equal(ruleOf('git clean -fd'), 'git-clean')
  assert.equal(levelOf('git clean -fd'), 'ask')
})

test('git -C and global options do not hide clean or destructive subcommands', () => {
  assert.equal(ruleOf('git -C C:\\repo clean -fdx'), 'git-clean-x')
  assert.equal(ruleOf('git -C "C:\\repo with spaces" clean -fdx'), 'git-clean-x')
  assert.equal(levelOf('git -C C:\\repo clean -ndx'), 'allow')
  assert.equal(ruleOf('git -C C:\\repo clean -fd'), 'git-clean')
  assert.equal(ruleOf('git --git-dir=C:\\repo\\.git clean -fdx'), 'git-clean-x')
  assert.equal(ruleOf('git --no-pager -C C:\\repo clean -fdx'), 'git-clean-x')
  assert.equal(ruleOf('git -C C:\\repo -c core.x=y clean -fdx'), 'git-clean-x')
  assert.equal(ruleOf('git -C C:\\repo reset --hard'), 'git-destructive')
  assert.equal(ruleOf('git -C C:\\repo restore .'), 'git-destructive')
  assert.equal(levelOf('git -C C:\\repo status'), 'allow')
  assert.equal(levelOf('git commit -m "clean -fdx"'), 'allow', 'a message is not a clean invocation')
})

test('find -delete, rsync --delete, and predicate deletes ask', () => {
  assert.equal(levelOf('find . -delete'), 'ask')
  assert.equal(ruleOf('find . -name "*.log" -delete'), 'find-delete')
  assert.equal(ruleOf('find / -delete'), 'catastrophic-target', 'a root predicate is still refused')
  assert.equal(ruleOf('find . -type f -exec rm {} +'), 'find-delete')
  assert.equal(levelOf('find . -name "*.ts"'), 'allow', 'a pure search is allowed')
  assert.equal(levelOf('rsync -a --delete src/ dist/'), 'ask')
  assert.equal(ruleOf('rsync -a --delete src/ dist/'), 'rsync-delete')
  assert.equal(ruleOf('rsync -a --delete src/ C:\\outside'), 'outside-workspace-delete')
  assert.equal(levelOf('rsync -a src/ dist/'), 'allow')
})

test('unlink and truncate are writes, not invisible commands', () => {
  assert.equal(ruleOf('unlink C:\\outside\\a.txt'), 'outside-workspace-delete')
  assert.equal(ruleOf('truncate -s 0 C:\\outside\\a.txt'), 'outside-workspace-write')
  assert.equal(ruleOf('truncate -s 0 notes.txt'), 'local-write')
})

test('deletes outside the workspace are refused', () => {
  const result = classifyCommand('Remove-Item -Recurse -Force C:\\Users\\me\\Documents', base)
  assert.equal(result.level, 'deny')
  assert.equal(result.rule, 'outside-workspace-delete')
  assert.match(result.reason, /C:\\Users\\me\\Documents/)
})

test('moves and redirects outside the workspace are refused', () => {
  assert.equal(ruleOf('Move-Item C:\\temp\\a.txt C:\\temp\\b.txt'), 'outside-workspace-write')
  assert.equal(ruleOf('Set-Content -Path out.txt -Value hi'), 'local-write')
  assert.equal(ruleOf('echo hi > C:\\Windows\\x.txt'), 'outside-workspace-write')
})

test('recursive and wildcard deletes ask, but regenerable targets do not', () => {
  assert.equal(ruleOf('Remove-Item -Recurse -Force src'), 'recursive-delete')
  assert.equal(levelOf('Remove-Item -Recurse -Force src'), 'ask')
  assert.equal(ruleOf('del /s /q *'), 'wildcard-delete')
  assert.equal(levelOf('Remove-Item -Recurse -Force node_modules'), 'allow')
  assert.equal(ruleOf('Remove-Item -Recurse -Force node_modules'), 'local-delete')
  assert.equal(levelOf('Remove-Item -Recurse -Force frontend\\node_modules'), 'allow')
})

test('pipeline deletes ask because the targets are invisible', () => {
  assert.equal(ruleOf('Get-ChildItem -Recurse | Remove-Item -Force'), 'pipeline-delete')
})

test('unresolvable delete targets ask instead of being dropped', () => {
  assert.equal(ruleOf('Remove-Item -Recurse -Force $someVariable'), 'unverifiable-target')
  assert.equal(levelOf('Remove-Item -Recurse -Force $env:TEMP\\x'), 'deny')
  assert.equal(levelOf('Remove-Item -Recurse -Force $env:TEMP\\x', { outsidePolicy: 'ask' }), 'ask')
})

test('history, mirror, inline code, publish, and elevation ask', () => {
  assert.equal(ruleOf('git reset --hard HEAD~3'), 'git-destructive')
  assert.equal(ruleOf('robocopy C:\\a C:\\b /MIR'), 'mirror-copy')
  assert.equal(ruleOf('node -e "require(\'fs\').rmSync(\'x\')"'), 'inline-code')
  assert.equal(ruleOf('npm publish'), 'publish')
  assert.equal(ruleOf('Expand-Archive -Path a.zip -DestinationPath . -Force'), 'archive-force')
  assert.equal(ruleOf('sudo apt install x'), 'elevate')
})

test('a merely mentioned destructive word is never a deny', () => {
  const result = classifyCommand('rg "Remove-Item -Recurse" docs/', base)
  assert.notEqual(result.level, 'deny', 'prose in a quoted pattern must not be treated as a destructive command')
})
