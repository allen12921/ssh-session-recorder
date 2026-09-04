# ssh-session-recorder

强制录制 SSH 登录会话（终端输入输出全量记录），面向"多人共用同一个系统账号登录"的场景，目标是即使连接异常断开（网络中断、被 kill、终端直接关闭）也不丢数据，且登录者本人无法删除/篡改自己的录制记录。

## 背景

最初评估过用 [tlog](https://github.com/Scribery/tlog)（Red Hat 出品的专门录制会话的工具）做这件事，SUID/SGID 到专属系统账号的权限模型做得很完善，但经过源码走读（`lib/tlog/rec.c` 的缓冲/刷新状态机）和实测复现，确认 tlog 14 在**真正交互式登录会话**（不带远程命令的裸 `ssh user@host`）下，无论是默认的定时刷新（`latency`）还是把 `payload` 阈值调到很小，都无法可靠地把数据落盘——异常断连时会话内容会直接丢失，只有正常执行 `exit` 才能保证完整。这是已知的上游缺陷（[Scribery/tlog#378](https://github.com/Scribery/tlog/issues/378) 报告的是同一个状态机在同版本上的另一种卡死症状，根源同源）。

这个仓库是对比测试后选定的方案：基于 Linux 自带的 `script`（util-linux）命令，架构简单很多，`-f` 参数保证每次读写立刻落盘，没有 tlog 那种容易出问题的复杂缓冲状态机。经过实测：真实交互输入 + 会话不退出 + 本地客户端异常 `kill -9` 模拟断连，数据依然完整保留。

## 架构

```
sshd 接受连接（走 authorized_keys 里某个人的 key）
  → 该 key 的 environment="REMOTEUSER=<真实姓名>" 生效（需要 sshd 开 PermitUserEnvironment）
  → 以共享账号（如 ubuntu）的身份 exec 登录 shell = bin/session-shell
      → sudo -u root bin/create_session_log.sh "$REMOTEUSER"   （走窄权限 sudoers 规则）
          → 在受限目录下创建本次会话专属的 .log / .log.timing / .log.stderr 三个文件
          → chown 给登录者本人、chmod 600
          → 只对 .log 主文件 chattr +a（只能追加，不能截断/覆写/删除，root 也不行除非先手动摘掉属性）
      → 有真实终端（交互登录，或 `ssh -tt host "cmd"`）：
            exec script -f -a -q -e --timing=<timing文件> <log文件>
            （每次读写立刻 flush；-e 保证退出码正确透传；-c 模式下把远程命令透传给 script -c）
      → 没有真实终端（`ssh host "cmd"` 这种自动化场景，最常见）：
            不用 script（它会强制分配伪终端，把 stdout/stderr 合并、破坏二进制/换行），
            改用 tee 分别记录两路输出到 .log / .log.stderr，同时通过 PIPESTATUS 保留真实退出码
      → 例外：如果这个 -c 命令其实是 sshd 转发过来的 sftp 子系统请求（scp/sftp
            客户端），直接原样 exec，完全不经过上面任何录制逻辑——sftp 协议需要
            裸的双向二进制通道，套进 tee/script 会直接破坏协议
```

### 权限设计要点

- 日志目录（`/opt/audit/log`）：`root:root`，权限 `0701`（owner 全权限，other 只有执行位）——登录者能凭已知文件名进去读写自己的文件，但看不到目录列表，建不了新文件，删不掉任何文件（unlink 需要目录写权限）。
- 日志文件本身：`chown` 给登录者、`chmod 600`（**不需要专门设置 group**——大家共用同一个账号登录，group 归属不能区分不同的人，纯粹是历史包袱，已经去掉了）。
- 主日志文件（`.log`）：`chattr +a`，登录者和 root 都无法截断/覆写已有内容；实测发现连 `rm` 都会被拦（"Operation not permitted"），比 man page 里写的"只挡覆写不挡删除"还严格——必须先 `chattr -a` 才能删。
- `.timing` / `.stderr` 这两个附属文件：**不能** `chattr +a`——`script` 自身实现（`script.c`）里 timing 文件不管有没有传 `-a` 都是 `O_TRUNC` 打开，加了 append-only 会直接报错导致 `script` 启动失败；`.stderr` 是我们自己用 `tee -a` 写的，理论上可以加 `+a`，但为了跟 timing 文件行为一致、避免以后改实现时又踩同样的坑，也没加。这两个文件的防篡改完全依赖目录权限（登录者拿不到目录写权限，删不掉、改不了名）。
- `sudoers.d/audit-session-log`：`ubuntu ALL=(root) NOPASSWD: /opt/audit/bin/create_session_log.sh` —— 登录者能且只能以 root 身份跑这一个脚本，不能干别的。
- `create_session_log.sh` 用 `$SUDO_USER`（sudo 自动设置、不可信外部输入的字段）判断真实登录账号，不信任任何来自调用方的伪造。
- 三个文件（`.log`/`.log.timing`/`.log.stderr`）在创建时就**一次性全部建好**，不管这次会话最终会不会用到某一个——因为登录者对目录本身没有写权限，没法在会话过程中临时"补建"一个新文件，必须提前把所有可能用到的文件都准备好。

### ⚠️ 关于 `authorized_keys` 加固：走过的弯路

第一版实现里，为了让 `REMOTEUSER` 标注不可伪造，把 `AuthorizedKeysFile` 这个**全局** sshd 配置改成了 `/etc/ssh/authorized_keys/%u`（按用户名分文件），结果只顾着建了 `ubuntu` 一个账号的新文件，**把服务器上其他所有账号（包括正在用来做运维操作的 `ec2-user`）的 SSH 访问全部锁死了**——因为 `%u` 对每个账号都要求有对应的新文件，没建的账号直接找不到 key，认证失败到触发 `MaxAuthTries`。

**正确、影响面小得多的做法**：不要碰 `AuthorizedKeysFile` 这种全局配置，直接原地把目标账号自己的 `~/.ssh/authorized_keys` **改属主**：

```bash
sudo chown root:root /home/ubuntu/.ssh/authorized_keys
sudo chmod 0644 /home/ubuntu/.ssh/authorized_keys
sudo chattr +i /home/ubuntu/.ssh/authorized_keys   # 见下面的说明，+a 不够
```

已验证：sshd 读取 `authorized_keys` 时会先把有效身份切到登录账号本身的 uid 再去读文件，**文件属主是谁不影响读取**，只要登录账号对文件有读权限（644 足够）。这个改动只影响这一个文件，不会波及服务器上任何其他账号。

**`chattr +a` 不够，要用 `chattr +i`**：`+a`（只能追加）只挡"编辑内容"，挡不住"删除文件"——因为 `rm` 检查的是**目录**的写权限，而 `~/.ssh` 目录本身还是登录者自己拥有、可写的（正常 SSH 场景就得这样，比如要能自己维护 `known_hosts`）。所以哪怕文件属主是 root、内容加了 `+a`，登录者依然能直接把整个文件 `rm` 掉再自己建一个新的、内容随意的假文件。`chattr +i`（immutable）连删除/改名都会挡住（哪怕 root 不先摘掉这个属性也删不掉），这才是需要的强度。

同样的道理也适用于 `~/.ssh/environment`（`PermitUserEnvironment` 打开后这个文件也会被处理，如果不管，登录者可以在这里注入任意环境变量，包括老版本 OpenSSH 上可能被用来做 `LD_PRELOAD` 劫持）：预先建一个属主 root、内容为空、`chattr +i` 的占位文件，登录者就没法再自己创建/覆盖它了。

## 部署步骤

用 `install.sh` 一步到位（幂等，可以放心重复执行）：

```bash
sudo ./install.sh ubuntu
```

它会依次做：建 `/opt/audit/bin`/`/opt/audit/log` 目录、装两个脚本、生成并校验 `sudoers.d/audit-session-log-<账号>`（sudoers 规则**固定绑定这一个账号**，不用用户组——多个共享账号就对每个账号各跑一次 `install.sh`，会各自生成一份独立的 sudoers 文件，互不影响）、注册 `/etc/shells`、原地加固该账号的 `authorized_keys`/`~/.ssh/environment`（`chown root + chattr +i`）、最后把登录 shell 切过去。**只会改动传给它的这一个账号**，跑完立刻用另一个终端窗口验证一下其他账号还能不能正常登录，别把自己锁在外面。

`PermitUserEnvironment yes`（用于 REMOTEUSER 标注，见下一节）不在脚本自动化范围内，因为这是全局 sshd 配置，改错了影响所有账号——手动改、手动 `sshd -t` 校验、手动 reload，务必谨慎。

<details>
<summary>不想用脚本、想自己一步步来，可以照着展开的手动步骤做</summary>

1. 建目录：
   ```bash
   sudo mkdir -p /opt/audit/bin /opt/audit/log
   sudo chown root:root /opt/audit/log
   sudo chmod 0701 /opt/audit/log
   ```
2. 部署脚本：
   ```bash
   sudo install -m 0755 -o root -g root bin/create_session_log.sh /opt/audit/bin/create_session_log.sh
   sudo install -m 0755 -o root -g root bin/session-shell        /opt/audit/bin/session-shell
   ```
3. 装 sudoers 规则（把 `ubuntu` 换成目标账号）：
   ```bash
   sed "s/^ubuntu /目标账号 /" sudoers.d/audit-session-log | sudo tee /etc/sudoers.d/audit-session-log-目标账号 > /dev/null
   sudo chmod 0440 /etc/sudoers.d/audit-session-log-目标账号
   sudo visudo -cf /etc/sudoers.d/audit-session-log-目标账号   # 校验语法
   ```
4. 注册为合法登录 shell（非强制，纯防御性；如果这台机器 PAM 没配 `pam_shells`，不加也能正常登录，先用 `grep -rn pam_shells /etc/pam.d/` 确认）：
   ```bash
   echo "/opt/audit/bin/session-shell" | sudo tee -a /etc/shells
   ```
5. 加固目标账号的 `authorized_keys` 和 `~/.ssh/environment`（见上面"走过的弯路"一节，直接原地 `chown`+`chattr +i`，不要碰 `AuthorizedKeysFile`）。
6. 把目标共享账号的登录 shell 改成这个包装脚本（**只改这一个账号**，改完立刻用另一个终端窗口验证一遍其他账号是否还能正常登录，别把自己锁在外面）：
   ```bash
   sudo usermod -s /opt/audit/bin/session-shell ubuntu
   ```

</details>

（可选，强烈建议）按 key 标注登录者身份——见下一节。

## 按 SSH key 标注登录者身份（REMOTEUSER）

多人共用一个账号登录时，日志文件名里默认只有账号名，看不出是谁登的。做法是给每个人的 SSH 公钥在 `authorized_keys` 里单独一行加 `environment=`：

```
environment="REMOTEUSER=zhangsan" ssh-ed25519 AAAA... zhangsan@example.com
environment="REMOTEUSER=lisi" ssh-rsa AAAA... lisi@example.com
```

这需要 sshd 开启 `PermitUserEnvironment`：

```
PermitUserEnvironment yes
```

> 新版本 OpenSSH 支持按变量名限定的白名单写法，比如 `PermitUserEnvironment REMOTEUSER`，只放行这一个变量名，能显著收窄官方文档提到的"可能被用 `LD_PRELOAD` 之类手段绕过访问限制"的风险面。本仓库部署时实测的 OpenSSH 7.4p1 **不支持**这种白名单写法（`sshd -t` 报 `Bad yes/no argument`），只能用裸 `yes`。改之前务必用 `sshd -t -f <配置文件副本>` 针对当前实际安装的版本验证一遍语法，不要直接照抄官方最新文档的写法就上生产。

**安全性已验证**：
- 客户端没法通过 `ssh -o SetEnv=REMOTEUSER=xxx` 或 `ssh -o SendEnv=REMOTEUSER`（配合本地环境变量）伪造这个值——只要服务端 `AcceptEnv` 没有显式放行 `REMOTEUSER`（默认只放行 `LANG`/`LC_*` 等语言区域变量），服务端就会完全忽略客户端传来的值。
- **但光靠 `AcceptEnv` 挡客户端不够**：`authorized_keys` 本身默认是登录账号自己拥有、可写的（这是 SSH 的默认行为），任何登录进来的人都能直接编辑自己的 `authorized_keys` 改标注、甚至冒充别人。必须按上面"走过的弯路"一节把这个文件（连同 `~/.ssh/environment`）改成 root 属主 + `chattr +i`，这个标注机制才是真正可信的。

没配 `environment=` 的 key 登录时，`REMOTEUSER` 为空，文件名会退化标注成 `unknown`。

## 查看 / 回放日志

```bash
# 交互式会话（有 .log.timing）：直接看内容
sudo cat /opt/audit/log/<账号>-<REMOTEUSER标签>-<时间戳>-<PID>.log

# 按真实时间节奏回放（像放录像一样）
sudo scriptreplay -t /opt/audit/log/<同上>.log.timing -s /opt/audit/log/<同上>.log

# 非交互命令模式（ssh host "cmd"）：stdout 在 .log，stderr 在 .log.stderr，没有 timing
sudo cat /opt/audit/log/<同上>.log          # 命令的 stdout
sudo cat /opt/audit/log/<同上>.log.stderr   # 命令的 stderr
```

## 已测试通过的场景

- 非交互命令模式（`ssh host "cmd"`）：独立文件，stdout/stderr 正确分离，退出码正确透传（用 `ssh host "exit 42"` 验证过客户端确实收到 42）
- `ssh -tt host "cmd"`（带伪终端的命令模式）：走 `script -c`，退出码同样正确透传
- 交互式登录（`ssh -tt`）：独立文件，内容完整
- 会话不退出、真实敲键盘、中途查看：数据已经落盘（`-f` 近实时 flush，不是 tlog 那种定时/阈值触发式的批量刷新）
- 模拟异常断连（本地 SSH 客户端 `kill -9`）：断连前的数据完好无损
- 登录者尝试截断/覆写/删除自己的日志：均被 `chattr +a`（主日志）+ 目录权限（附属文件）拦住
- 登录者尝试编辑/删除 `authorized_keys` 冒充别人：被 `chattr +i` 拦住（连 `rm` 都不行）
- 多次登录：文件名带时间戳 + PID，不会互相覆盖
- 客户端伪造 `REMOTEUSER`：被服务端 `AcceptEnv` 白名单机制挡住，完全不生效
- SFTP/SCP：上传下载双向都验证过，跟没套这层 shell 时行为完全一致（不记录传输内容，纯直通）

## 已知取舍 / 限制

- **SFTP/SCP 走的是完全直通、不记录**：`sshd` 对外部 sftp 子系统（`Subsystem sftp /path/to/sftp-server`）的调用方式跟 `ssh host "cmd"` 是同一种（`<shell> -c "<sftp-server路径>"`），`session-shell` 识别到这种调用会直接原样 `exec`，完全跳过录制逻辑——所以 SFTP/SCP 能正常用，但传输的文件内容本身不会进审计日志。**踩过坑**：第一版实现没处理这个识别逻辑，直接把 sftp 请求也塞进了录制管道，导致协议被破坏、`scp` 直接断连；更严重的是曾经误把还在正常用来做运维操作的账号（`ec2-user`）也切换成了这个 shell，当场把自己的 `scp` 堵死。如果需要审计"谁传了什么文件"，应该用 `sftp-server` 自带的日志能力（`Subsystem sftp /path/to/sftp-server -l VERBOSE` 之类，具体参数以 `man sftp-server` 为准），走 syslog，不是这个仓库现在做的事。
- **非交互命令模式（`.log`/`.log.stderr` 分流那条路径）只记录 stdout/stderr，不记录 stdin**：`rsync`/`scp -O`（老式 scp 协议）这类"客户端把数据往 stdin 推"的远程命令能正常跑（实测 20MB 二进制文件上传，md5 前后一致），但实际传输的文件内容是通过 stdin 流向远端进程的，我们只 `tee` 了 stdout/stderr——20MB 传完日志文件只有 17KB 左右，基本只是协议握手/校验和之类的小数据，**文件本身的内容不会进审计日志**。这跟 SFTP（整体识别后直接豁免、明确不记录）不是一回事，是个容易被忽略的记录盲区：凡是这种"数据主要走 stdin 上行"的远程命令，都存在同样的问题。
- rsync 走的还是一般的 `-c` 命令路径（没有像 `sftp-server` 那样被识别豁免），所以它照样会被 `tee` 包一层——目前观察下来协议本身没被破坏（大文件传输、校验和都正常），但没有像 SFTP 那样做过详尽的边界测试，如果以后这条路径出现类似 SFTP 当初那种协议被破坏的情况，参考 `session-shell` 里 sftp-server 那段的处理方式（识别到就直接原样 `exec`，跳过 tee）。
- 日志是原始终端字节流（含 ANSI 转义码），没有 tlog 那种结构化 JSON + `journalctl` 字段查询能力，查看/检索没那么方便，用 `cat`/`scriptreplay` 即可。
- 如果程序主动关掉终端回显（比如 `read -s` 读密码），敲的内容压根不会进日志——这是 `script` 这类工具的固有盲区，不是配置能解决的，不是完整的按键级审计。
- **`sudoers` 规则的参数没有做值校验**：`ubuntu ALL=(root) NOPASSWD: .../create_session_log.sh` 没锁定具体参数，理论上一个已经登录进来的人可以自己手动再跑一次 `sudo -u root create_session_log.sh <随便什么标签>`，凭空建一个挂着别人名字的空文件，如果再自己手动往里面写内容，能伪造出一份看起来是别人做的"记录"。这个风险目前**没有从技术上完全堵死**（sudoers 语法本身不支持"参数必须等于调用者自己当前的环境变量值"这种校验），只能算接受的残余风险，缓解因素是：伪造这个文件的整个操作过程，本身也会被记录在**这个人自己真实的、无法伪造的会话日志里**——事后审查两份日志能发现破绽。真要完全堵死，需要换一种从内核审计（如 `auditd`/utmp）而不是 shell 环境变量/参数去derive身份的方案，复杂度高很多，本仓库暂未实现。
- **如果目标账号本身已经有不受限的 sudo（比如云主机默认的 `ec2-user ALL=(ALL) NOPASSWD:ALL`），这套方案的防篡改能力基本不成立**：这套设计的核心假设是"登录者除了那一条窄权限 sudoers 规则外没有任何其他 root 权限"（`ubuntu` 就是这样）。如果给一个本来就有完整 sudo 的账号也套上 `session-shell`，它可以随时 `sudo chattr -a`/`sudo rm`/`sudo usermod -s /bin/bash 自己` 绕开或跳出录制——套不套得看需求：只是想要"正常情况下留痕、给操作留个底"，套上没问题；真要"就算这个人想干坏事也拦得住"，就没意义了，除非同时把这个账号的 sudo 收紧到跟 `ubuntu` 一样窄。
