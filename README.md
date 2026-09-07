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
            客户端）或者 rsync 的远程调用（"rsync --server ..."），直接原样 exec，
            完全不经过上面任何录制逻辑——这两种场景传的都是文件内容，本来就走 stdin
            （这条路径根本不记录 stdin），录了也没用，干脆直接豁免
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
- rsync：20MB 二进制文件上传验证过 md5 前后一致，且确认豁免生效（`/opt/audit/log` 里不会为 rsync 传输生成任何记录）
- 作为跳板（`ssh -J`/`ProxyJump`）转发到内网其他机器：转发和后续登录都正常，隔离测试确认转发过程完全不产生任何审计记录（原因见下面"已知取舍"一节）

> 以上都是在真实 sshd/PAM/文件系统的目标主机上实测过的。下面这条不是——`session-shell` 里 sftp/rsync 豁免分支的加固逻辑（属主校验、`realpath` 解析、TOCTOU 修复）和非交互命令分支新加的"执行前记命令行"这一行，只在本地用 GNU coreutils（`realpath`/`dirname`/`basename`/`stat`/`date`，跟目标 Linux 主机版本对齐）搭了等价的函数级测试逐条验证过输入输出（覆盖：合法 sftp-server/rsync 正常放行、参数原样保留、自建同名文件或符号链接被拒、`$PATH`/裸文件名被拒、注入分号或注释被拒、命令行确实先于输出写进日志、退出码/二进制透传不受影响），还没有在真实部署的 sshd 环境里跑过 `ssh`/`scp`/`rsync`/`ProxyCommand` 走一遍全流程——按本仓库自己的标准（见上面"命令"一节），这个验证强度比"实测"低一档，部署前建议照着"手动验证清单"再跑一遍。

## 已知取舍 / 限制

- **SFTP/SCP 和 rsync 都是完全直通、不审计**：`sshd` 对外部 sftp 子系统（`Subsystem sftp /path/to/sftp-server`）和 `rsync` 走 ssh 时的远程调用方式（实测确认固定是 `rsync --server ...` 开头）都跟 `ssh host "cmd"` 是同一种（`<shell> -c "<命令>"`），`session-shell` 识别到这两种调用会直接原样 `exec`，完全跳过录制逻辑——所以 SFTP/SCP/rsync 都能正常用，但传输的文件内容本身不会进审计日志。这是刻意选择，不是遗漏：这条 `-c` 命令路径本来就只记录 stdout/stderr、不记录 stdin，而文件传输的实际内容大多是走 stdin 上行的，就算不豁免、硬塞进 `tee` 管道，也录不到真正有用的内容（实测过 rsync 走 tee 管道协议本身不会坏，但 20MB 传输完日志只有十几 KB，全是协议握手/校验和之类的噪音）——干脆和 SFTP 一视同仁，直接豁免更干净。**踩过坑**：第一版实现没处理 SFTP 的识别逻辑，直接把 sftp 请求也塞进了录制管道，导致协议被破坏、`scp` 直接断连；更严重的是曾经误把还在正常用来做运维操作的账号（`ec2-user`）也切换成了这个 shell，当场把自己的 `scp` 堵死。如果需要审计"谁传了什么文件"，应该用 `sftp-server`/`rsync` 自带的日志能力（前者 `Subsystem sftp /path/to/sftp-server -l VERBOSE`，具体参数以 `man sftp-server`/`man rsyncd.conf` 为准），走 syslog，不是这个仓库现在做的事。

**踩过第二个坑，比第一个坑严重得多**：早期实现判断"是不是该豁免"，用的是 `$2 == *sftp-server* || $2 == rsync\ --server*` 这种子串/前缀匹配。问题是 sshd 把普通 `ssh host "任意文本"` 的 exec 命令和真正的 subsystem/rsync 调用塞进的是**同一个** `-c "命令"` 分支，`session-shell` 完全没有办法区分两者的来源——也就是说这个"命令"字符串本身是登录者百分百可控的输入，不管他是不是真的在用 sftp/rsync。子串/前缀匹配把这件事变成了一个完整的**录制绕过**：登录者能直接构造 `nc target 22 # sftp-server`（命中子串，原样 `exec`，零录制）或 `rsync --server ...; 任意命令`（命中前缀，`bash -c` 把追加的部分一起跑了，同样不落盘），把任意命令伪装成豁免路径逃过录制——不只是 ProxyCommand 场景会用到这条路，这是一个通用绕过。逐步收紧到现在这个版本，一共加了四层，任一层不满足都退回正常录制路径：

1. **拒绝任何 shell 元字符**（`;`、`&`、`|`、反引号、`$`、`<`、`>`、换行）：真正的 subsystem/rsync 调用从来不需要这些字符，一旦出现就说明是想借着豁免分支夹带别的命令。
2. **格式必须整体匹配、锚定在开头**（sftp 是绝对路径打头、以 `/sftp-server` 结尾；rsync 是逐字 `rsync --server ` 打头），而不是"包含"或"以……开头就行"。
3. **只认属主，不认权限位**：光锚定文件名挡不住登录者在自己能写的地方（`$HOME`、`/tmp`……）放一个同名文件或符号链接。而"检查目录当前是否不可写"这个标准本身也不成立——目录是登录者自己的，他能把权限改成只读糊弄检查，回头再改回去，`chmod` 自己的东西从不受限。真正伪造不了的只有**属主**：`chown` 成 root 只有 root 能做。所以 sftp 分支要求 `realpath` 解析后（会追踪符号链接）的文件名仍是 `sftp-server`，rsync 分支不相信 shell 帮忙从 `$PATH` 找出来的 `rsync`（这个登录 shell 从没设置过 `PATH`，找到谁完全看继承的环境，不可信），而是自己在几个标准系统目录（`/usr/bin`、`/bin` 等）里顺序找一个真正存在的 `rsync`，两条分支最后都要求解析出的可执行文件本身**以及从它往上一直到 `/` 的每一级目录**，属主都是 root（uid 0）**且**对当前账号不可写——只查文件和直接上级目录不够，再上一级如果是登录者能写的，他一样能把上级目录整个换掉，伪造出一个"属主是 root"的下级目录。
4. **`exec` 的必须是解析后的绝对路径本身，不能是登录者传进来的原始字符串**：光验证过 `$resolved` 还去跑原始路径，会留下经典的 TOCTOU（check 和 use 之间的时间差）——登录者放一个先指向真·root 二进制、检查一过马上换成自己东西的符号链接，`bash -c` 重新解析时用的已经是掉包后的假货，前面的检查全部白做。现在是把 `realpath` 解析出来的绝对路径（加上原样保留的参数部分）拼成最终执行的字符串，全程只认这个验证过的值。

本地用 GNU coreutils（`realpath`/`dirname`/`basename`/`stat`，跟目标 Linux 主机一致）针对这四层逐一验证过：root 属主目录下的真文件/真 `rsync`（用本机 `/usr/bin/rsync` 实测）正常豁免、参数原样保留；自己目录下的同名文件、指向真实二进制再企图掉包的符号链接、指向 `/bin/bash` 的符号链接、把自己目录权限改成只读后再放同名文件、裸文件名靠 `$PATH` 查找、注入分号/注释/`--rsync-path=` 之类绕过，全部都会被识别出来、退回录制。
- **把这个账号当跳板（`ssh -J`/`ProxyJump`）转发到其他机器，完全不会被录制，且这次连"识别再豁免"都算不上**：跳板转发在 SSH 协议层走的是 `direct-tcpip` 通道，不是"session"通道——sshd 收到这种请求会直接在内部处理转发，根本不会 exec 登录用户的 shell，`session-shell` 完全不会被调用，连有没有这层包装都无关紧要。实测隔离验证过：清空日志目录后单独跑一次跳板 `scp`+`ssh`，`/opt/audit/log` 里记录数是 0；只有事后另外单独执行的检查命令自己产生了一条记录。这个不是本仓库能通过改 `session-shell` 逻辑堵住的（因为压根走不到那一层），要审计跳板转发需要在 sshd 层面想办法，不是这个仓库解决的问题。

**如果要彻底堵住这个账号被当跳板用**（而不只是审计不到）：查过 OpenSSH 源码（`serverloop.c`），`-W`/`ProxyJump` 用的 `direct-tcpip` 通道请求，判断放不放行走的是 `AllowTcpForwarding` 的 **local** 那部分权限位（`options.allow_tcp_forwarding & FORWARD_LOCAL`），所以把这个账号的 `AllowTcpForwarding` 设成 `no`（或 `remote`，只保留远程转发那部分）确实能挡住。注意这是个比较钝的开关：

- 会把这个账号**所有** TCP 转发能力一起挡掉，不只是跳板——`-L`/`-R`/`-D` 全部一起没了，如果这个账号平时还有正当的端口转发用途会一起被挡。
- `AllowTcpForwarding` 默认是全局生效的 sshd 配置项，要精确只对目标账号生效，得用 `Match User <账号>` 包一层，不要直接改全局默认值（本仓库前面已经因为改全局 sshd 配置锁死过账号一次，教训见上文）：
  ```
  Match User ubuntu
      AllowTcpForwarding no
  ```
  改完照例先 `sshd -t` 校验语法，留一个已验证能登录的窗口再 reload，别把自己也锁在外面。
- 本仓库目前**没有**自动化这个配置（这是可选的进一步加固，不是默认部署的一部分），需要的话手动加。
- **`ssh -o ProxyCommand=...` 要分两种写法看，录制效果完全不同**（`ProxyCommand`/`ProxyJump` 的行为定义见 `man ssh_config`，`-W` 的定义见 `man ssh`）：
  - **走 `-W`**（如 `ProxyCommand="ssh -W %h:%p bastion"`）：这就是 `-J`/`ProxyJump` 底层实际执行的动作——`man ssh_config` 明确说 `-J` 是 `ProxyJump` 配置项的命令行快捷写法，而 `ProxyJump`/`-J` 的效果是"先连到跳板机，再从那边建一条 TCP forwarding 到最终目标"；`man ssh` 里 `-W host:port` 的定义是"把本地标准输入输出转发到远端这个 host:port"，并且隐含 `-N`/`-T`（不执行远程命令、不分配 pty）。也就是说走的还是 `direct-tcpip` 转发通道，不是 session/exec 通道——跟上面"跳板转发完全不会被录制"是同一件事、同一个限制，`session-shell` 根本不会被调用。想挡住的话用上面 `AllowTcpForwarding`/`Match User` 的做法即可，效果一样。
  - **走外部命令**（老式写法，如 `ProxyCommand="ssh bastion nc %h %p"`，在跳板机上跑 `nc`/`socat` 转发字节）：这是一次货真价实的 `ssh bastion "nc <目标host> <目标port>"` 远程命令执行，走的是普通 session/exec 通道，会正常命中 `session-shell` 的非交互命令分支，照常经过 `sudo create_session_log.sh` 建文件、`tee` 落盘——本地对着 `bin/session-shell` 的实际逻辑验证过 `nc 10.0.0.5 22`/`socat - TCP:...` 都不会被误判成 sftp/rsync 豁免。**这条路径能被录，前提是上面"踩过第二个坑"里说的豁免匹配是锚定+禁元字符的严格版本**——用旧的子串/前缀匹配版本时，登录者只要把命令写成 `nc target 22 # sftp-server` 这种形式就能让它连同 ProxyCommand 一起完全绕开录制，等于白说。录下来之后，主体内容是内层那条被转发的 SSH 连接本身的加密协议字节，这是密码学上就注定看不出目标机上到底敲了什么命令的——那是另一条端到端加密的 SSH 会话（客户端直接到最终目标机），中间这一跳不管有没有套这层 `session-shell`、不管日志权限设得多严，天然就拿不到解密后的明文，跟这个仓库的实现无关。但"这次转发本身"这个操作现在是留了痕的：`session-shell` 在非交互命令分支真正执行前，会先把 `-c` 后面那个命令字符串本身（`printf '+++ %s exec -c %q\n' ...`，`%q` 转义成明确的 shell-quote 形式，避免二义）连同时间戳一起追加写进同一个 `chattr +a` 的主日志——这一行和后面 `tee` 录的内容享受一样的防篡改强度，不是额外开的口子。所以现在能拿到的是确定性事实："这个账号在几点几分、被哪个 REMOTEUSER 标注的 key、敲了 `nc 10.0.0.5 22` 这条准确命令"，而不是之前那种"应该能推断出"的说法——本地对着实际的 `bin/session-shell` 验证过这一行会先于命令输出写入，配合前面几层反豁免加固之后，`nc`/`socat` 这类命令确实会落进这条记录路径，不会被误判成 sftp/rsync 豁免掉。跟 SFTP/rsync 一样，"记录不到目标机上发生了什么"是密码学边界决定的取舍，不是遗漏；但至少"谁在什么时候用这个账号转发到了哪"现在是确定可查的，不再是"记录了也没用"的噪音。
  - ⚠️ **容易被忽略的一点**：上面为了彻底挡住跳板用法建议的 `AllowTcpForwarding no`，**只挡得住 `-W`/`ProxyJump` 这一种**——`man sshd_config` 原文里 `AllowTcpForwarding` 控制的是"TCP forwarding"（即 `direct-tcpip`/`forwarded-tcpip` 这类转发通道请求），跟要不要放行远程命令执行是完全独立的两个维度，改了这个开关之后 `nc`/`socat` 版本的 `ProxyCommand` 跳板照样能用、照样能连出去。这条路径本仓库不打算堵（也没法只堵这一种命令又不影响正常运维命令——真要堵就得把这个账号能执行的命令收紧成白名单，跟这套方案"放行正常运维、只求留痕"的定位冲突），只是确认它至少会被记下来，不是完全没有痕迹。
- 日志是原始终端字节流（含 ANSI 转义码），没有 tlog 那种结构化 JSON + `journalctl` 字段查询能力，查看/检索没那么方便，用 `cat`/`scriptreplay` 即可。
- 如果程序主动关掉终端回显（比如 `read -s` 读密码），敲的内容压根不会进日志——这是 `script` 这类工具的固有盲区，不是配置能解决的，不是完整的按键级审计。
- **`sudoers` 规则的参数没有做值校验**：`ubuntu ALL=(root) NOPASSWD: .../create_session_log.sh` 没锁定具体参数，理论上一个已经登录进来的人可以自己手动再跑一次 `sudo -u root create_session_log.sh <随便什么标签>`，凭空建一个挂着别人名字的空文件，如果再自己手动往里面写内容，能伪造出一份看起来是别人做的"记录"。这个风险目前**没有从技术上完全堵死**（sudoers 语法本身不支持"参数必须等于调用者自己当前的环境变量值"这种校验），只能算接受的残余风险，缓解因素是：伪造这个文件的整个操作过程，本身也会被记录在**这个人自己真实的、无法伪造的会话日志里**——事后审查两份日志能发现破绽。真要完全堵死，需要换一种从内核审计（如 `auditd`/utmp）而不是 shell 环境变量/参数去derive身份的方案，复杂度高很多，本仓库暂未实现。
- **如果目标账号本身已经有不受限的 sudo（比如云主机默认的 `ec2-user ALL=(ALL) NOPASSWD:ALL`），这套方案的防篡改能力基本不成立**：这套设计的核心假设是"登录者除了那一条窄权限 sudoers 规则外没有任何其他 root 权限"（`ubuntu` 就是这样）。如果给一个本来就有完整 sudo 的账号也套上 `session-shell`，它可以随时 `sudo chattr -a`/`sudo rm`/`sudo usermod -s /bin/bash 自己` 绕开或跳出录制——套不套得看需求：只是想要"正常情况下留痕、给操作留个底"，套上没问题；真要"就算这个人想干坏事也拦得住"，就没意义了，除非同时把这个账号的 sudo 收紧到跟 `ubuntu` 一样窄。
