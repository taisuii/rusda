# rusda Issues 处理记录

> 维护者参考。每条含：根因 / 处理 / 可直接复制的中文回复草稿。
> 状态图例：✅已修复(代码)　🔨待编译验证　💬需对方补充信息　📌功能请求

---

## #9 rusda-gadget-17.6.2-android-arm64.so 是 32 位的　✅🔨

**根因**：`tools/build-android-all.sh` 旧逻辑用「`lib/rusda/32` 存在就优先取」来选 gadget。
但 64 位构建（arm64 / x86_64）会**同时**在 `lib/rusda/32/` 产出一个 32 位「模拟（emulated）」gadget，
于是 arm64 / x86_64 都被错打成了 32 位（arm64 实际是 32 位 ARM，`e_machine=0x28`）。

**处理**：
- 打包改为按 arch **显式映射位宽**（arm/x86→32，arm64/x86_64→64），不再「32 优先」。
- 对每个产物用 `readelf` 校验 `e_machine`，不符**直接中止打包**。
- `verify-patch.py` 增加 ELF 架构硬校验：文件名 arch 必须 == ELF 机器类型，自动发现本类错误。
- 顺带（@fh2002 反馈）：`verify-patch.py` 现在会扫描残留 `frida/gum` 字符串（`--paranoid` 可升为失败，
  `re.frida.*` 协议串走白名单）；`topatch.py` 对 `libfrida-gadget-raw` / `libfrida-agent-raw` 做等长替换，
  消除残留 SONAME 特征。

**回复草稿**：
> 已定位并修复。根因是打包脚本在 64 位构建里误选了同目录下的 32 位「模拟 gadget」，arm64/x86_64 都受影响。
> 现已改为按架构精确取 + `readelf` 机器类型校验（不符直接报错），重新编译打包后会更新 Release。
> @fh2002 的反馈也一并处理了：verify 脚本新增 ELF 架构硬校验 + 残留 frida 字符串扫描（`--paranoid`），
> `libfrida-gadget-raw` 这类 SONAME 残留也用等长替换清掉了。`re.frida.*` 是协议互操作需要、有意保留。感谢两位。

---

## #10 给我干哪来了，这还是国内吗？（版本号不符）　✅🔨

**根因**：截图里 `rusda-server --version` 报 **`17.6.3-dev.4`**，但文件名写的是 `17.6.2`。
因为 `build-android-all.sh` 把版本号写死成 `17.6.2`，而当时基线 commit 不在 17.6.2 tag 上
（tag 之后第 4 个提交 = `17.6.3-dev.4`），导致文件名与二进制实际版本不一致。

**处理**：版本号改为从 `releng/frida_version.py` **自动推导**，文件名与二进制 `--version` 永远一致。
（本次从干净的 17.6.2 基线构建，二者都会是 17.6.2。）

**回复草稿**：
> 哈哈这是版本号标注问题：之前打包脚本把版本写死成 17.6.2，但实际基线在 tag 之后几个提交，
> 所以二进制 `--version` 显示 17.6.3-dev.4。现在版本号改为自动从源码推导，文件名和二进制会一致。重新发包会修正。

---

## #4 运行链接时候报错（16.2.1 agent dlopen 失败）　🔨💬

**现象（截图）**：`Frida 16.2.1` → `Connected to 127.0.0.1:10080` →
`Failed to spawn: dlopen failed: "/memfd:jit-cache (deleted)" .dynamic section header was not found`

**分析**：`/memfd:jit-cache` 就是注入的 agent（魔改把 memfd 名改成了 jit-cache）。
`.dynamic section header was not found` 是 bionic 链接器在 agent ELF 里找不到 PT_DYNAMIC，
通常意味着**嵌入的 agent .so 被 topatch/lief 改写后结构损坏**。属 16.2.1 线的真实 bug，
需重编 16.2.1 并用 `readelf` 检查 topatch 后 agent 的 program header 是否完好；
若是 lief `write()` 破坏结构，则把符号改名也改成「等长 in-place 字节替换」，避免 lief 重排 ELF。

**回复草稿（先收集信息 + 告知在查）**：
> 这是 spawn 时注入的 agent（memfd:jit-cache）被加载器拒绝，多半是 16.2.1 的 agent 在二进制改写后
> 结构受损。我正在重编 16.2.1 复现排查。麻烦先补充：设备 Android 版本、架构（`uname -m`）、
> 用的是 server 还是 gadget、spawn 还是 attach。修好会更新 16.2.1 的包。

---

## #11 16.2.1 没有 rusda-inject　📌🔨

**根因**：16.2.1 的补丁集里**没有**对 `inject/meson.build` 的改名补丁（17.6.2 才有），
所以从没产出过 `rusda-inject`。低版本 Android 用不了 17.x，需要 16.2.1 的 inject。

**处理**：给 16.2.1 补上 inject 改名（对齐 17.6.2 的 `inject/meson.build` → `rusda-inject` / `re.rusda.Inject`），
`--enable-inject` 重新编译四架构并打包 `rusda-inject-16.2.1-android-*`。

**回复草稿**：
> 确实漏了——16.2.1 的补丁没有改 inject，所以没产出 rusda-inject。我已对齐补上，重编 16.2.1 后会把
> `rusda-inject-16.2.1-android-{arm,arm64,x86,x86_64}` 一起发到 Release。

---

## #3 能编译一个 16.7 的吗　📌

**说明**：16.7 属功能请求（另有人 +1）。本轮已直接提供**最新版 17.14.1**（同 17.x 线，特性最全）。
16.7 介于 16.2.1 与 17.x 之间，如确有低版本需求可单独排期。

**回复草稿**：
> 这轮我把补丁移植到了**最新的 17.14.1**，并补全了 16.2.1（含 inject）。16.7 如果是为了特定设备/旧系统兼容，
> 麻烦说下具体场景（Android 版本/机型），我评估下要不要单独出一版。

---

## #6 拉取的包没有 build 文件夹了？　💬

**分析（截图）**：用户 `cd frida && ls` 看到的是**官方 frida 源码树**（frida-go/frida-clr/... 同级目录），
没有 `build/`。`build/` 是 `make`/`configure` 编译时才生成的，本仓库只放**补丁 + 工具**，不含编译产物或 build 目录
（`.gitignore` 已排除 `build-android-*/`、`dist-android/`）。编译产物在 **Releases**。

**回复草稿**：
> `build/` 是执行 `make`/`./configure` 时才会生成的目录，源码刚拉下来没有是正常的。
> 本仓库只放补丁和工具脚本，不含 build 目录；编译好的二进制在 Releases 里直接下。
> 想自己编译就按 README / `patches/deliver/README.txt` 的步骤，跑完 `make` 后自然会有 build 目录。

---

## #8 某 APP 附加闪退（com.jxedt 驾考宝典）　💬

**分析**：目标 App 大概率带反调试 / 反 frida 检测（或加固）。当前魔改仍有未覆盖面：
默认端口 `27042/27052`、`/data/local/tmp/frida-` 路径、`pool-frida` 线程池名等（见 `tools/scan-frida-signatures.py`）。
另外若之前下到的是 #9 的错架构 gadget，也会直接崩。

**回复草稿**：
> 先确认你用的不是之前架构打错的 arm64 gadget（#9 已修，重新下）。如果换了正确包还崩，
> 多半是该 App 自带反调试/检测。麻烦提供：`logcat` 崩溃段或 tombstone、server 还是 gadget、spawn 还是 attach。
> 这类加固 App 需要再补特征（端口/路径/线程名），我按日志评估。

---

## 备注：本轮交付

- 代码修复已提交分支 `fix/issues-9-10-arch-version`（#9 #10 + verify 强化 + SONAME + LF 规范化）。
- 重新构建并发布：**17.6.2**（修正 arch/版本）、**16.2.1**（补 inject、查 #4）、**17.14.1**（最新）。
