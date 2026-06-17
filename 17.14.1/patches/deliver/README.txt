patches/deliver/ — 17.14.1 交付补丁（相对官方 Frida tag 17.14.1）

文件
----
  superrepo.patch   顶层：.gitignore + tools/build-android-all.sh（串行四架构，按位宽精确选 gadget + readelf 架构校验 + 版本号自动推导）
  frida-core.patch  子模块 frida-core（含新增 lib/base/obfuscate.vala、src/topatch.py）
  frida-gum.patch   子模块 frida-gum

应用顺序
--------
  1) git clone --recurse-submodules -b 17.14.1 https://github.com/frida/frida frida17.14.1
  2) cd frida17.14.1
  3) git apply patches/deliver/superrepo.patch    # 若 releng gitlink 报错可加 --exclude=releng
  4) cd subprojects/frida-core && git apply ../../patches/deliver/frida-core.patch && cd ../..
  5) cd subprojects/frida-gum  && git apply ../../patches/deliver/frida-gum.patch  && cd ../..
  6) 编译（需 NDK r29、node22、lief）：
       export ANDROID_NDK_ROOT=<NDK r29 路径>
       ./tools/build-android-all.sh
     产物在 dist-android/，用 python tools/verify-patch.py dist-android 自检。

与 17.6.2 的差异（移植要点）
---------------------------
  - 资源目录改为 lib/rusda-<api_version>/{32,64}/（meson.build frida_libdir_name）
  - lib/base/linux.vala memfd 改为 LinuxSyscall.MEMFD_CREATE
  - lib/base/rpc.vala 用 get_rpc_str + Obfuscate 运行时解码
  - linux-host-session 的 re.frida.helper app_process 启动逻辑在 17.14 已重构移除（JNI HelperBackend）
  - 需要 NDK r29（17.6.2 是 r25）
