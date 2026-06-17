#!/bin/bash
# 串行编译 Android 全架构 (x86, x86_64, arm, arm64)，包含 server、gadget、inject
# 输出命名格式: rusda-server-{version}-android-{arch}.xz
# 用法: ./tools/build-android-all.sh

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SRC_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
OUTPUT_DIR="${SRC_ROOT}/dist-android"

# 版本号自动从 frida 源码推导，保证产物文件名与二进制 `--version` 一致。
# 否则若基线 commit 不在 tag 上（如 17.6.2 之后 4 个提交 = 17.6.3-dev.4），
# 文件名会写死成 17.6.2 而二进制其实是 17.6.3-dev.4 (见 issue #10)。
VERSION_FALLBACK="17.6.2"
VERSION=""
if [ -f "${SRC_ROOT}/releng/frida_version.py" ]; then
    VERSION="$(python3 "${SRC_ROOT}/releng/frida_version.py" 2>/dev/null \
                | grep -oE '[0-9]+\.[0-9]+\.[0-9]+(-dev\.[0-9]+)?' | head -1)"
fi
VERSION="${VERSION:-$VERSION_FALLBACK}"
echo "[*] 打包版本号: ${VERSION}"

# 检查 NDK
if [ -z "$ANDROID_NDK_ROOT" ]; then
    echo "错误: 请设置 ANDROID_NDK_ROOT 环境变量"
    echo "  export ANDROID_NDK_ROOT=/path/to/ndk-r25"
    exit 1
fi

cd "$SRC_ROOT"

# 清理旧的输出
rm -rf "$OUTPUT_DIR"
mkdir -p "$OUTPUT_DIR"

# 单架构：configure + make + install
build_arch() {
    local arch=$1
    local build_dir="${SRC_ROOT}/build-android-${arch}"
    local prefix="${OUTPUT_DIR}/staging-${arch}"

    echo "[$arch] 开始配置..."
    rm -rf "$build_dir"
    mkdir -p "$build_dir"
    cd "$build_dir"

    ../configure \
        --prefix="$prefix" \
        --host="android-${arch}" \
        --enable-server \
        --enable-gadget \
        --enable-inject

    echo "[$arch] 开始编译..."
    make -j$(nproc)
    make install

    cd "$SRC_ROOT"
    echo "[$arch] 完成"
}

# 串行编译：避免多个 configure 同时解压/写入 deps 导致 SDK 不完整
echo "=== 串行编译 Android 全架构 ==="
for arch in x86 x86_64 arm arm64; do
    build_arch "$arch" || exit 1
done

echo ""
echo "=== 打包 (命名格式: rusda-*-{version}-android-{arch}.xz) ==="

# arch -> ELF 位宽 (gadget 安装目录 lib/rusda/{32,64})
# 64 位构建 (arm64/x86_64) 会同时产出一个 32 位的「模拟」gadget 放在 lib/rusda/32，
# 不能用 `-f 32 优先` 选择，否则 arm64 会错打成 32 位 ARM (见 issue #9)。
gadget_bits_for_arch() {
    case "$1" in
        arm|x86)        echo 32 ;;
        arm64|x86_64)   echo 64 ;;
        *)              echo "" ;;
    esac
}

# arch -> readelf -h "Machine:" 行中应出现的关键字，用于校验产物架构
elf_machine_for_arch() {
    case "$1" in
        arm)     echo "ARM" ;;
        arm64)   echo "AArch64" ;;
        x86)     echo "Intel 80386" ;;
        x86_64)  echo "X86-64" ;;
        *)       echo "" ;;
    esac
}

# 校验 ELF 文件的机器类型与目标 arch 一致，不一致直接报错退出
assert_elf_arch() {
    local file=$1 arch=$2
    local expect; expect="$(elf_machine_for_arch "$arch")"
    if ! command -v readelf >/dev/null 2>&1; then
        echo "  [warn] 未找到 readelf，跳过 $arch 架构校验"
        return 0
    fi
    local machine; machine="$(readelf -h "$file" 2>/dev/null | sed -n 's/.*Machine:[[:space:]]*//p')"
    case "$machine" in
        *"$expect"*) : ;;
        *)
            echo "  [ERROR] $(basename "$file") 架构不符: 期望含 '$expect'，实际 '$machine' (arch=$arch)"
            echo "          打包中止，请检查 build/staging 目录。"
            exit 1
            ;;
    esac
}

# 按官方格式打包：单文件 xz 压缩，非 tar
for arch in x86 x86_64 arm arm64; do
    staging="${OUTPUT_DIR}/staging-${arch}"

    # rusda-server: rusda-server-17.6.2-android-arm.xz
    if [ -f "$staging/bin/rusda-server" ]; then
        assert_elf_arch "$staging/bin/rusda-server" "$arch"
        echo "  rusda-server-${VERSION}-android-${arch}.xz"
        xz -c -T0 "$staging/bin/rusda-server" > "${OUTPUT_DIR}/rusda-server-${VERSION}-android-${arch}.xz"
    fi

    # rusda-inject: rusda-inject-17.6.2-android-arm.xz
    if [ -f "$staging/bin/rusda-inject" ]; then
        assert_elf_arch "$staging/bin/rusda-inject" "$arch"
        echo "  rusda-inject-${VERSION}-android-${arch}.xz"
        xz -c -T0 "$staging/bin/rusda-inject" > "${OUTPUT_DIR}/rusda-inject-${VERSION}-android-${arch}.xz"
    fi

    # rusda-gadget: rusda-gadget-17.6.2-android-arm.so.xz
    # 按 arch 位宽精确选择，避免 64 位构建误选 32 位「模拟」gadget (issue #9)。
    # 用 find 兼容不同 frida 版本的资源目录：老版 lib/rusda/{32,64}/，
    # 新版(17.14+) lib/rusda-<api_version>/{32,64}/。
    bits="$(gadget_bits_for_arch "$arch")"
    gadget="$(find "$staging/lib" -path "*/${bits}/rusda-gadget.so" 2>/dev/null | head -1)"
    if [ -n "$bits" ] && [ -n "$gadget" ] && [ -f "$gadget" ]; then
        assert_elf_arch "$gadget" "$arch"
        echo "  rusda-gadget-${VERSION}-android-${arch}.so.xz"
        xz -c -T0 "$gadget" > "${OUTPUT_DIR}/rusda-gadget-${VERSION}-android-${arch}.so.xz"
    else
        echo "  [warn] 未找到 $arch 的 gadget: $gadget"
    fi
done

# 清理 staging
rm -rf "${OUTPUT_DIR}"/staging-*

echo ""
echo "=== 完成 ==="
echo "输出目录: $OUTPUT_DIR"
ls -lh "$OUTPUT_DIR"/*.xz 2>/dev/null || true
