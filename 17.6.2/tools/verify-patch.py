#!/usr/bin/env python3
"""
rusda patch 验证脚本

验证 dist-android 中所有打包产物是否已正确 patch，避免部分产物 patch 生效、部分未生效。

用法:
  python tools/verify-patch.py [dist-android 目录]
  python tools/verify-patch.py /path/to/dist-android
  python tools/verify-patch.py --strict     # 额外检查 frida:rpc（gadget 内嵌 JS 可能仍含）
  python tools/verify-patch.py --paranoid    # 把「残留 frida 字符串」也算作失败

检查项:
  1) 不应出现 (硬性): FridaScriptEngine, GLib-GIO, GDBusProxy, GumScript, gum-js-loop, gmain, gdbus
  2) 应出现 (硬性):   enignEtpircSadirF/OIG-biLG/yxorPsuBDG/tpircSmuG, russellloop, rmain, rubus
  3) ELF 架构一致 (硬性): 文件名里的 -android-<arch> 必须与 ELF e_machine 匹配（防止 issue #9：
     64 位构建误打成 32 位 gadget）。
  4) 残留 frida 字符串 (默认仅告警): 列出仍含 "frida"/"gum" 的字符串（如 libfrida-gadget-raw.so、
     编译期源码路径等），方便评估魔改完成度；--paranoid 下视为失败。
"""

import argparse
import re
import subprocess
import sys
import tempfile
from pathlib import Path

# topatch 会替换的原始字符串（不应再出现）—— 硬性失败
BAD_STRINGS = [
    "FridaScriptEngine",
    "GLib-GIO",
    "GDBusProxy",
    "GumScript",
    "gum-js-loop",
    "gmain",
    "gdbus",
]

# 严格模式额外检查（Vala 已用 XOR 运行时解码，但 worker.js/message-dispatcher.js 仍含字面量）
BAD_STRINGS_STRICT = ["frida:rpc"]

# topatch 替换后的字符串（应出现，表示 patch 生效）
GOOD_STRINGS = [
    "enignEtpircSadirF",  # FridaScriptEngine 反转
    "OIG-biLG",           # GLib-GIO 反转
    "yxorPsuBDG",         # GDBusProxy 反转
    "tpircSmuG",          # GumScript 反转
    "russellloop",        # gum-js-loop
    "rmain",              # gmain
    "rubus",              # gdbus
]

# 残留 frida/gum 扫描时，明确「有意保留」的字面量（协议互操作所需，不计入告警）。
# 说明: 标准 Frida 客户端仍依赖这些 D-Bus 接口/路径名，批量改会破坏兼容性。
RESIDUAL_ALLOWLIST = (
    "re.frida.",          # D-Bus 对象路径/接口（客户端兼容）
)

# ELF e_machine -> 规范 arch 名
EM_MACHINE = {
    0x03: "x86",
    0x28: "arm",
    0x3E: "x86_64",
    0xB7: "arm64",
}

# 文件名里的 arch token（长的在前，避免 arm64/x86_64 被 arm/x86 抢先匹配）
ARCH_RE = re.compile(r"-android-(x86_64|x86|arm64|arm)\b")


def materialize(path: Path) -> tuple[Path, Path | None]:
    """
    返回 (可读的 ELF 路径, 需删除的临时文件 or None)。
    .xz 会被解压到临时文件；普通文件原样返回。
    """
    if path.suffix == ".xz" or path.name.endswith(".xz"):
        out = subprocess.run(["xz", "-d", "-c", str(path)], capture_output=True, check=True, timeout=60)
        tmp = Path(tempfile.NamedTemporaryFile(delete=False, suffix=".bin").name)
        tmp.write_bytes(out.stdout)
        return tmp, tmp
    return path, None


def read_elf_machine(bin_path: Path) -> int | None:
    """直接读 ELF 头的 e_machine（offset 18, 2 字节, 小端）；非 ELF 返回 None。"""
    try:
        with open(bin_path, "rb") as f:
            head = f.read(20)
        if len(head) < 20 or head[:4] != b"\x7fELF":
            return None
        return int.from_bytes(head[18:20], "little")
    except OSError:
        return None


def _strings_py(bin_path: Path, min_len: int = 4) -> list[str]:
    """纯 Python 版 strings 回退实现（无 binutils 时使用，如 Windows/macOS）。"""
    out = []
    try:
        data = bin_path.read_bytes()
    except OSError:
        return out
    cur = bytearray()
    for b in data:
        if 0x20 <= b < 0x7F:
            cur.append(b)
        else:
            if len(cur) >= min_len:
                out.append(cur.decode("ascii", "ignore"))
            cur.clear()
    if len(cur) >= min_len:
        out.append(cur.decode("ascii", "ignore"))
    return out


def get_strings(bin_path: Path) -> list[str]:
    try:
        result = subprocess.run(["strings", str(bin_path)], capture_output=True, text=True, timeout=120)
        if result.returncode == 0:
            return result.stdout.splitlines()
        return _strings_py(bin_path)
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return _strings_py(bin_path)


def expected_arch_from_name(name: str) -> str | None:
    m = ARCH_RE.search(name)
    return m.group(1) if m else None


def residual_frida(lines: list[str]) -> list[str]:
    """返回仍含 frida/gum 的去重字符串（排除有意保留项）。"""
    seen = []
    seen_set = set()
    for line in lines:
        low = line.lower()
        if "frida" not in low and "gum" not in low:
            continue
        if any(allow in line for allow in RESIDUAL_ALLOWLIST):
            continue
        s = line.strip()
        if s and s not in seen_set:
            seen_set.add(s)
            seen.append(s)
    return seen


def verify_file(path: Path, strict: bool) -> dict:
    """验证单个文件，返回结果字典。"""
    res = {
        "name": path.name,
        "bad": [],
        "bad_strict": [],
        "good": [],
        "arch_ok": None,     # None=非ELF/无法判定, True/False
        "arch_detail": "",
        "residual": [],
        "readable": True,
    }
    try:
        bin_path, tmp = materialize(path)
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
        res["readable"] = False
        return res

    try:
        # ELF 架构校验
        expect = expected_arch_from_name(path.name)
        em = read_elf_machine(bin_path)
        if expect is not None and em is not None:
            actual = EM_MACHINE.get(em, f"0x{em:x}")
            res["arch_ok"] = (actual == expect)
            res["arch_detail"] = f"期望 {expect} / 实际 {actual}"
        elif expect is not None and em is None:
            res["arch_detail"] = f"期望 {expect} / 非 ELF(无法判定)"

        lines = get_strings(bin_path)
        if not lines:
            res["readable"] = False
            return res

        line_blob = "\n".join(lines)
        res["bad"] = [s for s in BAD_STRINGS if s in line_blob]
        if strict:
            res["bad_strict"] = [s for s in BAD_STRINGS_STRICT if s in line_blob]
        res["good"] = [s for s in GOOD_STRINGS if s in line_blob]
        res["residual"] = residual_frida(lines)
    finally:
        if tmp is not None:
            tmp.unlink(missing_ok=True)
    return res


def find_artifacts(dist_dir: Path) -> list[Path]:
    artifacts = []
    patterns = [
        "rusda-server-*-android-*",
        "rusda-inject-*-android-*",
        "rusda-gadget-*-android-*.so*",
    ]
    for p in patterns:
        artifacts.extend(dist_dir.glob(p))
    for staging in dist_dir.glob("staging-*"):
        if staging.is_dir():
            for exe in (staging / "bin").glob("rusda-*"):
                if exe.is_file():
                    artifacts.append(exe)
            for lib in (staging / "lib" / "rusda").rglob("rusda-gadget.so"):
                if lib.is_file():
                    artifacts.append(lib)
    return sorted(set(artifacts))


def main():
    # 在 GBK 等非 UTF-8 控制台（Windows）下也能正常输出 ✓/✗ 等符号
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except (AttributeError, ValueError):
        pass

    parser = argparse.ArgumentParser(description="rusda patch 验证")
    parser.add_argument("dir", nargs="?", help="dist-android 目录")
    parser.add_argument("--strict", action="store_true",
                        help="额外检查 frida:rpc（gadget 内嵌 JS 可能仍含，预期会 fail）")
    parser.add_argument("--paranoid", action="store_true",
                        help="把『残留 frida 字符串』也算作失败")
    args = parser.parse_args()

    root = Path(__file__).resolve().parent.parent
    dist_dir = Path(args.dir) if args.dir else root / "dist-android"

    if not dist_dir.exists():
        print(f"错误: 目录不存在 {dist_dir}")
        sys.exit(1)

    artifacts = find_artifacts(dist_dir)
    if not artifacts:
        print(f"未找到 rusda 产物，请检查 {dist_dir}")
        sys.exit(1)

    print("=" * 70)
    print("rusda patch 验证")
    print("=" * 70)
    print(f"目录: {dist_dir}")
    print(f"产物数: {len(artifacts)}")
    print(f"模式: {'严格 ' if args.strict else ''}{'偏执(残留即失败) ' if args.paranoid else ''}".strip() or "标准")
    print()
    print("检查规则:")
    print("  ✗ 不应出现: FridaScriptEngine, GLib-GIO, GDBusProxy, GumScript, gum-js-loop, gmain, gdbus"
          + (", frida:rpc" if args.strict else ""))
    print("  ✓ 应出现:   enignEtpircSadirF, OIG-biLG, yxorPsuBDG, tpircSmuG, russellloop, rmain, rubus")
    print("  ⚙ 架构一致: 文件名 arch == ELF e_machine")
    print("  ⚠ 残留扫描: 仍含 frida/gum 的字符串（默认仅告警）")
    print("-" * 70)

    all_passed = True
    total_residual = 0
    for path in artifacts:
        r = verify_file(path, strict=args.strict)

        failed = False
        if not r["readable"]:
            failed = True
        if r["bad"] or r["bad_strict"]:
            failed = True
        if r["arch_ok"] is False:
            failed = True
        if args.paranoid and r["residual"]:
            failed = True
        if failed:
            all_passed = False

        status = "✗ FAIL" if failed else "✓ PASS"
        print(f"\n{r['name']}")
        print(f"  状态: {status}")
        if not r["readable"]:
            print("  无法读取或解压")
        if r["arch_detail"]:
            mark = "✓" if r["arch_ok"] else ("✗" if r["arch_ok"] is False else "·")
            print(f"  架构: {mark} {r['arch_detail']}")
        if r["bad"]:
            print(f"  未 patch: {', '.join(r['bad'])}")
        if r["bad_strict"]:
            print(f"  严格检查: {', '.join(r['bad_strict'])}")
        if r["good"]:
            print(f"  已 patch: {', '.join(r['good'])}")
        if r["residual"]:
            total_residual += len(r["residual"])
            shown = r["residual"][:8]
            print(f"  ⚠ 残留 frida/gum 字符串 ({len(r['residual'])} 条，示例):")
            for s in shown:
                print(f"      - {s[:80]}")
            if len(r["residual"]) > len(shown):
                print(f"      … 其余 {len(r['residual']) - len(shown)} 条")

    print()
    print("=" * 70)
    if total_residual and not args.paranoid:
        print(f"提示: 共 {total_residual} 条残留 frida/gum 字符串（仅告警）。"
              "这些多为协议/源码路径/SONAME，属已知魔改盲区，可用 --paranoid 强制失败。")
    if all_passed:
        print("全部通过 ✓")
        sys.exit(0)
    else:
        print("存在不合格产物，请检查构建流程")
        sys.exit(1)


if __name__ == "__main__":
    main()
