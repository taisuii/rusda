import lief
import sys
import random
import os


def log_color(msg):
    print(f"\033[1;31;40m{msg}\033[0m")


if __name__ == "__main__":
    input_file = sys.argv[1]

    log_color(f"[*] Patch frida-agent: {input_file}")
    binary = lief.parse(input_file)

    random_name = "rusda"
    log_color(f"[*] Patch `frida` to `{random_name}`")

    if not binary:
        log_color(f"[*] Not ELF, exit")
        sys.exit(1)
    else:
        for symbol in binary.symbols:
            if symbol.name == "frida_agent_main":
                symbol.name = "main"
            if "frida" in symbol.name:
                symbol.name = symbol.name.replace("frida", random_name)
            if "FRIDA" in symbol.name:
                symbol.name = symbol.name.replace("FRIDA", random_name)

        all_patch_string = ["FridaScriptEngine", "GLib-GIO", "GDBusProxy", "GumScript"]  # 字符串特征修改 尽量与源字符一样

        for section in binary.sections:
            if section.name != ".rodata":
                continue
            for patch_str in all_patch_string:
                addr_all = section.search_all(patch_str)  # Patch 内存字符串

                for addr in addr_all:
                    patch = [ord(n) for n in list(patch_str)[::-1]]
                    log_color(
                        f"[*] Patching section name={section.name} offset={hex(section.file_offset + addr)} orig:{patch_str} new:{''.join(list(patch_str)[::-1])}")
                    binary.patch_address(section.file_offset + addr, patch)

        binary.write(input_file)

        # thread_gum_js_loop
        random_name = "russellloop"
        log_color(f"[*] Patch `gum-js-loop` to `{random_name}`")
        os.system(f"sed -b -i s/gum-js-loop/{random_name}/g {input_file}")

        random_name = "rmain"
        log_color(f"[*] Patch `gmain` to `{random_name}`")
        os.system(f"sed -b -i s/gmain/{random_name}/g {input_file}")

        random_name = "rubus"
        log_color(f"[*] Patch `gdbus` to `{random_name}`")
        os.system(f"sed -b -i s/gdbus/{random_name}/g {input_file}")

        # 注：frida-gadget 不可全局 sed，会破坏 injector 的 frida-gadget-tcp- 匹配；gadget.glue 线程名已由 gadget.vala Obfuscate 处理

        # 仅做 rusda 式二进制 patch，不改协议（re.frida.*、frida:rpc 等），保证与标准 frida 客户端兼容

        # SONAME 残留特征：libfrida-gadget-raw.so / libfrida-agent-raw.so
        # 等长替换（frida->rusda 均 5 字节），不改变 ELF 结构，安全。issue #9 (fh2002)
        for raw_name in ["libfrida-gadget-raw", "libfrida-agent-raw"]:
            new_raw = raw_name.replace("frida", "rusda")
            log_color(f"[*] Patch `{raw_name}` to `{new_raw}`")
            os.system(f"sed -b -i s/{raw_name}/{new_raw}/g {input_file}")
        log_color(f"[*] Patch Finish")
