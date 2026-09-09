#!/usr/bin/env python3
"""从 dSYM 中提取全部函数签名与结构体布局，按源文件分组。

这是 docs/decrypt-node-reverse.md 的**可复现来源**：文档里那些函数签名、
参数名、类型、结构体成员偏移，都是本脚本对 reference/ 里的 dSYM 解析出来的。

用法:
    python3 scripts/dwarf-functions.py [dSYM路径] > docs/dwarf-functions.txt

依赖: Xcode Command Line Tools 自带的 `dwarfdump`（/usr/bin/dwarfdump）。
"""
from __future__ import annotations

import os
import re
import subprocess
import sys
from collections import defaultdict

DEFAULT_DSYM = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "reference", "koolearn-decrypt", "decrypt.node.dSYM",
)

# 一行 DIE 头: "0x0001c876:   DW_TAG_subprogram"
DIE_RE = re.compile(r"^0x([0-9a-f]+):\s+(DW_TAG_\w+)\s*$")
# 一行属性: "                DW_AT_name\t(\"decryptByPlan\")"
ATTR_RE = re.compile(r"^\s+DW_AT_(\w+)\s+\((.*)\)\s*$")
# 类型引用形如: 0x0001c545 "dataTag *"
TYPE_RE = re.compile(r'^0x[0-9a-f]+\s+"(.*)"$')


class Die:
    __slots__ = ("offset", "tag", "col", "attrs")

    def __init__(self, offset: str, tag: str, col: int) -> None:
        self.offset = offset
        self.tag = tag
        self.col = col
        self.attrs: dict[str, str] = {}

    def attr(self, name: str) -> str | None:
        return self.attrs.get(name)

    def typename(self) -> str:
        """把 DW_AT_type 的值解析成可读类型名。"""
        raw = self.attrs.get("type")
        if raw is None:
            return "void"
        m = TYPE_RE.match(raw.strip())
        return m.group(1) if m else raw.strip()


def parse_dies(text: str) -> list[Die]:
    dies: list[Die] = []
    cur: Die | None = None
    for line in text.splitlines():
        m = DIE_RE.match(line)
        if m:
            cur = Die(m.group(1), m.group(2), line.index("DW_TAG"))
            dies.append(cur)
            continue
        if cur is None:
            continue
        a = ATTR_RE.match(line)
        if a:
            cur.attrs[a.group(1)] = a.group(2)
    return dies


def children(dies: list[Die], i: int) -> list[Die]:
    """返回 dies[i] 的直接子 DIE（按 DWARF 深度优先顺序向后扫描）。"""
    parent = dies[i]
    out: list[Die] = []
    j = i + 1
    while j < len(dies) and dies[j].col > parent.col:
        if dies[j].col == parent.col + 2:
            out.append(dies[j])
        j += 1
    return out


def unquote(s: str | None) -> str:
    if s is None:
        return ""
    m = re.search(r'"([^"]*)"', s)
    return m.group(1) if m else s.strip()


# koolearn-decrypt 自身的源文件（其余为 Node/V8/STL 等依赖头文件）。
PROJECT_FILES = {
    "libdecrypt.cc",
    "encrypt.c", "parser.c", "tag.c", "header.c", "common.c", "md5.c",
    "sha1.c", "aes.c", "AESEncode.c", "AESDecode.c", "rc4.c", "caesar.c", "fence.c",
    "struct.h", "parser.h", "md5.h", "sha1.h", "aes.h", "AesInterns.h", "EfAes.h",
}


def file_rank(name: str) -> tuple[int, str]:
    """项目自身源文件排前，其余（依赖头文件/未知）排后。"""
    return (0 if name in PROJECT_FILES else 1, name)


def short_file(path: str | None) -> str:
    """把 decl_file 的绝对路径归一化成 basename（去掉 build/.. 之类的绕路）。"""
    if not path:
        return "(unknown)"
    p = os.path.normpath(unquote(path))
    return os.path.basename(p)


def fmt_function(die: Die, params: list[Die]) -> str:
    name = unquote(die.attr("name")) or "(anonymous)"
    ret = die.typename()
    args = ", ".join(f"{p.typename()} {unquote(p.attr('name'))}" for p in params)
    lines = [f"### {name}", f"    {ret} {name}({args})"]
    low, high = die.attr("low_pc"), die.attr("high_pc")
    if low:
        addr = low.strip()
        if high:
            try:
                span = int(high, 16) - int(addr, 16)
                addr += f"-{int(high, 16):x} (0x{span:x} bytes)"
            except ValueError:
                pass
        lines.append(f"    地址: {addr}")
    line = die.attr("decl_line")
    if line:
        lines.append(f"    源码行: {line.strip()}")
    return "\n".join(lines)


def member_offset(raw: str | None) -> str:
    """把 data_member_location 归一化成简洁的 +0xNN。"""
    if not raw:
        return ""
    s = raw.strip()
    m = re.search(r"0x[0-9a-fA-F]+", s)
    if m:
        return f" +{m.group(0)}"
    if s.isdigit():
        return f" +0x{int(s):x}"
    return f" +{s}"


def fmt_struct(die: Die, members: list[Die]) -> str:
    name = unquote(die.attr("name")) or "(anonymous)"
    size = die.attr("byte_size")
    head = f"### {name}"
    if size:
        head += f"  ({size} bytes)"
    lines = [head]
    for m in members:
        loc = member_offset(m.attr("data_member_location"))
        lines.append(f"    {m.typename()} {unquote(m.attr('name'))}{loc}")
    return "\n".join(lines)


def main() -> int:
    dsym = sys.argv[1] if len(sys.argv) > 1 else DEFAULT_DSYM
    if not os.path.exists(dsym):
        print(f"dSYM not found: {dsym}", file=sys.stderr)
        return 1

    text = subprocess.run(
        ["dwarfdump", "--debug-info", dsym],
        capture_output=True, text=True, check=True,
    ).stdout
    dies = parse_dies(text)

    funcs: dict[str, list[str]] = defaultdict(list)
    structs: dict[str, list[str]] = defaultdict(list)

    for i, die in enumerate(dies):
        kids = children(dies, i)
        if die.tag == "DW_TAG_subprogram":
            if die.attr("declaration") == "0x01":
                continue
            params = [k for k in kids if k.tag == "DW_TAG_formal_parameter"]
            funcs[short_file(die.attr("decl_file"))].append(fmt_function(die, params))
        elif die.tag == "DW_TAG_structure_type":
            members = [k for k in kids if k.tag == "DW_TAG_member"]
            if members:
                structs[short_file(die.attr("decl_file"))].append(fmt_struct(die, members))

    print("# decrypt.node DWARF 符号清单")
    print()
    print("> 由 `scripts/dwarf-functions.py` 从 `reference/koolearn-decrypt/decrypt.node.dSYM`")
    print("> 自动提取（`dwarfdump --debug-info`）。仅供研究参考，勿手工编辑。")
    print()

    print(f"## 函数（{sum(len(v) for v in funcs.values())} 个，{len(funcs)} 个源文件）")
    for f in sorted(funcs, key=file_rank):
        print()
        print(f"---")
        print()
        print(f"## 源文件: {f}")
        print()
        print("\n\n".join(funcs[f]))

    if structs:
        print()
        print("---")
        print()
        print(f"## 结构体（{sum(len(v) for v in structs.values())} 个）")
        for f in sorted(structs, key=file_rank):
            print()
            print(f"## 源文件: {f}")
            print()
            print("\n\n".join(structs[f]))

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
