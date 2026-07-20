#!/usr/bin/env python3
"""
MediaTek scatter file → fixed-partitions DTS (特殊エンコード対応)
"""
import sys, re, argparse

DEFAULT_USER_OFFSET = 0x420000

def parse_scatter(lines):
    pattern = re.compile(r'^\s*(\S+)\s+(0x[0-9a-fA-F]+)\b')
    parts = []
    for line in lines:
        m = pattern.match(line)
        if m:
            name = m.group(1)
            start = int(m.group(2), 16)
            parts.append((name, start))
    parts.sort(key=lambda x: x[1])
    return parts

def is_special_part(start):
    return (start >> 16) == 0xFFFF

def compute_special_part(start, user_offset, user_area_size):
    size = (start & 0xFFFF) * 128 * 1024
    linear_start = user_offset + user_area_size - size
    return linear_start, size

def gen_dts(parts, user_offset, user_area_size):
    if not parts:
        return "/* No partitions found */\n"

    # 特殊パーティションを展開
    expanded = []
    for name, start in parts:
        if is_special_part(start):
            linear_start, size = compute_special_part(start, user_offset, user_area_size)
            expanded.append((name, linear_start, size))
        else:
            expanded.append((name, start, None))  # size はあとで計算

    # 有効なパーティションのみ（user領域内に開始アドレスがあるもの）
    valid = []
    for name, linear_start, size in expanded:
        user_start = linear_start - user_offset
        if user_start < 0:
            continue
        valid.append((name, user_start, size))

    # user_start でソート
    valid.sort(key=lambda x: x[1])

    # サイズを計算（既知のものはそのまま、それ以外は次のパーティションとの差）
    final = []
    n = len(valid)
    for i in range(n):
        name, user_start, size = valid[i]
        if size is None:
            if i < n - 1:
                next_start = valid[i+1][1]
                size = next_start - user_start
            else:
                # 最終パーティション (通常は usrdata など)
                size = user_area_size - user_start
        final.append((name, user_start, size))

    # 64bit cells の必要性を判断
    need_64 = any(start > 0xFFFFFFFF or size > 0xFFFFFFFF for (_, start, size) in final)
    addr_cells = 2 if need_64 else 1
    size_cells = 2 if need_64 else 1

    lines = []
    lines.append("partitions {")
    lines.append("\tcompatible = \"fixed-partitions\";")
    lines.append(f"\t#address-cells = <{addr_cells}>;")
    lines.append(f"\t#size-cells = <{size_cells}>;")
    lines.append("")

    for name, user_start, size in final:
        if user_start % 512 != 0 or size % 512 != 0:
            print(f"Warning: partition '{name}' not sector-aligned, skipping", file=sys.stderr)
            continue
        node_name = f"partition@{user_start:x}"
        lines.append(f"\t{node_name} {{")
        lines.append(f"\t\tlabel = \"{name}\";")
        if addr_cells == 2:
            lines.append(f"\t\treg = <0x{user_start >> 32:08x} 0x{user_start & 0xFFFFFFFF:08x} "
                         f"0x{size >> 32:08x} 0x{size & 0xFFFFFFFF:08x}>;")
        else:
            lines.append(f"\t\treg = <0x{user_start:08x} 0x{size:08x}>;")
        lines.append(f"\t}};")
        lines.append("")

    lines.append("};")
    return "\n".join(lines)

def main():
    parser = argparse.ArgumentParser(description="Convert MTK scatter to fixed-partitions DTS")
    parser.add_argument("file", nargs="?", help="Scatter file")
    parser.add_argument("--offset", type=lambda x: int(x,16), default=DEFAULT_USER_OFFSET,
                        help="User area offset (default 0x420000)")
    parser.add_argument("--user-size", type=lambda x: int(x,16), required=True,
                        help="Total user area size in hex (e.g. 0x3A3E00000)")
    args = parser.parse_args()

    if args.file:
        with open(args.file) as f:
            content = f.readlines()
    else:
        content = sys.stdin.readlines()

    parts = parse_scatter(content)
    dts = gen_dts(parts, args.offset, args.user_size)
    print(dts)

if __name__ == "__main__":
    main()
