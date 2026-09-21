#!/usr/bin/env python3
import argparse
import re
import sys

def renumber(lines, start=0, prefix=None, reset_on_zero=False):
    counter = start
    new_lines = []
    pattern = re.compile(r'^(\s*#define\s+)(\w+)(\s+)(.+?)(\s*)$')

    for line in lines:
        m = pattern.match(line)
        if m:
            name = m.group(2)
            if prefix is None or name.startswith(prefix):
                original_value_str = m.group(4).strip()

                if reset_on_zero and original_value_str == "0":
                    counter = 0

                new_line = f"{m.group(1)}{name}{m.group(3)}{counter}{m.group(5)}"
                new_lines.append(new_line)

                if reset_on_zero and original_value_str == "0":
                    counter = 1
                else:
                    counter += 1
                continue

        new_lines.append(line)
    return new_lines

def main():
    parser = argparse.ArgumentParser(description="regen #define ids")
    parser.add_argument("input", help="input file")
    parser.add_argument("-o", "--output", help="output file (default: stdout)")
    parser.add_argument("-s", "--start", type=int, default=0, help="start num (default: 0)")
    parser.add_argument("-p", "--prefix", help="target prefix (rg: CLK_TOP_)")
    parser.add_argument("--reset-on-zero", action="store_true", help="process multiple sections")
    args = parser.parse_args()

    with open(args.input, "r", encoding="utf-8") as f:
        lines = f.readlines()

    new_lines = renumber(lines, start=args.start, prefix=args.prefix,
                         reset_on_zero=args.reset_on_zero)

    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            f.writelines(new_lines)
    else:
        sys.stdout.writelines(new_lines)

if __name__ == "__main__":
    main()
