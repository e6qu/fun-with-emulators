#!/usr/bin/env python3
"""Generate the x18forms guest from x18forms.tsv, into the file the one
argument names (the end-to-end test does, into its build directory).

x18forms.tsv lists instruction words that name x18 (or w18), one per line:
the word in hex, its mnemonic and its operands as llvm-objdump prints them.
They were taken from a real binary (Alpine's OpenJDK 25 libjvm.so, whose
GCC allocates x18 as Linux allows).

For each word the guest gets two functions: one runs the word itself (fwe
rewrites it, as it rewrites the binary's), the other the same instruction
with x18 renamed to a register it does not use (which runs as it is). Both
start from the same registers, flags, stack and memory, and are checked to end
the same. Branches and pc-relative forms are left out: their result depends on
where the copy sits.
"""
import re
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent

SKIP_MNEMONICS = {"cbz", "cbnz", "tbz", "tbnz", "adr", "adrp", "prfm", "b", "bl", "br", "blr", "ret"}


def registers_named(ops):
    """GPR numbers (0-30) the operand text names, as x or w."""
    return {int(n) for n in re.findall(r"\b[xw]([0-9]|[12][0-9]|30)\b", ops)}


def entries():
    for line in (HERE / "x18forms.tsv").read_text().splitlines():
        word, mnemonic, ops = line.split("\t")
        if mnemonic in SKIP_MNEMONICS or mnemonic.startswith("b."):
            continue
        # A literal load names an address, not a register.
        if mnemonic.startswith("ldr") and "[" not in ops:
            continue
        named = registers_named(ops)
        # The working register for the renamed copy, and the one holding the
        # state's address: neither named by the instruction.
        free = [r for r in range(1, 18) if r not in named]
        if len(free) < 2:
            continue
        rename, base = free[0], free[1]
        renamed = re.sub(r"\bx18\b", f"x{rename}", ops)
        renamed = re.sub(r"\bw18\b", f"w{rename}", renamed)
        yield int(word, 16), mnemonic, ops, f"{mnemonic} {renamed}", rename, base


# The state block (see the C side): x[31] at 0, nzcv at 248, sp at 256.
NZCV, SP = 248, 256


def body(name, insn, base, rename):
    """A function running `insn` (an assembler line) with the state at x0.
    `rename`: the register standing for x18 in this copy (18 for the word
    itself)."""
    lines = [f"{name}:"]
    lines += [
        "stp x29, x30, [sp, #-112]!",
        "stp x19, x20, [sp, #16]",
        "stp x21, x22, [sp, #32]",
        "stp x23, x24, [sp, #48]",
        "stp x25, x26, [sp, #64]",
        "stp x27, x28, [sp, #80]",
        "str x18, [sp, #96]",
        f"mov x{base}, x0",
        # The caller's sp, kept in the state, and the state's own.
        "mov x16, sp",
        f"str x16, [x{base}, #{SP + 8}]",
        f"ldr x16, [x{base}, #{SP}]",
        "mov sp, x16",
        f"ldr x16, [x{base}, #{NZCV}]",
        "msr nzcv, x16",
    ]
    # The renamed copy leaves x18 itself alone: its stand-in is x18.
    skip = {base} | ({18} if rename != 18 else set())
    for r in range(0, 29):
        if r in skip:
            continue
        src = 18 if r == rename else r
        lines.append(f"ldr x{r}, [x{base}, #{8 * src}]")
    lines.append(insn)
    for r in range(0, 29):
        if r in skip:
            continue
        dst = 18 if r == rename else r
        lines.append(f"str x{r}, [x{base}, #{8 * dst}]")
    lines += [
        "mrs x16, nzcv",
        f"str x16, [x{base}, #{NZCV}]",
        "mov x16, sp",
        f"str x16, [x{base}, #{SP}]",
        f"ldr x16, [x{base}, #{SP + 8}]",
        "mov sp, x16",
        "ldr x18, [sp, #96]",
        "ldp x19, x20, [sp, #16]",
        "ldp x21, x22, [sp, #32]",
        "ldp x23, x24, [sp, #48]",
        "ldp x25, x26, [sp, #64]",
        "ldp x27, x28, [sp, #80]",
        "ldp x29, x30, [sp], #112",
        "ret",
    ]
    return lines


def main():
    items = list(entries())
    asm = []
    table = []
    for i, (word, mnemonic, ops, renamed, rename, base) in enumerate(items):
        asm += body(f"xf_a{i}", f".inst 0x{word:08x}", base, 18)
        asm += body(f"xf_b{i}", renamed, base, rename)
        table.append(f'    {{xf_a{i}, xf_b{i}, "{mnemonic} {ops}"}},')
    decls = "\n".join(f"extern void xf_a{i}(struct state *), xf_b{i}(struct state *);" for i in range(len(items)))
    asm_text = "\n".join(f'    "{l}\\n"' for l in asm)
    template = (HERE / "x18forms.c.in").read_text()
    out = (
        template.replace("@COUNT@", str(len(items)))
        .replace("@DECLS@", decls)
        .replace("@ASM@", asm_text)
        .replace("@TABLE@", "\n".join(table))
    )
    Path(sys.argv[1]).write_text(out)
    print(f"{len(items)} instructions", file=sys.stderr)


if __name__ == "__main__":
    main()
