#!/usr/bin/env python3
"""把 Mach-O 展平成 RWX 可写镜像，并导出符号偏移（基址归一化为 0）
用法: flatten_macho.py <macho> <out.bin> <out_syms.txt>
"""
import struct
import sys


def main():
    src, out_bin, out_syms = sys.argv[1], sys.argv[2], sys.argv[3]
    d = open(src, "rb").read()
    magic = struct.unpack("<I", d[:4])[0]
    if magic != 0xFEEDFACF:
        raise SystemExit("not thin 64-bit mach-o: %08x" % magic)
    cputype, cpusub, filetype, ncmds = struct.unpack("<iiII", d[4:20])
    print("cputype=%08x sub=%08x filetype=%d ncmds=%d" % (cputype & 0xffffffff, cpusub & 0xffffffff, filetype, ncmds))

    off = 32
    sections = []
    min_vm = None
    symtab = None
    for _ in range(ncmds):
        cmd, cmdsize = struct.unpack("<II", d[off:off + 8])
        if cmd == 0x19:  # LC_SEGMENT_64
            segname = d[off + 8:off + 24].split(b"\0")[0].decode("ascii", "replace")
            vmaddr, vmsize, fileoff, filesize = struct.unpack("<QQQQ", d[off + 24:off + 56])
            nsects = struct.unpack("<I", d[off + 64:off + 68])[0]
            if filesize and (min_vm is None or vmaddr < min_vm):
                min_vm = vmaddr
            s_off = off + 72
            for _ in range(nsects):
                sectname = d[s_off:s_off + 16].split(b"\0")[0].decode("ascii", "replace")
                addr, size = struct.unpack("<QQ", d[s_off + 32:s_off + 48])
                foff = struct.unpack("<I", d[s_off + 48:s_off + 52])[0]
                sflags = struct.unpack("<I", d[s_off + 64:s_off + 68])[0]
                sections.append((segname, sectname, addr, size, foff, sflags))
                s_off += 80
        elif cmd == 0x2:  # LC_SYMTAB
            symoff, nsyms, stroff, strsize = struct.unpack("<IIII", d[off + 8:off + 24])
            symtab = (symoff, nsyms, stroff, strsize)
        off += cmdsize

    if min_vm is None:
        raise SystemExit("no file-backed segments")

    end = max(addr + size for (_s, _n, addr, size, _f, _fl) in sections)
    img = bytearray(end - min_vm)
    for (seg, sect, addr, size, foff, fl) in sections:
        if size == 0:
            continue
        if (fl & 0xFF) in (0x1, 0xC):  # zerofill
            continue
        dst = addr - min_vm
        avail = max(0, len(d) - foff)
        size = min(size, avail)
        img[dst:dst + size] = d[foff:foff + size]

    open(out_bin, "wb").write(bytes(img))
    print("flat image %d bytes (base vmaddr=0x%x)" % (len(img), min_vm))

    lines = ["# symbol offsets (add to RWX base)", "IMAGE_SIZE 0x%x" % len(img)]
    if symtab:
        symoff, nsyms, stroff, strsize = symtab
        strtab = d[stroff:stroff + strsize]
        for i in range(nsyms):
            p = symoff + i * 16
            if p + 16 > len(d):
                break
            n_strx, n_type, n_sect, n_desc = struct.unpack("<IBBH", d[p:p + 8])
            n_value = struct.unpack("<Q", d[p + 8:p + 16])[0]
            if n_value == 0:
                continue
            if not (n_type & 0x01):  # 只看外部可见
                continue
            kind = n_type & 0x0E
            if kind not in (0x0E, 0x0):
                continue
            name = strtab[n_strx:].split(b"\0")[0].decode("ascii", "replace")
            if not name:
                continue
            lines.append("SYM %s 0x%x" % (name, n_value - min_vm))

    open(out_syms, "w").write("\n".join(lines) + "\n")
    print("symbols written:", out_syms, "count", len(lines) - 2)


if __name__ == "__main__":
    main()
