"""Verify one digest-bound node115 db_home source-reference coordinate.

Static parsing and binutils only. No captured program is executed. recover()
intentionally omits identity checks for counterfactual operand controls;
analyse() is the authenticated public entry point.
"""
from pathlib import Path
import argparse
import hashlib
import json
import re
import struct
import subprocess

TARGET = Path('artifacts/node/115/hl-node')
SHA256 = 'a6e2897cd051213d004802deca416e8eca62b7a8278fa39f249e98c3867b5301'
SIZE = 105896032
PC = 0x4469b64
LOCATION = 0x648b960
START, END = 0x44699c0, 0x4469bd8
RELA_OFFSET = 0xbc1a8
SOURCE = b'db/src/db_home.rs'


def recover(data):
    """Recover selected operands; reject changed coordinates, not target identity."""
    def read(fmt, offset):
        if offset < 0 or offset + struct.calcsize(fmt) > len(data):
            raise ValueError('truncated structure')
        return struct.unpack_from(fmt, data, offset)

    if data[:6] != b'\x7fELF\x02\x01':
        raise ValueError('ELF64 little-endian required')
    if read('<H', 18)[0] != 62:
        raise ValueError('x86-64 required')
    phoff, shoff = read('<QQ', 32)
    phsize, phnum, shsize, shnum = read('<HHHH', 54)
    if phsize != 56 or shsize != 64 or not phnum or not shnum:
        raise ValueError('unsupported ELF table layout')
    segments = []
    for index in range(phnum):
        kind, flags, off, va, _, filesz, memsz, _ = read('<IIQQQQQQ', phoff + index * phsize)
        if kind == 1:
            if filesz > memsz or off + filesz > len(data):
                raise ValueError('invalid file-backed segment')
            segments.append((off, va, filesz, flags))

    def mapped(va, size, executable=False):
        hits = [off + va - start for off, start, length, flags in segments
                if start <= va and va + size <= start + length
                and (not executable or flags & 1)]
        if len(hits) != 1:
            raise ValueError('ambiguous or missing file mapping')
        return hits[0]

    instruction_offset = mapped(PC, 7, executable=True)
    instruction = data[instruction_offset:instruction_offset + 7]
    if instruction[:3] != bytes.fromhex('488d15'):
        raise ValueError('selected LEA opcode')
    destination = PC + 7 + struct.unpack_from('<i', instruction, 3)[0]
    if destination != LOCATION:
        raise ValueError('selected LEA displacement')
    relocation_tables = []
    for index in range(shnum):
        fields = read('<IIQQQQIIQQ', shoff + index * shsize)
        _, kind, _, _, offset, size, _, _, _, entsize = fields
        if kind == 4:
            if entsize != 24 or size % entsize or offset + size > len(data):
                raise ValueError('invalid RELA table')
            relocation_tables.append((offset, size))
    if sum(start <= RELA_OFFSET and RELA_OFFSET + 24 <= start + size
           and (RELA_OFFSET - start) % 24 == 0
           for start, size in relocation_tables) != 1:
        raise ValueError('selected relocation not in one RELA table')
    matches = []
    for offset, size in relocation_tables:
        for entry in range(offset, offset + size, 24):
            address, info, addend = read('<QQq', entry)
            if address == LOCATION:
                matches.append((entry, info, addend))
    if len(matches) != 1 or matches[0][:2] != (RELA_OFFSET, 8):
        raise ValueError('selected RELATIVE relocation missing, duplicate or changed')
    source_va = matches[0][2]
    if source_va != 0x448051:
        raise ValueError('source relocation addend')
    location_offset = mapped(LOCATION, 24)
    pointer, length, line, column = read('<QQII', location_offset)
    if (pointer, length, line, column) != (0, len(SOURCE), 85, 13):
        raise ValueError('source Location fields')
    source_offset = mapped(source_va, length)
    if data[source_offset:source_offset + length] != SOURCE:
        raise ValueError('source path bytes')
    return {'instruction_va': hex(PC), 'instruction_file_offset': hex(instruction_offset),
            'instruction_bytes': instruction.hex(), 'location_va': hex(LOCATION),
            'location_file_offset': hex(location_offset), 'relocation_file_offset': hex(RELA_OFFSET),
            'relocation_info': 8, 'source_va': hex(source_va),
            'source_file_offset': hex(source_offset), 'source_path': SOURCE.decode(),
            'line': line, 'column': column}


def analyse(path=TARGET):
    path = Path(path)
    data = path.read_bytes()
    if len(data) != SIZE or hashlib.sha256(data).hexdigest() != SHA256:
        raise ValueError('target size/SHA-256 mismatch')
    result = recover(data)
    commands = [['readelf', '--debug-dump=frames', str(path)],
                ['objdump', '-d', '-M', 'intel', '--start-address=' + hex(START),
                 '--stop-address=' + hex(END), str(path)]]
    frames = subprocess.check_output(commands[0], text=True)
    extents = [(int(a, 16), int(b, 16)) for a, b in
               re.findall(r'\bFDE\b[^\n]*\bpc=([0-9a-fA-F]+)\.\.([0-9a-fA-F]+)', frames)]
    owners = [(a, b) for a, b in extents if a <= PC < b]
    if owners != [(START, END)]:
        raise ValueError('missing, duplicate or changed containing FDE')
    native = subprocess.check_output(commands[1], text=True)
    hits = re.findall(r'^\s*4469b64:\s*((?:[0-9a-f]{2}\s+)+)\s*(.*)$', native, re.M)
    if len(hits) != 1 or bytes.fromhex(hits[0][0]).hex() != result['instruction_bytes']:
        raise ValueError('native instruction boundary/raw bytes')
    if not re.search(r'\blea\b.*\b648b960\b', hits[0][1]):
        raise ValueError('native selected reference')
    result.update({'target_size': len(data), 'target_sha256': SHA256,
                   'source_revision': '8fd8db680ec4bfef40996e5616bce3d5156d0b86',
                   'fde_start': hex(START), 'fde_end': hex(END), 'fde_bytes': END - START,
                   'commands': commands, 'native_reference': hits[0][1],
                   'versions': {name: subprocess.check_output([name, '--version'], text=True).splitlines()[0]
                                for name in ('readelf', 'objdump')},
                   'limitations': 'One static source-reference coordinate; not semantics, complete xrefs, storage schema, runtime equivalence or a completion gate.'})
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--target', type=Path, default=TARGET)
    parser.add_argument('--output', type=Path)
    args = parser.parse_args()
    result = analyse(args.target)
    text = json.dumps(result, indent=2) + '\n'
    if args.output:
        args.output.write_text(text)
    else:
        print(text, end='')


if __name__ == '__main__':
    main()
