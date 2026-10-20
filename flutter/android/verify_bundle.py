#!/usr/bin/env python3
"""Reject unsigned bundles or native libraries incompatible with 16 KB pages."""
import struct
import sys
import zipfile

with zipfile.ZipFile(sys.argv[1]) as bundle:
    assert any(n.startswith('META-INF/') and n.endswith(('.RSA', '.EC', '.DSA'))
               for n in bundle.namelist()), 'Missing signing certificate'
    libraries = [n for n in bundle.namelist() if n.endswith('.so')]
    assert libraries, 'No native libraries in bundle'
    for name in libraries:
        data = bundle.read(name)
        assert data[:6] == b'\x7fELF\x02\x01', f'{name}: expected little-endian ELF64'
        offset = struct.unpack_from('<Q', data, 32)[0]
        size, count = struct.unpack_from('<HH', data, 54)
        for i in range(count):
            header = offset + i * size
            if struct.unpack_from('<I', data, header)[0] == 1:  # PT_LOAD
                alignment = struct.unpack_from('<Q', data, header + 48)[0]
                assert alignment >= 16384, f'{name}: LOAD alignment {alignment}'
        print(f'16 KB compatible: {name}')
