import os
import re
from pathlib import Path
from collections import Counter

BIN_DIR = Path('/usr/bin')
OUTPUT = Path('src/known_good/operating_system/usr_bin_binaries.yar')

HEADER = (
    'include "../../private/executables/native/elf.yar"\n'
)

MIN_LEN = 8
MAX_STRINGS = 3
MAX_STRING_LEN = 100


def extract_strings(data, min_len=MIN_LEN):
    pattern = rb'[\x20-\x7E]{%d,}' % min_len
    return [m.group().decode('ascii', errors='ignore') for m in re.finditer(pattern, data)]


files = []
for f in sorted(BIN_DIR.iterdir()):
    if f.is_symlink() or not f.is_file():
        continue
    with open(f, 'rb') as fd:
        data = fd.read()
    if data[:4] != b'\x7fELF':
        continue
    strings = extract_strings(data)
    files.append((f, strings))

TOTAL_FILES = len(files)
HEADER += f"// Auto-generated from {TOTAL_FILES} ELF binaries in {BIN_DIR}\n"

# Count string occurrences across all files
counter = Counter()
for _, strs in files:
    counter.update(strs)

rules = []
for path, strs in files:
    unique = [s for s in strs if counter[s] == 1]
    unique = sorted(unique, key=len, reverse=True)
    if unique:
        selected = unique[:MAX_STRINGS]
    else:
        selected = sorted(strs, key=lambda s: (counter[s], -len(s)))[:MAX_STRINGS]
    rule_name = re.sub(r'[^A-Za-z0-9_]', '_', path.name)
    if not re.match(r'^[A-Za-z_]', rule_name):
        rule_name = '_' + rule_name
    rule_name = f"Known_Good_Linux_{rule_name}_Binary"

    meta = f"""        description = \"Track {path} binary by unique strings\"
        author = \"AutoGen\"
        date = \"2025-05-30\"
        version = \"1.0\"
        file_type = \"ELF\"
        tlp = \"WHITE\"
        scope = \"tracking\"
        path = \"{path}\"
    """.rstrip()

    strings_block_lines = []
    for i, s in enumerate(selected):
        freq = counter[s]
        comment = f" // found in {freq}/{TOTAL_FILES} binaries"
        escaped = s[:MAX_STRING_LEN].replace('\\', '\\\\').replace('"', '\\"')
        strings_block_lines.append(f"        $s{i+1} = \"{escaped}\" ascii{comment}")
    strings_block = "\n".join(strings_block_lines)

    rule = f"""rule {rule_name} {{
    meta:
{meta}

    strings:
{strings_block}

    condition:
        ELF_Structure and all of them
}}
"""
    rules.append(rule)

with open(OUTPUT, 'w') as out:
    out.write(HEADER)
    out.write("\n".join(rules))
