import re
import json
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, asdict
from enum import Enum
import idc
import ida_funcs


def rename_function(ea, new_name):
    func = ida_funcs.get_func(ea)
    if not func:
        print(f"[!] No function found at 0x{ea:X}")
        return False
    if idc.set_name(ea, new_name, idc.SN_NOWARN):
        print(f"[+] Function at 0x{ea:X} renamed to '{new_name}'")
        return True
    else:
        print(f"[!] Failed to rename function at 0x{ea:X}")
        return False

@dataclass
class TypeMember:
    kind: str  # field, property, method, const
    name: str
    signature: str
    offset: Optional[str] = None
    va: Optional[str] = None

@dataclass
class ParsedType:
    name: str
    kind: str  # class, enum, struct, interface
    dll: str
    namespace: str
    members: List[TypeMember] = None

    def __post_init__(self):
        if self.members is None:
            self.members = []

class ParseState(Enum):
    HEADER = 1
    IN_TYPE = 2
    IN_MEMBERS = 3

def parse_dump_file(content: str) -> Dict[str, List[ParsedType]]:
    lines = content.splitlines()
    result: Dict[str, List[ParsedType]] = {}
    current_dll = "unknown"
    current_ns = ""
    current_type: Optional[ParsedType] = None
    state = ParseState.HEADER

    i = 0
    while i < len(lines):
        raw_line = lines[i]
        line = raw_line.strip()

        dll_match = re.match(r'// Dll\s*:\s*(.+?)\.dll', line)
        if dll_match:
            current_dll = dll_match.group(1).strip()
            if current_dll not in result:
                result[current_dll] = []
            i += 1
            continue

        if raw_line.startswith('// Namespace:'):
            ns_part = raw_line[13:].strip()
            current_ns = ns_part if ns_part else ""
            i += 1
            continue

        if line.startswith('// Image ') or line.startswith('// Dll :') or '<Module>' in line:
            i += 1
            continue

        type_match = re.match(
            r'(public|internal|private)?\s*(sealed|abstract|static)?\s*(class|enum|struct|interface)\s+([<>\w`]+)',
            line
        )
        if type_match and state != ParseState.IN_TYPE:
            if current_type and current_type.name != '<Module>':
                result[current_dll].append(current_type)

            type_kind = type_match.group(3)
            type_name = type_match.group(4).strip()

            current_type = ParsedType(
                name=type_name,
                kind=type_kind,
                dll=current_dll,
                namespace=current_ns,
                members=[]
            )
            state = ParseState.IN_TYPE
            i += 1
            continue

        if state == ParseState.IN_TYPE and current_type:
            rva_match = re.match(r'//\s*RVA:\s*0x([0-9a-fA-F]+)\s*VA:\s*0x([0-9a-fA-F]+)', line)
            if rva_match:
                rva = '0x' + rva_match.group(1)
                va = '0x' + rva_match.group(2)
                i += 1
                while i < len(lines) and not lines[i].strip():
                    i += 1
                if i >= len(lines):
                    continue
                sig_line = lines[i].strip()
                sig_match = re.match(r'([^{]+?)\s+([^\s(]+)\s*\((.*?)\)\s*(?:\{|$)', sig_line)
                if sig_match:
                    mods_ret = sig_match.group(1).strip()
                    name = sig_match.group(2).strip()
                    params = sig_match.group(3).strip()
                    signature = f"{mods_ret} {name}({params})"
                    current_type.members.append(TypeMember(
                        kind='method',
                        name=name,
                        signature=signature,
                        offset=rva,
                        va=va
                    ))
                else:
                    print(f"[DEBUG] Failed to parse method signature at line {i+1}: {sig_line}")
                i += 1
                continue

            field_match = re.match(r'(public|private|internal)?\s*(readonly)?\s*([\w\[\]<>`]+)\s+([^\s;]+);?\s*//\s*0x([0-9a-fA-F]+)', line)
            if field_match:
                mods = ' '.join([g for g in field_match.groups()[:2] if g]).strip()
                ftype = field_match.group(3)
                fname = field_match.group(4).strip()
                offset = '0x' + field_match.group(5)
                signature = f"{mods} {ftype} {fname}" if mods else f"{ftype} {fname}"
                current_type.members.append(TypeMember(kind='field', name=fname, signature=signature, offset=offset))
                i += 1
                continue

            const_match = re.match(r'public const (\w+)\s+(\w+)\s*=\s*(\d+);?\s*//\s*0x0', line)
            if const_match and current_type.kind == 'enum':
                ename = const_match.group(2)
                value = const_match.group(3)
                signature = f"const {ename} = {value}"
                current_type.members.append(TypeMember(kind='const', name=ename, signature=signature))
                i += 1
                continue

            prop_match = re.match(r'(.+?)\s+(\w+)\s*\{\s*get;\s*(set;)?\s*\}', line)
            if prop_match:
                ptype = prop_match.group(1).strip()
                pname = prop_match.group(2)
                setter = prop_match.group(3) or ''
                signature = f"{ptype} {pname} {{ get; {setter} }}"
                current_type.members.append(TypeMember(kind='property', name=pname, signature=signature))
                i += 1
                continue

            if line == '}' or ('{' in line and 'Methods' in line):
                if current_type.name != '<Module>':
                    result[current_dll].append(current_type)
                current_type = None
                state = ParseState.HEADER
                i += 1
                continue

        i += 1

    if current_type and current_type.name != '<Module>':
        result[current_dll].append(current_type)

    return result

def main():
    with open(idaapi.ask_file(False, '*.cs', 'dump.cs from Il2cppdumper'), 'r', encoding='utf-8') as f:
        content = f.read()

    parsed = parse_dump_file(content)

    for dll, types in parsed.items():
        for t in types:
            for m in t.members:
                if m.kind == "method":
                    met_name = ""
                    namespace = t.namespace
                    if namespace:
                        met_name = namespace + "."
                    met_name += t.name+"$$"+m.name
                    print(met_name)
                    addr = int(m.offset, 16)
                    rename_function(addr, met_name)

if __name__ == "__main__":
    main()
    for _ in range(500):
        print("=" * 50)
        print("IDA Renamer by walld3v")
        print("github: walld3v")
        print("tg: wdp_closed")
        print("https://github.com/WallD3v/IDARenamer")
        print("=" * 50)
