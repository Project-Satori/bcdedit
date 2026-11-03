#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
bcdtool v2 — offline BCD store editor backed by python-hivex/libhivex.

This is a practical BCDEdit-compatible subset, not Microsoft's bcdedit.exe.
Unknown element payloads are preserved. Numeric element IDs are first-class:
  custom:54000001, 0x54000001, 54000001

Safety model:
  * Mutations happen on a sibling temporary copy.
  * The hive is committed and closed before atomic replacement.
  * The original is not replaced if parsing or mutation fails.
  * Device descriptors remain opaque unless supplied as raw:HEX.

Compatibility:
  * Some python-hivex builds expose no Hivex.close(); safe_close() handles both.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import struct
import sys
import tempfile
import uuid
from pathlib import Path
from typing import Callable

try:
    import hivex
except ImportError:
    hivex = None


BOOTMGR = "{9DEA862C-5CDD-4E70-ACC1-F32B344D4795}"
FWBOOTMGR = "{A5A30FA2-3D06-4E9F-B5F4-A01DF9D1FCBA}"

REG_BINARY = 3
REG_DWORD = 4
REG_SZ = 1
REG_MULTI_SZ = 7

BUILTIN_ELEMENTS: dict[int, str] = {
    # Library
    0x11000001: "device",
    0x12000002: "path",
    0x12000004: "description",
    0x12000005: "locale",
    0x14000006: "inherit",
    0x15000007: "truncatememory",
    0x14000008: "recoversequence",
    0x16000009: "recoveryenabled",
    0x16000010: "bootdebug",
    0x15000011: "debugtype",
    0x15000012: "debugaddress",
    0x15000013: "debugport",
    0x15000014: "baudrate",
    0x15000015: "channel",
    0x12000016: "targetname",
    0x16000017: "noumex",
    0x15000018: "debugstart",
    0x12000019: "busparams",
    0x1500001A: "hostip",
    0x1500001B: "port",
    0x1600001C: "dhcp",
    0x1200001D: "key",
    0x16000020: "bootems",
    0x15000022: "emsport",
    0x15000023: "emsbaudrate",
    0x12000030: "loadoptions",
    0x16000040: "advancedoptions",
    0x16000041: "optionsedit",
    # Boot manager
    0x24000001: "displayorder",
    0x24000002: "bootsequence",
    0x23000003: "default",
    0x25000004: "timeout",
    0x26000005: "resume",
    0x23000006: "resumeobject",
    0x24000010: "toolsdisplayorder",
    0x26000020: "displaybootmenu",
    0x26000021: "noerrordisplay",
    0x21000022: "bcddevice",
    0x22000023: "bcdfilepath",
    0x26000028: "processcustomactionsfirst",
    0x27000030: "customactions",
    0x26000031: "persistbootsequence",
    # Device / ramdisk
    0x35000001: "ramdiskimageoffset",
    0x35000002: "ramdiskftpclientport",
    0x31000003: "ramdisksdidevice",
    0x32000004: "ramdisksdipath",
    0x35000005: "ramdiskimagelength",
    # OS loader
    0x21000001: "osdevice",
    0x22000002: "systemroot",
    0x23000003: "resumeobject",
    0x26000010: "detecthal",
    0x22000011: "kernel",
    0x22000012: "hal",
    0x25000020: "nx",
    0x25000021: "pae",
    0x26000022: "winpe",
    0x26000024: "nocrashautoreboot",
    0x26000025: "lastknowngood",
    0x26000027: "testsigning",
    0x25000031: "removememory",
    0x25000032: "increaseuserva",
    0x26000040: "vga",
    0x26000041: "quietboot",
    0x26000060: "onecpu",
    0x25000061: "numproc",
    0x26000062: "maxproc",
    0x25000080: "safeboot",
    0x26000081: "safebootalternateshell",
    0x26000090: "bootlog",
    0x26000091: "sos",
    0x260000A0: "debug",
    0x260000A1: "halbreakpoint",
    0x260000A2: "useplatformclock",
    0x250000C2: "bootmenupolicy",
    0x250000F0: "hypervisorlaunchtype",
    0x220000F1: "hypervisorpath",
    # Common OEM/custom entries
    0x54000001: "custom:54000001",
    0x54000002: "custom:54000002",
    0x26000201: "custom:26000201",
    0x26000206: "custom:26000206",
    0x250000E0: "custom:250000e0",
    0x25000510: "custom:25000510",
    0x25000511: "custom:25000511",
    0x25000AAA: "custom:25000aaa",
    0x26000512: "custom:26000512",
    0x15000079: "custom:15000079",
    0x1500007D: "custom:1500007d",
    0x16000050: "custom:16000050",
    0x16000068: "custom:16000068",
    0x16000069: "custom:16000069",
    0x1600006A: "custom:1600006a",
    0x16000072: "custom:16000072",
    0x1600007A: "custom:1600007a",
}

APP_ELEMENTS = {
    "bootmgr": {
        0x24000001: "displayorder", 0x24000002: "bootsequence",
        0x23000003: "default", 0x25000004: "timeout",
        0x26000005: "resume", 0x23000006: "resumeobject",
        0x24000010: "toolsdisplayorder", 0x26000020: "displaybootmenu",
        0x26000021: "noerrordisplay", 0x27000030: "customactions",
    },
    "fwbootmgr": {
        0x24000001: "displayorder", 0x24000002: "bootsequence",
        0x23000003: "default", 0x25000004: "timeout",
        0x24000010: "toolsdisplayorder",
    },
    "osloader": {
        0x21000001: "osdevice", 0x22000002: "systemroot",
        0x23000003: "resumeobject", 0x26000010: "detecthal",
        0x22000011: "kernel", 0x22000012: "hal",
        0x25000020: "nx", 0x25000021: "pae", 0x26000022: "winpe",
        0x26000024: "nocrashautoreboot", 0x26000027: "testsigning",
        0x25000031: "removememory", 0x25000032: "increaseuserva",
        0x26000040: "vga", 0x26000041: "quietboot",
        0x26000060: "onecpu", 0x25000061: "numproc",
        0x26000062: "maxproc", 0x25000080: "safeboot",
        0x26000081: "safebootalternateshell", 0x26000090: "bootlog",
        0x26000091: "sos", 0x260000A0: "debug",
        0x260000A1: "halbreakpoint", 0x260000A2: "useplatformclock",
        0x250000C2: "bootmenupolicy", 0x250000F0: "hypervisorlaunchtype",
        0x220000F1: "hypervisorpath",
    },
    "ramdiskoptions": {
        0x31000001: "ramdiskimageoffset",
        0x35000002: "ramdiskftpclientport",
        0x31000003: "ramdisksdidevice",
        0x32000004: "ramdisksdipath",
        0x35000005: "ramdiskimagelength",
    },
    "resume": {
        0x21000001: "filedevice", 0x22000002: "filepath",
        0x26000003: "customsettings", 0x26000004: "pae",
        0x21000005: "associatedosdevice", 0x26000006: "debugoptionenabled",
    },
}

OBJECT_GUIDS = {
    "9DEA862C-5CDD-4E70-ACC1-F32B344D4795": "bootmgr",
    "A5A30FA2-3D06-4E9F-B5F4-A01DF9D1FCBA": "fwbootmgr",
    "0CE4991B-E6B3-4B16-B23C-5E0D9250E5D9": "emssettings",
    "4636856E-540F-4170-A130-A84776F4C654": "dbgsettings",
    "6EFB52BF-1766-41DB-A6B3-0EE5EFF72BD7": "bootloadersettings",
    "7EA2E1AC-2E61-4728-AAA3-896D9D0A9F0E": "globalsettings",
    "AE5534E0-A924-466C-B836-758539A3EE3A": "ramdiskoptions",
    "1AFA9C49-16AB-4A5C-4A90-212802DA9460": "resumeloadersettings",
    "B2721D73-1DB4-4C62-BF78-C548A880142D": "memdiag",
    "FA926493-6F1C-4193-A414-58F0B2456D1E": "current",
    "1CAE1EB7-A0DF-4D4D-9851-4860E34EF535": "default",
}

GUID_RE = re.compile(
    r"\{?[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
    r"[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\}?"
)


class BcdError(Exception):
    pass


def die(message: str):
    raise BcdError(message)


def safe_close(h):
    """Close a Hivex handle if the binding exposes close().

    Some python-hivex builds have no Hivex.close(); the C handle is then
    released by the object's destructor. We must never fail on close().
    """
    if h is None:
        return
    close_fn = getattr(h, "close", None)
    if close_fn is None:
        return
    try:
        close_fn()
    except Exception:
        pass


def norm_guid(value: str) -> str:
    s = value.strip().strip("{}")
    try:
        return "{" + str(uuid.UUID(s)).upper() + "}"
    except (ValueError, AttributeError, TypeError):
        die(f"Invalid identifier: {value}")


def guid_bytes(value: str) -> bytes:
    return uuid.UUID(norm_guid(value).strip("{}")).bytes_le


def parse_type_token(token: str, object_alias: str | None = None) -> int:
    s = token.strip().lower()
    if s.startswith("custom:"):
        raw = s.split(":", 1)[1]
        try:
            value = int(raw, 16)
        except ValueError:
            die(f"Invalid custom BCD element type: {token}")
        if not 0 <= value <= 0xFFFFFFFF:
            die(f"BCD element type out of range: {token}")
        return value
    if s.startswith("0x"):
        try:
            value = int(s, 16)
        except ValueError:
            die(f"Invalid BCD element type: {token}")
        if not 0 <= value <= 0xFFFFFFFF:
            die(f"BCD element type out of range: {token}")
        return value
    if re.fullmatch(r"[0-9a-f]{8}", s):
        return int(s, 16)
    if s in NAME_TO_TYPE:
        return NAME_TO_TYPE[s]
    if object_alias:
        t = APP_ELEMENTS.get(object_alias, {})
        for typ, name in t.items():
            if name.lower() == s:
                return typ
    die(f"Unknown BCD element: {token}. Use a friendly name, custom:XXXXXXXX or 0xXXXXXXXX.")


NAME_TO_TYPE: dict[str, int] = {}
TYPE_TO_NAME: dict[int, str] = {}


def load_symbols(script_dir: Path):
    for typ, name in BUILTIN_ELEMENTS.items():
        TYPE_TO_NAME[typ] = name
        if not name.startswith("custom:"):
            NAME_TO_TYPE[name.lower()] = typ

    path = script_dir / "known_symbols.json"
    if path.exists():
        try:
            doc = json.loads(path.read_text(encoding="utf-8"))
            for group in doc.get("entryNames", []):
                for hx, pair in group.get("names", {}).items():
                    typ = int(hx, 16)
                    symbol = pair[0] if len(pair) > 0 else ""
                    friendly = pair[1] if len(pair) > 1 else ""
                    if friendly:
                        NAME_TO_TYPE[friendly.lower()] = typ
                        TYPE_TO_NAME.setdefault(typ, friendly)
                    if symbol:
                        NAME_TO_TYPE[symbol.lower()] = typ
                        TYPE_TO_NAME.setdefault(typ, symbol)
            for guid, info in doc.get("objectGuids", {}).items():
                name = info.get("name")
                if name:
                    OBJECT_GUIDS[guid.upper()] = name
        except Exception as exc:
            print(f"bcdtool: warning: cannot load {path.name}: {exc}", file=sys.stderr)

    NAME_TO_TYPE["customactions"] = 0x27000030
    TYPE_TO_NAME[0x27000030] = "customactions"


def _hive_error_call(fn, *args):
    try:
        return fn(*args)
    except RuntimeError:
        return 0


def node_name(h, node) -> str:
    return h.node_name(node)


def children(h, node) -> list:
    return h.node_children(node)


def child(h, node, name: str, required: bool = True):
    found = _hive_error_call(h.node_get_child, node, name)
    if not found and required:
        die(f"Registry key not found: {name}")
    return found


def get_value(h, node, name: str, required: bool = True):
    vh = _hive_error_call(h.node_get_value, node, name)
    if not vh:
        if required:
            die(f"Registry value not found: {name}")
        return None
    return h.value_value(vh)


def raw_value(h, node, name="Element"):
    item = get_value(h, node, name, required=False)
    if item is None:
        return None
    _regtype, data = item
    if isinstance(data, bytes):
        return data
    if isinstance(data, str):
        return data.encode("latin1")
    return bytes(data)


def set_reg(h, node, name: str, regtype: int, data):
    h.node_set_value(node, {"key": name, "t": regtype, "value": data})


def object_type(h, obj) -> int:
    desc = child(h, obj, "Description", required=False)
    if not desc:
        return 0
    item = get_value(h, desc, "Type", required=False)
    if item is None:
        return 0
    _regtype, data = item
    if isinstance(data, bytes):
        return int.from_bytes(data[:4].ljust(4, b"\0"), "little")
    return int(data)


def object_alias(guid: str) -> str | None:
    return OBJECT_GUIDS.get(norm_guid(guid).strip("{}"))


def objects_node(h):
    return child(h, h.root(), "Objects")


def object_elements(h, obj):
    return child(h, obj, "Elements", required=False)


def all_objects(h) -> dict[str, int]:
    root = objects_node(h)
    result = {}
    for n in children(h, root):
        try:
            g = norm_guid(node_name(h, n))
        except BcdError:
            continue
        result[g] = n
    return result


def resolve_id(h, objects, ident: str) -> str:
    s = ident.strip()
    low = s.lower().strip("{}")
    if low == "bootmgr":
        return BOOTMGR
    if low == "fwbootmgr":
        return FWBOOTMGR
    if low == "default":
        bm = objects.get(BOOTMGR)
        if bm:
            els = object_elements(h, bm)
            if els:
                en = child(h, els, "23000003", required=False)
                raw = raw_value(h, en) if en else None
                if raw:
                    try:
                        return decode_object(raw)
                    except Exception:
                        pass
        die("Cannot resolve {default}: Boot Manager default element is missing or malformed.")
    if low == "current":
        for g, name in OBJECT_GUIDS.items():
            if name == "current":
                return "{" + g + "}"
    if s.startswith("{") or re.fullmatch(r"[0-9a-fA-F-]{36}", s):
        return norm_guid(s)
    for g, name in OBJECT_GUIDS.items():
        if name and name.casefold() == low:
            return "{" + g + "}"
    die(f"Unknown identifier: {ident}")


def decode_object(data: bytes) -> str:
    if len(data) == 16:
        return "{" + str(uuid.UUID(bytes_le=data)).upper() + "}"
    text = decode_utf16_text(data)
    match = GUID_RE.search(text)
    if match:
        return norm_guid(match.group(0))
    raise ValueError("not a GUID object payload")


def decode_utf16_text(data: bytes) -> str:
    return data.decode("utf-16le", errors="strict").rstrip("\x00")


def decode_object_list(data: bytes) -> tuple[list[str], str]:
    try:
        text = data.decode("utf-16le").rstrip("\x00")
        candidates = [x.strip() for x in text.split("\x00") if x.strip()]
        if candidates and all(GUID_RE.fullmatch(x) for x in candidates):
            return [norm_guid(x) for x in candidates], "utf16"
        found = GUID_RE.findall(text)
        residue = GUID_RE.sub("", text).replace("\x00", "").strip()
        if found and not residue:
            return [norm_guid(x) for x in found], "utf16"
    except (UnicodeDecodeError, ValueError):
        pass

    if len(data) % 16:
        raise ValueError(f"ObjectList payload length {len(data)} is neither valid UTF-16 GUID text nor a multiple of 16")
    return [
        "{" + str(uuid.UUID(bytes_le=data[i:i + 16])).upper() + "}"
        for i in range(0, len(data), 16)
    ], "binary"


def encode_object_list(items: list[str], encoding: str = "binary") -> bytes:
    ids = [norm_guid(x) for x in items]
    if encoding == "utf16":
        return ("\x00".join(ids) + "\x00\x00").encode("utf-16le")
    return b"".join(guid_bytes(x) for x in ids)


def decode_integer_list(data: bytes) -> list[int]:
    if len(data) % 8:
        raise ValueError(f"IntegerList payload length {len(data)} is not divisible by 8")
    return [struct.unpack_from("<Q", data, i)[0] for i in range(0, len(data), 8)]


def format_data(typ: int, data: bytes) -> str:
    fmt = (typ >> 24) & 0xF
    if fmt == 1:
        return "raw:" + data.hex()
    if fmt == 2:
        try:
            return decode_utf16_text(data)
        except UnicodeDecodeError:
            return "hex:" + data.hex()
    if fmt == 3:
        try:
            return decode_object(data)
        except Exception:
            return "hex:" + data.hex()
    if fmt == 4:
        try:
            values, _encoding = decode_object_list(data)
            return ", ".join(values)
        except Exception:
            return "hex:" + data.hex()
    if fmt == 5:
        if len(data) < 8:
            return "hex:" + data.hex()
        return hex(struct.unpack_from("<Q", data)[0])
    if fmt == 6:
        return "Yes" if data and data[0] else "No"
    if fmt == 7:
        try:
            return ", ".join(hex(x) for x in decode_integer_list(data))
        except ValueError:
            return "hex:" + data.hex()
    if fmt == 8:
        return "hex:" + data.hex()
    return "hex:" + data.hex()


def object_dump(h, guid: str, obj, verbose=False):
    typ = object_type(h, obj)
    alias = object_alias(guid)
    title = alias or (f"Object Type {typ:#010x}" if typ else "Object")
    print(f"\n{title}\n----------------")
    print(f"identifier              {guid if verbose or not alias else '{' + alias + '}'}")
    els = object_elements(h, obj)
    if not els:
        return
    for en in sorted(children(h, els), key=lambda n: node_name(h, n)):
        key = node_name(h, en)
        try:
            element_type = int(key, 16)
        except ValueError:
            continue
        data = raw_value(h, en)
        if data is None:
            continue
        name = TYPE_TO_NAME.get(element_type, f"custom:{element_type:08x}")
        shown = format_data(element_type, data)
        label = f"{name}<{key}>" if verbose else name
        print(f"{label:<28}{shown}")


def object_kind(typ: int) -> tuple[int, int, int]:
    return ((typ >> 28) & 0xF, (typ >> 20) & 0xF, typ & 0xFFFFF)


def enum_objects(h, selector: str, verbose=False):
    objects = all_objects(h)
    selected: dict[str, int] = {}
    if selector == "active":
        selected[BOOTMGR] = objects.get(BOOTMGR)
        bm = objects.get(BOOTMGR)
        if bm:
            els = object_elements(h, bm)
            if els:
                for typ in (0x23000003, 0x24000001, 0x24000002, 0x24000010):
                    en = child(h, els, f"{typ:08X}", required=False)
                    raw = raw_value(h, en) if en else None
                    if not raw:
                        continue
                    try:
                        ids, _enc = decode_object_list(raw) if ((typ >> 24) & 0xF) == 4 else ([decode_object(raw)], "auto")
                    except Exception:
                        continue
                    for ident in ids:
                        if ident in objects:
                            selected[ident] = objects[ident]
        selected = {k: v for k, v in selected.items() if v}
    else:
        for guid, node in objects.items():
            typ = object_type(h, node)
            kind = object_kind(typ)
            alias = object_alias(guid)
            if selector == "all":
                selected[guid] = node
            elif selector == "firmware" and kind[0] == 1 and kind[1] == 1:
                selected[guid] = node
            elif selector == "bootmgr" and alias in ("bootmgr", "fwbootmgr"):
                selected[guid] = node
            elif selector == "osloader" and kind == (1, 2, 3):
                selected[guid] = node
            elif selector == "resume" and kind == (1, 2, 4):
                selected[guid] = node
            elif selector == "inherit" and kind[0] == 2:
                selected[guid] = node
    for guid, node in sorted(selected.items()):
        object_dump(h, guid, node, verbose)


def parse_element_value(h, obj, typ: int, value: str, existing_data: bytes | None = None) -> bytes:
    fmt = (typ >> 24) & 0xF
    if fmt == 1:
        if not value.lower().startswith("raw:"):
            die("Device elements are opaque in this build; use raw:HEX to supply an exact descriptor.")
        try:
            return bytes.fromhex(value[4:])
        except ValueError:
            die("Invalid raw device hex payload.")
    if fmt == 2:
        return value.encode("utf-16le") + b"\x00\x00"
    if fmt == 3:
        ident = resolve_id(h, all_objects(h), value)
        if existing_data is not None:
            try:
                decode_object(existing_data)
                if len(existing_data) != 16:
                    return (ident + "\x00").encode("utf-16le")
            except Exception:
                pass
        return guid_bytes(ident)
    if fmt == 4:
        items = [x.strip() for x in value.split(",") if x.strip()]
        encoding = "utf16"
        if existing_data is not None:
            try:
                _old, encoding = decode_object_list(existing_data)
            except Exception:
                pass
        return encode_object_list([resolve_id(h, all_objects(h), x) for x in items], encoding)
    if fmt == 5:
        try:
            n = int(value, 0)
        except ValueError:
            die(f"Expected integer for element type 0x{typ:08X}: {value}")
        if not 0 <= n <= 0xFFFFFFFFFFFFFFFF:
            die("Integer must fit in unsigned 64-bit range.")
        return struct.pack("<Q", n)
    if fmt == 6:
        parsed = {
            "yes": 1, "true": 1, "on": 1, "1": 1,
            "no": 0, "false": 0, "off": 0, "0": 0,
        }.get(value.lower())
        if parsed is None:
            die("Expected on/off, yes/no, true/false or 1/0.")
        return bytes([parsed])
    if fmt == 7:
        parts = [x.strip() for x in value.split(",") if x.strip()]
        try:
            nums = [int(x, 0) for x in parts]
        except ValueError:
            die("IntegerList values must be comma-separated integers.")
        if any(n < 0 or n > 0xFFFFFFFFFFFFFFFF for n in nums):
            die("IntegerList items must fit in unsigned 64-bit range.")
        return b"".join(struct.pack("<Q", n) for n in nums)
    if fmt == 8:
        if not value.lower().startswith("hex:"):
            die("Binary elements require hex:HEX.")
        try:
            return bytes.fromhex(value[4:])
        except ValueError:
            die("Invalid binary hex payload.")
    die(f"Unsupported BCD element format {fmt} for type 0x{typ:08X}.")


def mutate_store(path: str | Path, operation: Callable):
    path = Path(path).expanduser().resolve()
    if not path.is_file():
        die(f"BCD store does not exist: {path}")
    if hivex is None:
        die("Python hivex bindings missing. Install libhivex0 and python3-hivex.")
    parent = path.parent
    if not os.access(parent, os.W_OK):
        die(
            f"Cannot create a sibling temporary file in {parent} (directory not writable). "
            "Mount the ESP read-write and run as a user with directory write permission."
        )
    fd, tmp = tempfile.mkstemp(prefix=path.name + ".bcdtool.", dir=str(parent))
    os.close(fd)
    hive = None
    try:
        shutil.copy2(path, tmp)
        hive = hivex.Hivex(tmp, write=True)
        try:
            operation(hive)
            hive.commit(None)
        finally:
            safe_close(hive)
            hive = None
        os.replace(tmp, path)
    except PermissionError as exc:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        die(
            f"Permission denied while creating/committing/replacing the BCD store: {exc}. "
            "The parent directory must be writable; chmod on the BCD file alone is insufficient."
        )
    except Exception:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def write_element(h, ident: str, typ: int, data: bytes):
    obj = child(h, objects_node(h), ident)
    els = child(h, obj, "Elements", required=False)
    if not els:
        els = h.node_add_child(obj, "Elements")
    key = f"{typ:08X}"
    en = child(h, els, key, required=False)
    if not en:
        en = h.node_add_child(els, key)
    set_reg(h, en, "Element", REG_BINARY, data)


def delete_element(h, ident: str, typ: int):
    obj = child(h, objects_node(h), ident)
    els = child(h, obj, "Elements")
    en = child(h, els, f"{typ:08X}")
    h.node_delete_child(en)


def clone_node(h, src, dst):
    values = []
    for vh in h.node_values(src):
        key = h.value_key(vh)
        regtype, data = h.value_value(vh)
        values.append({"key": key, "t": regtype, "value": data})
    if values:
        h.node_set_values(dst, values)
    for sub in children(h, src):
        new_child = h.node_add_child(dst, node_name(h, sub))
        clone_node(h, sub, new_child)


def set_description(h, obj, description: str):
    els = child(h, obj, "Elements", required=False)
    if not els:
        els = h.node_add_child(obj, "Elements")
    en = child(h, els, "12000004", required=False)
    if not en:
        en = h.node_add_child(els, "12000004")
    set_reg(h, en, "Element", REG_BINARY, description.encode("utf-16le") + b"\x00\x00")


def parse_app_type(text: str) -> int:
    mapping = {
        "osloader": 0x10200003,
        "bootapp": 0x10200005,
        "bootsector": 0x10300008,
        "ntldr": 0x10300006,
        "resume": 0x10200004,
        "memdiag": 0x10200005,
    }
    key = text.lower()
    if key not in mapping:
        die(f"Unsupported /application type: {text}")
    return mapping[key]


def cmd_enum(store, args, verbose):
    selector = args[0].lower() if args else "active"
    if selector not in ("all", "active", "firmware", "bootmgr", "osloader", "resume", "inherit"):
        die(f"Unsupported /enum selector: {selector}")
    h = hivex.Hivex(store, write=False)
    try:
        enum_objects(h, selector, verbose)
    finally:
        safe_close(h)


def cmd_set(store, args):
    if len(args) < 3:
        die("Syntax: /set ID datatype value")
    h = hivex.Hivex(store, write=False)
    try:
        ident = resolve_id(h, all_objects(h), args[0])
        alias = object_alias(ident)
        typ = parse_type_token(args[1], alias)
        value = " ".join(args[2:])
        obj = child(h, objects_node(h), ident)
        els = object_elements(h, obj)
        existing = None
        if els:
            en = child(h, els, f"{typ:08X}", required=False)
            if en:
                existing = raw_value(h, en)
        data = parse_element_value(h, obj, typ, value, existing)
    finally:
        safe_close(h)
    mutate_store(store, lambda w: write_element(w, ident, typ, data))
    print("The operation completed successfully.")


def cmd_deletevalue(store, args):
    if len(args) != 2:
        die("Syntax: /deletevalue ID datatype")
    h = hivex.Hivex(store, write=False)
    try:
        ident = resolve_id(h, all_objects(h), args[0])
        typ = parse_type_token(args[1], object_alias(ident))
    finally:
        safe_close(h)
    mutate_store(store, lambda w: delete_element(w, ident, typ))
    print("The operation completed successfully.")


def cmd_delete(store, args):
    if not args:
        die("Syntax: /delete ID")
    h = hivex.Hivex(store, write=False)
    try:
        ident = resolve_id(h, all_objects(h), args[0])
    finally:
        safe_close(h)
    if ident == BOOTMGR:
        die("Refusing to delete the Windows Boot Manager object.")
    def op(w):
        hobj = child(w, objects_node(w), ident)
        w.node_delete_child(hobj)
    mutate_store(store, op)
    print("The operation completed successfully.")


def cmd_copy(store, args):
    if not args:
        die("Syntax: /copy ID [/d description]")
    src_arg = args[0]
    desc = None
    if "/d" in [x.lower() for x in args]:
        i = [x.lower() for x in args].index("/d")
        if i + 1 >= len(args):
            die("/copy /d requires a description.")
        desc = args[i + 1]
    h = hivex.Hivex(store, write=False)
    try:
        src = resolve_id(h, all_objects(h), src_arg)
        typ = object_type(h, child(h, objects_node(h), src))
    finally:
        safe_close(h)
    new_id = "{" + str(uuid.uuid4()).upper() + "}"
    def op(w):
        root = objects_node(w)
        srcnode = child(w, root, src)
        dst = w.node_add_child(root, new_id)
        clone_node(w, srcnode, dst)
        if desc is not None:
            d = child(w, dst, "Elements", required=False)
            if not d:
                d = w.node_add_child(dst, "Elements")
            set_description(w, dst, desc)
    mutate_store(store, op)
    print(f"The entry was successfully copied to {new_id}.")


def cmd_create(store, args):
    lower = [x.lower() for x in args]
    desc = None
    if "/d" in lower:
        i = lower.index("/d")
        if i + 1 >= len(args):
            die("/create /d requires a description.")
        desc = args[i + 1]
    if "/application" in lower:
        i = lower.index("/application")
        if i + 1 >= len(args):
            die("/create /application requires a type.")
        objtype = parse_app_type(args[i + 1])
    elif "/inherit" in lower:
        i = lower.index("/inherit")
        if i + 1 >= len(args):
            die("/create /inherit requires an inherited-object type.")
        source = args[i + 1].lower()
        if source in ("bootloadersettings", "osloader", "library"):
            objtype = 0x20200000
        elif source in ("device", "deviceoptions"):
            objtype = 0x20100000
        else:
            die(f"Unsupported /inherit type: {args[i + 1]}")
    else:
        die("Syntax: /create /d DESCRIPTION /application osloader|bootapp|bootsector")
    new_id = "{" + str(uuid.uuid4()).upper() + "}"
    def op(w):
        obj = w.node_add_child(objects_node(w), new_id)
        d = w.node_add_child(obj, "Description")
        set_reg(w, d, "Type", REG_DWORD, struct.pack("<I", objtype))
        w.node_add_child(obj, "Elements")
        if desc:
            set_description(w, obj, desc)
    mutate_store(store, op)
    print(f"The entry was successfully created: {new_id}")


def cmd_order(store, object_id: str, typ: int, ids: list[str], mode: str = "replace"):
    h = hivex.Hivex(store, write=False)
    try:
        objects = all_objects(h)
        ident = resolve_id(h, objects, object_id)
        resolved = [resolve_id(h, objects, x) for x in ids]
        existing: list[str] = []
        encoding = "utf16"
        obj = objects.get(ident)
        els = object_elements(h, obj) if obj else None
        en = child(h, els, f"{typ:08X}", required=False) if els else None
        if en:
            raw = raw_value(h, en)
            if raw:
                try:
                    existing, encoding = decode_object_list(raw)
                except Exception:
                    encoding = "binary"
            else:
                encoding = "binary"
        else:
            encoding = "binary"
    finally:
        safe_close(h)
    if mode == "replace":
        result = resolved
    elif mode == "addfirst":
        result = resolved + [x for x in existing if x not in resolved]
    elif mode == "addlast":
        result = [x for x in existing if x not in resolved] + resolved
    else:
        die(f"Unknown order mode: {mode}")
    data = encode_object_list(result, encoding)
    mutate_store(store, lambda w: write_element(w, ident, typ, data))
    print("The operation completed successfully.")


def cmd_default(store, args):
    if len(args) != 1:
        die("Syntax: /default ID")
    cmd_set(store, ["{bootmgr}", "default", args[0]])


def cmd_bootsequence(store, args):
    if not args:
        die("Syntax: /bootsequence ID [ID ...]")
    cmd_order(store, "{bootmgr}", 0x24000002, args, "replace")


def cmd_displayorder(store, args):
    if not args:
        die("Syntax: /displayorder ID [ID ...] [/addfirst|/addlast]")
    mode = "replace"
    ids = []
    for x in args:
        if x.lower() == "/addfirst":
            mode = "addfirst"
        elif x.lower() == "/addlast":
            mode = "addlast"
        else:
            ids.append(x)
    if not ids:
        die("/displayorder requires at least one identifier.")
    cmd_order(store, "{bootmgr}", 0x24000001, ids, mode)


def cmd_timeout(store, args):
    if len(args) != 1:
        die("Syntax: /timeout seconds")
    cmd_set(store, ["{bootmgr}", "timeout", args[0]])


def normalize_argv(argv: list[str]) -> tuple[list[str], bool]:
    out = []
    verbose = False
    for item in argv:
        low = item.lower()
        if low == "/store":
            out.append("--store")
        elif low == "/v":
            verbose = True
        elif low in ("/?", "-?"):
            out.append("--help")
        else:
            out.append(item)
    return out, verbose


def main(argv=None) -> int:
    script_dir = Path(__file__).resolve().parent
    load_symbols(script_dir)

    raw = list(sys.argv[1:] if argv is None else argv)
    raw, slash_verbose = normalize_argv(raw)

    parser = argparse.ArgumentParser(
        prog="bcdtool",
        description="Offline BCD store editor (Python + libhivex; BCDEdit-style syntax).",
    )
    parser.add_argument("--store", required=True, help="BCD hive path (BCDEdit /store)")
    parser.add_argument("--verbose", action="store_true", default=slash_verbose,
                        help="BCDEdit /v: show full object GUIDs and numeric element IDs")
    parser.add_argument("command", nargs=argparse.REMAINDER)
    ns = parser.parse_args(raw)

    if hivex is None:
        die("Python hivex bindings missing. Debian/Ubuntu: sudo apt install libhivex0 python3-hivex")
    if not ns.command:
        ns.command = ["/enum", "active"]

    cmd = ns.command[0].lower()
    args = ns.command[1:]

    if cmd in ("/enum", "enum"):
        cmd_enum(ns.store, args, ns.verbose)
    elif cmd in ("/set", "set"):
        cmd_set(ns.store, args)
    elif cmd in ("/deletevalue", "deletevalue"):
        cmd_deletevalue(ns.store, args)
    elif cmd in ("/delete", "delete"):
        cmd_delete(ns.store, args)
    elif cmd in ("/copy", "copy"):
        cmd_copy(ns.store, args)
    elif cmd in ("/create", "create"):
        cmd_create(ns.store, args)
    elif cmd in ("/displayorder", "displayorder"):
        cmd_displayorder(ns.store, args)
    elif cmd in ("/bootsequence", "bootsequence"):
        cmd_bootsequence(ns.store, args)
    elif cmd in ("/default", "default"):
        cmd_default(ns.store, args)
    elif cmd in ("/timeout", "timeout"):
        cmd_timeout(ns.store, args)
    elif cmd in ("/export", "export"):
        if len(args) != 1:
            die("Syntax: /export FILE (exports a byte-for-byte copy of this offline store)")
        shutil.copy2(ns.store, args[0])
        print("The BCD store was successfully exported.")
    elif cmd in ("/import", "import"):
        if len(args) != 1:
            die("Syntax: /import FILE")
        shutil.copy2(args[0], ns.store)
        print("The BCD store was successfully imported.")
    else:
        die(
            f"Unsupported command: {cmd}. Implemented: /enum, /set, /deletevalue, "
            "/delete, /copy, /create, /displayorder, /bootsequence, /default, "
            "/timeout, /export, /import."
        )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except BcdError as exc:
        print(f"bcdtool: {exc}", file=sys.stderr)
        raise SystemExit(1)
    except Exception as exc:
        print(f"bcdtool: internal error: {exc}", file=sys.stderr)
        raise SystemExit(2)
