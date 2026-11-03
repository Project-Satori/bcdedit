#!/usr/bin/env python3
"""Offline, libhivex-backed BCD editor (bcdedit-compatible command subset).

The on-disk BCD store is a Registry hive. BCD-specific object/element semantics
are layered on top of libhivex. Unknown element payloads are preserved as raw
bytes; this tool never guesses an unknown binary layout.
"""
from __future__ import annotations
import argparse, json, os, re, shutil, struct, sys, tempfile, uuid
from pathlib import Path

try:
    import hivex
except ImportError:
    hivex = None

HERE = Path(__file__).resolve().parent
SYMBOLS = json.loads((HERE / 'known_symbols.json').read_text())
OBJ_SYMBOLS = {k.upper(): v for k, v in SYMBOLS['objectGuids'].items()}
ALIAS_TO_GUID = {v['name'].lower(): '{'+k+'}' for k,v in OBJ_SYMBOLS.items() if v.get('name')}
# {default} is a dynamic alias resolved through bootmgr's Default element.
BOOTMGR = '{9DEA862C-5CDD-4E70-ACC1-F32B344D4795}'
# Element type values from known_symbols.json plus the application-specific
# aliases needed by common Windows OS-loader / boot-manager objects.
NAME_TO_TYPE = {}
TYPE_TO_NAME = {}
for group in SYMBOLS['entryNames']:
    for hx, pair in group['names'].items():
        typ = int(hx, 16); friendly = pair[1]
        TYPE_TO_NAME[typ] = friendly or pair[0] or f'custom:{typ:08x}'
        if friendly: NAME_TO_TYPE[friendly.lower()] = typ
# pybcd's reverse-engineered per-application element map, used only where the
# upstream known_symbols list intentionally has no application-specific rows.
APP_NAMES = {
 'bootmgr': {0x24000001:'displayorder',0x24000002:'bootsequence',0x23000003:'default',0x25000004:'timeout',0x26000005:'resume',0x23000006:'resumeobject',0x24000010:'toolsdisplayorder',0x26000020:'displaybootmenu',0x26000021:'noerrordisplay',0x11000022:'bcddevice',0x12000023:'bcdfilepath'},
 'fwbootmgr': {0x24000001:'displayorder',0x24000002:'bootsequence',0x23000003:'default',0x25000004:'timeout',0x24000010:'toolsdisplayorder'},
 'osloader': {0x21000001:'osdevice',0x22000002:'systemroot',0x23000003:'resumeobject',0x26000010:'detecthal',0x22000011:'kernel',0x22000012:'hal',0x25000020:'nx',0x25000021:'pae',0x26000022:'winpe',0x26000024:'nocrashautoreboot',0x26000026:'oslnointegritychecks',0x26000027:'osltestsigning',0x25000031:'removememory',0x25000032:'increaseuserva',0x26000040:'vga',0x26000041:'quietboot',0x26000060:'onecpu',0x25000061:'numproc',0x26000062:'maxproc',0x26000080:'safeboot',0x26000081:'safebootalternateshell',0x26000090:'bootlog',0x26000091:'sos',0x260000A0:'debug',0x260000A1:'halbreakpoint',0x260000A2:'useplatformclock',0x250000F0:'hypervisorlaunchtype',0x220000F1:'hypervisorpath'},
 'resume': {0x21000001:'filedevice',0x22000002:'filepath',0x26000003:'customsettings',0x26000004:'pae',0x21000005:'associatedosdevice',0x26000006:'debugoptionenabled'},
 'memdiag': {0x25000001:'passcount',0x25000002:'testmix',0x25000003:'failurecount'},
 'ramdiskoptions': {0x31000001:'ramdiskimageoffset',0x31000002:'ramdiskftpclientport',0x31000003:'ramdisksdidevice',0x32000004:'ramdisksdipath',0x31000005:'ramdiskimagelength'}
}
for mp in APP_NAMES.values():
    for t,n in mp.items(): NAME_TO_TYPE.setdefault(n,t); TYPE_TO_NAME.setdefault(t,n)

REG_BINARY, REG_DWORD = 3, 4

def die(msg): raise BcdError(msg)
class BcdError(Exception): pass

def norm_guid(s):
    s=s.strip()
    if s.startswith('{') and s.endswith('}'): s=s[1:-1]
    try: return '{'+str(uuid.UUID(s)).upper()+'}'
    except Exception: die(f'Invalid identifier: {s}')

def node_name(h,n): return h.node_name(n)
def children(h,n): return h.node_children(n)
def child(h,n,name,required=True):
    try: x=h.node_get_child(n,name)
    except RuntimeError: x=0
    if not x and required: die(f'Registry key not found: {name}')
    return x

def val(h,n,key,required=True):
    try: v=h.node_get_value(n,key)
    except RuntimeError: v=0
    if not v:
        if required: die(f'Registry value not found: {key}')
        return None
    return h.value_value(v)

def raw_value(h,n,key='Element'):
    got=val(h,n,key,False)
    if got is None: return None
    return got[1] if isinstance(got[1],bytes) else got[1].encode('latin1')

def set_reg(h,n,key,typ,data):
    h.node_set_value(n, {'key':key,'t':typ,'value':data})

def del_reg_value(h,n,key):
    keep=[]
    for vh in h.node_values(n):
        k=h.value_key(vh)
        if k.lower()==key.lower(): continue
        t,d=h.value_value(vh); keep.append({'key':k,'t':t,'value':d})
    h.node_set_values(n,keep)

def elem_type(key):
    try: return int(key,16)
    except ValueError: return None

def elem_alias(t): return TYPE_TO_NAME.get(t, f'custom:{t:08x}')

def object_type(h,obj):
    d=child(h,obj,'Description',False)
    if not d: return 0
    got=val(h,d,'Type',False)
    if not got: return 0
    data=got[1]
    if isinstance(data,bytes): return int.from_bytes(data[:4],'little') if len(data)>=4 else 0
    return int(data)

def object_alias(guid):
    g=norm_guid(guid); return OBJ_SYMBOLS.get(g[1:-1],{}).get('name')

def resolve_id(h,objects,ident):
    s=ident.strip()
    if s.lower() in ('{bootmgr}','bootmgr'): return BOOTMGR
    if s.lower() in ('{default}','default'):
        bm=child(h,objects,BOOTMGR,False)
        if bm:
            els=child(h,bm,'Elements',False)
            if els:
                for e in children(h,els):
                    t=elem_type(node_name(h,e))
                    if t in (0x23000003,):
                        b=raw_value(h,e)
                        if b and len(b)>=16: return '{'+str(uuid.UUID(bytes_le=b[:16])).upper()+'}'
        die('The {default} object cannot be resolved: Boot Manager Default element is missing.')
    if s.startswith('{') or re.fullmatch(r'[0-9a-fA-F-]{36}',s): return norm_guid(s)
    a=s.strip('{}').lower()
    if a in ALIAS_TO_GUID: return ALIAS_TO_GUID[a]
    die(f'Unknown identifier: {ident}')

def obj_nodes(h):
    root=h.root(); objects=child(h,root,'Objects')
    return objects

def object_elements(h,obj):
    return child(h,obj,'Elements',False)

def format_data(t,data):
    fmt=(t>>24)&0xF
    if fmt==2: # UTF-16LE string
        try: return data.decode('utf-16le').rstrip('\x00')
        except Exception: return 'hex:'+data.hex()
    if fmt==5:
        return hex(int.from_bytes(data[:8].ljust(8,b'\0'),'little'))
    if fmt==6:
        return 'Yes' if data and data[0] else 'No'
    if fmt==3 and len(data)>=16:
        return '{'+str(uuid.UUID(bytes_le=data[:16])).upper()+'}'
    if fmt==4 and len(data)%16==0:
        return ', '.join('{'+str(uuid.UUID(bytes_le=data[i:i+16])).upper()+'}' for i in range(0,len(data),16))
    if fmt==7 and len(data)%8==0:
        return ', '.join(hex(int.from_bytes(data[i:i+8],'little')) for i in range(0,len(data),8))
    if fmt==1: return 'raw:'+data.hex()
    return 'hex:'+data.hex()

def object_dump(h,guid,obj,verbose=False):
    typ=object_type(h,obj); alias=object_alias(guid)
    title=alias or ('Object' if not typ else f'Object Type {typ:#x}')
    print(f'\n{title}')
    print('----------------')
    print(f'identifier              {guid if verbose or not alias else "{"+alias+"}"}')
    els=object_elements(h,obj)
    if not els: return
    for en in sorted(children(h,els),key=lambda n:node_name(h,n)):
        key=node_name(h,en); t=elem_type(key)
        if t is None: continue
        b=raw_value(h,en)
        if b is None: continue
        name=elem_alias(t)
        shown=format_data(t,b)
        if not verbose and shown.startswith('{') and shown.endswith('}'):
            try:
                g=norm_guid(shown); a=object_alias(g)
                if a: shown='{'+a+'}'
            except BcdError: pass
        label=f'{name}<{key}>' if verbose else name
        print(f'{label:<24}{shown}')

def parse_elem(h,objects,obj,typname,value):
    # Raw element ID is accepted for unknown/undocumented BCD entries.
    if typname.lower().startswith('0x'):
        t=int(typname,16)
    else:
        candidates={k:v for k,v in NAME_TO_TYPE.items() if k==typname.lower()}
        if not candidates: die(f'Unknown BCD element name: {typname} (use its 8-digit 0x type)')
        t=next(iter(candidates.values()))
    fmt=(t>>24)&0xF
    if fmt==2:
        data=value.encode('utf-16le')+b'\0\0'
    elif fmt==5:
        try: n=int(value,0)
        except ValueError: die(f'Expected integer for {typname}: {value}')
        if n<0 or n>0xffffffffffffffff: die('Integer is outside unsigned 64-bit range')
        data=struct.pack('<Q',n)
    elif fmt==6:
        b={'yes':1,'true':1,'on':1,'1':1,'no':0,'false':0,'off':0,'0':0}.get(value.lower())
        if b is None: die(f'Expected on/off, yes/no, true/false or 1/0 for {typname}')
        data=bytes([b])
    elif fmt==3:
        g=resolve_id(h,objects,value); data=uuid.UUID(g.strip('{}')).bytes_le
    elif fmt==4:
        parts=[x.strip() for x in value.split(',') if x.strip()]
        data=b''.join(uuid.UUID(resolve_id(h,objects,x).strip('{}')).bytes_le for x in parts)
    elif fmt==7:
        parts=[x.strip() for x in value.split(',') if x.strip()]
        data=b''.join(struct.pack('<Q',int(x,0)) for x in parts)
    elif fmt==1:
        if not value.lower().startswith('raw:'): die('Device elements require raw:HEX in this build; refusing to guess device descriptor encoding.')
        try: data=bytes.fromhex(value[4:])
        except ValueError: die('Invalid raw hex payload')
    else:
        die(f'Unsupported BCD element format {fmt}; use raw registry tooling rather than corrupting the store.')
    return t,data

def mutate(path, fn):
    path=Path(path).resolve()
    if not path.is_file(): die(f'BCD store does not exist: {path}')
    # Work on a sibling copy; commit then atomically replace the original.
    fd,tmp=tempfile.mkstemp(prefix=path.name+'.bcdtool.',dir=str(path.parent)); os.close(fd)
    shutil.copy2(path,tmp)
    try:
        h=hivex.Hivex(tmp,write=True)
        try:
            fn(h)
            h.commit(None)
        finally:
            try: h.close()
            except Exception: pass
        os.replace(tmp,path)
    except Exception:
        try: os.unlink(tmp)
        except OSError: pass
        raise

def do_enum(h,kind,verbose):
    objects=obj_nodes(h); all_nodes={}
    for n in children(h,objects):
        g=node_name(h,n)
        try: g=norm_guid(g)
        except BcdError: continue
        all_nodes[g]=n
    if kind=='active':
        # Active means the Boot Manager and entries it currently references,
        # not every dormant object in the store.
        selected={BOOTMGR}
        bm=all_nodes.get(BOOTMGR)
        if bm:
            els=object_elements(h,bm)
            if els:
                for et in (0x23000003,0x24000001,0x24000002):
                    en=child(h,els,f'{et:08X}',False)
                    if not en: continue
                    raw=raw_value(h,en)
                    if not raw: continue
                    stride=16 if et in (0x24000001,0x24000002) else 16
                    for off in range(0,len(raw)-stride+1,stride):
                        selected.add('{'+str(uuid.UUID(bytes_le=raw[off:off+16])).upper()+'}')
        entries=[(g,all_nodes[g]) for g in selected if g in all_nodes]
    else:
        entries=[]
        for g,n in all_nodes.items():
            typ=object_type(h,n); info=((typ>>28)&0xF,(typ>>20)&0xF,typ&0xFFFFF)
            alias=object_alias(g)
            if kind=='all': entries.append((g,n))
            elif kind=='firmware' and info[0]==1 and info[1]==1: entries.append((g,n))
            elif kind=='bootmgr' and alias in ('bootmgr','fwbootmgr'): entries.append((g,n))
            elif kind=='osloader' and info==(1,2,3): entries.append((g,n))
            elif kind=='resume' and info==(1,2,4): entries.append((g,n))
            elif kind=='inherit' and info[0]==2: entries.append((g,n))
    for g,n in sorted(entries): object_dump(h,g,n,verbose)

def main(argv=None):
    p=argparse.ArgumentParser(prog='bcdtool',description='Offline BCD editor backed by libhivex')
    p.add_argument('--store',dest='store',required=True,help='BCD hive path (BCDEdit-style /store)')
    p.add_argument('--verbose',dest='verbose',action='store_true',help='verbose identifiers and element types (BCDEdit-style /v)')
    p.add_argument('command',nargs='*')
    raw=list(sys.argv[1:] if argv is None else argv)
    raw=['--store' if x.lower()=='/store' else '--verbose' if x.lower()=='/v' else x for x in raw]
    ns=p.parse_args(raw)
    if hivex is None: die('Python hivex bindings missing. Install python3-hivex / python-hivex.')
    if not ns.command: ns.command=['/enum','active']
    cmd=ns.command[0].lower(); args=ns.command[1:]
    h=hivex.Hivex(ns.store,write=False)
    try:
        objects=obj_nodes(h)
        if cmd in ('/enum','enum'):
            kind=args[0].lower() if args else 'active'
            if kind not in ('all','active','firmware','bootmgr','osloader','resume','inherit'): die(f'Unsupported /enum selector: {kind}')
            do_enum(h,kind,ns.verbose)
        elif cmd in ('/set','set'):
            if len(args)<3: die('Syntax: /set ID datatype value')
            ident=resolve_id(h,objects,args[0]); typname=args[1]; value=' '.join(args[2:])
            def op(w):
                ob=child(w,obj_nodes(w),ident); els=child(w,ob,'Elements',False)
                if not els: els=w.node_add_child(ob,'Elements')
                t,data=parse_elem(w,obj_nodes(w),ob,typname,value); ename=f'{t:08X}'
                en=child(w,els,ename,False)
                if not en: en=w.node_add_child(els,ename)
                set_reg(w,en,'Element',REG_BINARY,data)
            mutate(ns.store,op); print('The operation completed successfully.')
        elif cmd in ('/deletevalue','deletevalue'):
            if len(args)!=2: die('Syntax: /deletevalue ID datatype')
            ident=resolve_id(h,objects,args[0]); t=NAME_TO_TYPE.get(args[1].lower(),int(args[1],16) if args[1].lower().startswith('0x') else None)
            if t is None: die(f'Unknown BCD element: {args[1]}')
            def op(w):
                ob=child(w,obj_nodes(w),ident); els=child(w,ob,'Elements'); en=child(w,els,f'{t:08X}'); w.node_delete_child(en)
            mutate(ns.store,op); print('The operation completed successfully.')
        elif cmd in ('/delete','delete'):
            if not args: die('Syntax: /delete ID [/cleanup]')
            ident=resolve_id(h,objects,args[0])
            if ident in (BOOTMGR,): die('Refusing to delete the Windows Boot Manager object.')
            def op(w): w.node_delete_child(child(w,obj_nodes(w),ident))
            mutate(ns.store,op); print('The operation completed successfully.')
        elif cmd in ('/copy','copy'):
            if len(args)<1: die('Syntax: /copy ID [/d description]')
            src=resolve_id(h,objects,args[0]); desc=None
            if '/d' in args:
                i=args.index('/d'); desc=args[i+1]
            new='{'+str(uuid.uuid4()).upper()+'}'
            def op(w):
                srcn=child(w,obj_nodes(w),src); dst=w.node_add_child(obj_nodes(w),new)
                # Deep-copy registry subtree through hivex API.
                def clone(a,b):
                    vals=[]
                    for vh in w.node_values(a):
                        k=w.value_key(vh); t,d=w.value_value(vh); vals.append({'key':k,'t':t,'value':d})
                    if vals: w.node_set_values(b,vals)
                    for c in children(w,a):
                        cn=w.node_add_child(b,node_name(w,c)); clone(c,cn)
                clone(srcn,dst)
                if desc:
                    d=child(w,dst,'Description',False)
                    if d: set_reg(w,d,'Type',REG_DWORD,struct.pack('<I',object_type(w,srcn)))
                    # BCD display description is an Element, not an object-level string.
                    els=child(w,dst,'Elements',False)
                    if els:
                        t=0x12000004; en=child(w,els,f'{t:08X}',False)
                        if en: set_reg(w,en,'Element',REG_BINARY,desc.encode('utf-16le')+b'\0\0')
            mutate(ns.store,op); print(f'The entry was successfully copied to {new}.')
        elif cmd in ('/create','create'):
            die('/create is not implemented in this first build: BCD object Description.Type and application-specific object type validation must be completed before writing a new object.')
        elif cmd in ('/export','export'):
            die('/export is a system-store operation in BCDEdit; this offline tool accepts explicit file copies instead.')
        elif cmd in ('/import','import','/createstore','createstore','/sysstore','sysstore'):
            die(f'{cmd} is not implemented; see README for scope.')
        else: die(f'Unsupported command: {cmd}. Try /enum, /set, /deletevalue, /delete or /copy.')
    finally:
        try: h.close()
        except Exception: pass
    return 0

if __name__=='__main__':
    try: sys.exit(main())
    except BcdError as e: print(f'bcdtool: {e}',file=sys.stderr); sys.exit(1)
    except Exception as e: print(f'bcdtool: internal error: {e}',file=sys.stderr); sys.exit(2)
