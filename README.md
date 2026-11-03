# bcdtool — offline BCDEdit-style BCD editor

Python 3 + libhivex. This project uses the upstream `known_symbols.json` object GUID and common element-name map as its data-driven symbol source. The original JSON's trailing empty `prefix` record was omitted because it is not valid JSON; all populated `objectGuids` and `entryNames[0].names` entries were retained.

## Install

Debian/Ubuntu:

```sh
sudo apt install libhivex0 python3-hivex
```

Use the distro Python that can import `hivex` (often `/usr/bin/python3`). No pip package is required.

## Usage

Always work on an offline copy of the BCD file. The tool makes a temporary sibling copy and atomically replaces the selected file after a successful hivex commit for supported mutations.

```sh
./bcdtool.py /store ./BCD /enum all
./bcdtool.py /store ./BCD /v /enum all
./bcdtool.py /store ./BCD /set '{GUID}' description 'Linux Boot Entry'
./bcdtool.py /store ./BCD /set '{GUID}' path '\\EFI\\BOOT\\BOOTAA64.EFI'
./bcdtool.py /store ./BCD /set '{GUID}' loadoptions 'debug loglevel=8'
./bcdtool.py /store ./BCD /deletevalue '{GUID}' loadoptions
./bcdtool.py /store ./BCD /delete '{GUID}'
./bcdtool.py /store ./BCD /copy '{GUID}'
```

The syntax intentionally follows the BCDEdit command shape (`/store`, `/v`, `/enum`, `/set`, `/deletevalue`, `/delete`, `/copy`). This is an offline BCD-store editor, not a replacement for firmware NVRAM management.

## Important implementation boundary

BCD element keys are 32-bit IDs. Their upper nibbles encode element class and format; the `Element` registry value stores the payload. `known_symbols.json` supplies friendly aliases but is not a complete schema. The implementation supports the generic string, integer, boolean, object GUID, object-list and integer-list encodings. Device descriptors are opaque in this build: `/set device` and `/set osdevice` require `raw:HEX`; the tool refuses to invent a device descriptor. Existing device payloads are displayed as raw hex and preserved by unrelated edits.

Supported commands in this build: `/enum` (all, active, firmware, bootmgr, osloader, resume, inherit), `/set`, `/deletevalue`, `/delete`, `/copy`.

Not yet implemented: `/create`, `/mirror`, `/bootsequence`, `/default`, `/displayorder`, `/timeout`, `/toolsdisplayorder`, `/bootems`, `/ems`, `/emssettings`, `/bootdebug`, `/dbgsettings`, `/debug`, `/hypervisorsettings`, `/eventsettings`, `/event`, `/export`, `/import`, `/createstore`, `/sysstore`, dynamic-disk descriptors, and full BCDEdit-compatible text formatting/exit codes. Do not describe this as a complete BCDEdit clone until these are implemented and validated against Windows-generated fixture stores.

## Safety

- Back up the BCD before editing.
- Test edits against a disposable copy and validate with Windows `bcdedit /store <file> /enum all` before booting.
- Device elements are intentionally not synthesized from drive letters or guessed partition identities.
- Unknown element types remain untouched unless explicitly selected by raw numeric ID.

## References

- `SaphireLattice/bcd-editor` `known_symbols.json` (MIT): https://github.com/SaphireLattice/bcd-editor
- `kupiakos/pybcd` (MIT): https://github.com/kupiakos/pybcd — reverse-engineered element/object/device format research.
- Microsoft BCDEdit command reference: https://learn.microsoft.com/en-us/windows-hardware/manufacture/desktop/bcdedit-command-line-options?view=windows-11
