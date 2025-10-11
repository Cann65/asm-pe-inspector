# PE Inspector (x64, Windows)

Static, defensive-only PE triage tool written in MASM for Windows x64. The utility memory-maps a given PE file, parses all major headers, computes Shannon entropy per section, and emits JSON or CSV that can be ingested by DFIR/SIEM pipelines. It focuses on spotting packed/obfuscated artefacts without executing the sample.

## Features
- Pure assembly implementation targeting the Windows x64 ABI (ml64 + link).
- Walks DOS, NT, file, optional, and section headers without copying the image.
- Calculates Shannon entropy over raw section data to highlight compressed/encrypted payloads.
- Heuristic scoring with severity-driven exit codes (`0 = ok`, `1 = warning`, `2 = high-risk`):
  - `.text` section above configurable entropy threshold (default 7.2).
  - Missing import table.
  - Single very large section.
  - Executable sections that are also writable.
- Machine-readable output:
  - JSON (default): `{"file": "...", "sections": [...], "heuristics": [...], "severity": n}`
  - CSV: section metrics, heuristic list, final severity summary.
- UTF-8 safe output path handling and clean failure paths.

## Repository Layout
```
asm/                # MASM sources
  include/          # Shared structs and constants
tools/              # Example binaries (populate with your test PE files)
tests/              # Future Python-based regression tests
README.md           # This document
```

## Building
Prerequisites:
- Windows 10/11 x64
- Visual Studio Build Tools (ml64.exe, link.exe) or an equivalent MASM toolchain

Example build steps from a “x64 Native Tools Command Prompt for VS”:
```batch
cd asm
ml64 /c /nologo /Fo peinspector.obj peinspector.asm
link /nologo /subsystem:console /entry:main /out:peinspector.exe peinspector.obj kernel32.lib shell32.lib msvcrt.lib
```
Place the resulting `peinspector.exe` at the repo root or wherever convenient.

## Usage
```
peinspector.exe <path-to-pe> [--json | --csv] [--warn-threshold=<float>]
```
Examples:
```batch
peinspector.exe tools\hello64.exe --json > reports\hello.json
peinspector.exe tools\upx-packed.exe --csv > reports\packed.csv
peinspector.exe C:\Windows\System32\kernel32.dll --warn-threshold=7.0
```
Exit codes reflect the highest triggered heuristic (0/1/2).

## Output Reference
### JSON
```json
{
  "file": "sample.exe",
  "sections": [
    {"name": ".text", "raw_size": 4096, "virtual_size": 3584, "entropy": 7.92,
     "exec": true, "write": false, "characteristics": "0x60000020"}
  ],
  "heuristics": [
    {"id": "high_entropy_text", "severity": "high"}
  ],
  "severity": 2
}
```

### CSV
```
section,raw_size,virtual_size,entropy,exec,write,characteristics
.text,4096,3584,7.920,1,0,0x60000020
.rsrc,2048,1536,4.032,0,0,0x40000040
heuristic,id,severity
heuristic,high_entropy_text,high
summary,severity,2
```

## Heuristic Details
- `high_entropy_text` (high): `.text` exceeds the entropy threshold (default 7.2, configurable).
- `no_imports` (high): Import directory RVA/size absent — common with packers/shellcode loaders.
- `single_section` (warning): Only one section present; typical for heavily packed binaries.
- `large_section` (warning): Any section larger than 2 MB of raw data.
- `suspicious_characteristics` (warning): Section marked executable **and** writable.

Adjust the entropy trigger with `--warn-threshold=<value>`. This threshold only affects the `.text` entropy heuristic and leaves other checks untouched.

## Roadmap & Tests
- [ ] Populate `tools/` with a benign hello-world executable and a self-packed sample (e.g., UPX).
- [ ] Implement Python-based regression tests under `tests/` that run the inspector against known samples and assert the emitted JSON/CSV.
- [ ] Optional: auto-generate YARA skeletons from heuristic findings.
- [ ] Capture a short terminal demo GIF showcasing JSON + CSV modes.

## Operational Notes & Ethics
- Designed strictly for defensive analysis. Do **not** use this project to aid malware creation or evasion.
- Entropy thresholds and heuristics are deliberately conservative; treat them as triage hints, not final verdicts.
- Tested against standard Windows PE files only; malformed binaries may require additional guard rails before production use.

## Troubleshooting
- Ensure you are compiling inside an x64 developer prompt — 32-bit toolchains will not work.
- If linking fails with unresolved externals, confirm that `kernel32.lib`, `shell32.lib`, and `msvcrt.lib` are on the LIB path (provided by VS Build Tools).
- For debugging, temporarily switch the output mode to CSV to sanity-check section metrics against expectations.

Happy dissecting!
