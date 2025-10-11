option casemap:none

include include\pe.inc

; ---------------------------------------------------------------------------
; External dependencies / libraries
; ---------------------------------------------------------------------------

includelib kernel32.lib
includelib shell32.lib
includelib msvcrt.lib

ExitProcess                 proto :DWORD
GetCommandLineW             proto
CommandLineToArgvW          proto :QWORD, :QWORD
LocalFree                   proto :QWORD
CreateFileW                 proto :QWORD, :DWORD, :DWORD, :QWORD, :DWORD, :DWORD, :QWORD
GetFileSizeEx               proto :QWORD, :QWORD
CreateFileMappingW          proto :QWORD, :QWORD, :DWORD, :DWORD, :DWORD, :QWORD
MapViewOfFile               proto :QWORD, :DWORD, :DWORD, :DWORD, :QWORD
UnmapViewOfFile             proto :QWORD
CloseHandle                 proto :QWORD
WideCharToMultiByte         proto :DWORD, :DWORD, :QWORD, :DWORD, :QWORD, :DWORD, :QWORD, :QWORD
lstrcmpiW                   proto :QWORD, :QWORD
wcstod                      proto :QWORD, :QWORD
memcmp                      proto :QWORD, :QWORD, :QWORD
memset                      proto :QWORD, :DWORD, :QWORD
log                         proto :REAL8

printf                      proto :QWORD, :VARARG

; ---------------------------------------------------------------------------
; Constants / offsets
; ---------------------------------------------------------------------------

IMAGE_SECTION_HEADER_SIZE   equ SIZEOF IMAGE_SECTION_HEADER

SEC_OFF_NAME                equ 0
SEC_OFF_VIRTUALSIZE         equ 8
SEC_OFF_RAWSIZE             equ 16
SEC_OFF_POINTERTORAW        equ 20
SEC_OFF_CHARACTERISTICS     equ 36

.CONST

WarnPrefixLen           equ 17
SectionInfoSize         equ SIZEOF SectionInfo

WarnThresholdDefault    REAL8   7.2
InvLn2                  REAL8   1.4426950408889634
LargeSectionThreshold   DWORD   200000h            ; 2 MB

UsageMessage    BYTE    "Usage: peinspector.exe <path-to-pe> [--json|--csv] [--warn-threshold=<float>]",13,10,0
HelpMessage     BYTE    "PE Inspector (x64) static analyzer - outputs JSON (default) or CSV.",13,10,0

OptionJson      WORD    '-', '-', 'j', 's', 'o', 'n', 0
OptionCsv       WORD    '-', '-', 'c', 's', 'v', 0
OptionHelp      WORD    '-', '-', 'h', 'e', 'l', 'p', 0
WarnPrefix      WORD    '-', '-', 'w', 'a', 'r', 'n', '-', 't', 'h', 'r', 'e', 's', 'h', 'o', 'l', 'd', '=', 0
TextSectionName BYTE    '.','t','e','x','t',0,0,0,0

TrueStr         BYTE    "true",0
FalseStr        BYTE    "false",0
UnknownFileStr  BYTE    "unknown",0

JsonFileStart   BYTE    "{\"file\":\"%s\",\"sections\":[",0
JsonSectionFmt  BYTE    "{\"name\":\"%s\",\"raw_size\":%u,\"virtual_size\":%u,\"entropy\":%.3f,\"exec\":%s,\"write\":%s,\"characteristics\":\"0x%08X\"}",0
JsonComma       BYTE    ",",0
JsonSectionsEnd BYTE    "],\"heuristics\":[",0
JsonHeurFmt     BYTE    "{\"id\":\"%s\",\"severity\":\"%s\"}",0
JsonHeurEnd     BYTE    "],\"severity\":%d}",13,10,0

CsvHeader       BYTE    "section,raw_size,virtual_size,entropy,exec,write,characteristics",13,10,0
CsvSectionFmt   BYTE    "%s,%u,%u,%.3f,%u,%u,0x%08X",13,10,0
CsvHeurHeader   BYTE    "heuristic,id,severity",13,10,0
CsvHeurFmt      BYTE    "heuristic,%s,%s",13,10,0
CsvSummaryFmt   BYTE    "summary,severity,%d",13,10,0

HeurNameHighEntropy BYTE "high_entropy_text",0
HeurNameNoImports   BYTE "no_imports",0
HeurNameSingle      BYTE "single_section",0
HeurNameLarge       BYTE "large_section",0
HeurNameFlags       BYTE "suspicious_characteristics",0

SeverityHighStr BYTE "high",0
SeverityMediumStr BYTE "medium",0

HeuristicTable LABEL QWORD
    QWORD HEURISTIC_HIGH_ENTROPY_TEXT
    QWORD OFFSET HeurNameHighEntropy
    QWORD OFFSET SeverityHighStr
    QWORD HEURISTIC_NO_IMPORTS
    QWORD OFFSET HeurNameNoImports
    QWORD OFFSET SeverityHighStr
    QWORD HEURISTIC_SINGLE_SECTION
    QWORD OFFSET HeurNameSingle
    QWORD OFFSET SeverityMediumStr
    QWORD HEURISTIC_LARGE_SECTION
    QWORD OFFSET HeurNameLarge
    QWORD OFFSET SeverityMediumStr
    QWORD HEURISTIC_SUSPICIOUS_FLAGS
    QWORD OFFSET HeurNameFlags
    QWORD OFFSET SeverityMediumStr
    QWORD 0

.data?

gOutputMode     DWORD   ?
gWarnThreshold  REAL8   ?
gSectionCount   DWORD   ?
gSectionInfos   SectionInfo MAX_SECTIONS DUP(<>)
gHeuristicFlags DWORD   ?
gSeverity       DWORD   ?
gImportSize     DWORD   ?

gUtf8PathBuffer BYTE    1024 DUP(?)

.code

; Prototypes
main                        proto
InspectAndReport            proto :QWORD
ProcessMappedImage          proto :QWORD, :QWORD
ComputeEntropy              proto :QWORD, :QWORD
EmitJson                    proto :QWORD
EmitCsv                     proto :QWORD
EmitHeuristicsJson          proto
EmitHeuristicsCsv           proto
PrepareSectionName          proto :QWORD, :QWORD
ConvertPathToUtf8           proto :QWORD
wcs_prefix_equal            proto :QWORD, :QWORD, :DWORD
parse_warn_threshold        proto :QWORD, :QWORD

; ---------------------------------------------------------------------------
; Entry point
; ---------------------------------------------------------------------------

main PROC
    sub     rsp, 120

    mov     dword ptr [gOutputMode], OUTPUT_JSON
    movsd   xmm0, WarnThresholdDefault
    movsd   qword ptr [gWarnThreshold], xmm0
    mov     dword ptr [gSectionCount], 0
    mov     dword ptr [gHeuristicFlags], 0
    mov     dword ptr [gSeverity], SEVERITY_OK
    mov     dword ptr [gImportSize], 0

    call    GetCommandLineW
    mov     rcx, rax
    lea     rdx, [rsp+80]
    call    CommandLineToArgvW
    test    rax, rax
    jz      main_fail

    mov     qword ptr [rsp+48], rax       ; argv
    mov     eax, dword ptr [rsp+80]       ; argc
    mov     dword ptr [rsp+84], eax
    mov     qword ptr [rsp+56], 0         ; target path pointer
    mov     dword ptr [rsp+88], 1         ; index

parse_args:
    mov     eax, dword ptr [rsp+88]
    cmp     eax, dword ptr [rsp+84]
    jge     args_done

    mov     rcx, qword ptr [rsp+48]
    mov     eax, dword ptr [rsp+88]
    movsxd  rdx, eax
    shl     rdx, 3
    mov     rcx, qword ptr [rcx+rdx]

    mov     rdx, OFFSET OptionJson
    call    lstrcmpiW
    test    eax, eax
    jnz     check_csv
    mov     dword ptr [gOutputMode], OUTPUT_JSON
    jmp     next_arg

check_csv:
    mov     rcx, qword ptr [rsp+48]
    mov     eax, dword ptr [rsp+88]
    movsxd  rdx, eax
    shl     rdx, 3
    mov     rcx, qword ptr [rcx+rdx]
    mov     rdx, OFFSET OptionCsv
    call    lstrcmpiW
    test    eax, eax
    jnz     check_help
    mov     dword ptr [gOutputMode], OUTPUT_CSV
    jmp     next_arg

check_help:
    mov     rcx, qword ptr [rsp+48]
    mov     eax, dword ptr [rsp+88]
    movsxd  rdx, eax
    shl     rdx, 3
    mov     rcx, qword ptr [rcx+rdx]
    mov     rdx, OFFSET OptionHelp
    call    lstrcmpiW
    test    eax, eax
    jnz     check_threshold
    mov     rcx, OFFSET HelpMessage
    call    printf
    mov     rcx, OFFSET UsageMessage
    call    printf
    xor     ecx, ecx
    jmp     cleanup_and_exit

check_threshold:
    mov     rcx, qword ptr [rsp+48]
    mov     eax, dword ptr [rsp+88]
    movsxd  rdx, eax
    shl     rdx, 3
    mov     rcx, qword ptr [rcx+rdx]
    lea     rdx, WarnPrefix
    mov     r8d, WarnPrefixLen
    call    wcs_prefix_equal
    test    eax, eax
    jz      check_path
    mov     rcx, qword ptr [rsp+48]
    mov     eax, dword ptr [rsp+88]
    movsxd  rdx, eax
    shl     rdx, 3
    mov     rcx, qword ptr [rcx+rdx]
    lea     rdx, WarnPrefix
    call    parse_warn_threshold
    jmp     next_arg

check_path:
    cmp     qword ptr [rsp+56], 0
    jne     next_arg
    mov     rcx, qword ptr [rsp+48]
    mov     eax, dword ptr [rsp+88]
    movsxd  rdx, eax
    shl     rdx, 3
    mov     rax, qword ptr [rcx+rdx]
    mov     qword ptr [rsp+56], rax

next_arg:
    inc     dword ptr [rsp+88]
    jmp     parse_args

args_done:
    cmp     qword ptr [rsp+56], 0
    jne     have_path
    mov     rcx, OFFSET UsageMessage
    call    printf
    mov     ecx, 1
    jmp     cleanup_and_exit

have_path:
    mov     rcx, qword ptr [rsp+56]
    call    InspectAndReport
    mov     ecx, eax
    jmp     cleanup_and_exit

main_fail:
    mov     ecx, 2

cleanup_and_exit:
    mov     rax, qword ptr [rsp+48]
    test    rax, rax
    jz      skip_free
    mov     rcx, rax
    call    LocalFree
skip_free:
    add     rsp, 120
    call    ExitProcess
main ENDP

; ---------------------------------------------------------------------------
; wcs_prefix_equal
; rcx = string, rdx = prefix, r8d = prefix length (characters)
; returns eax=1 when string starts with prefix
; ---------------------------------------------------------------------------
wcs_prefix_equal PROC
    push    rsi
    push    rdi
    mov     rsi, rcx
    mov     rdi, rdx
    mov     ecx, r8d
    test    ecx, ecx
    jle     prefix_fail
prefix_loop:
    movzx   eax, word ptr [rsi]
    movzx   edx, word ptr [rdi]
    cmp     eax, edx
    jne     prefix_fail
    add     rsi, 2
    add     rdi, 2
    dec     ecx
    jz      prefix_success
    jmp     prefix_loop
prefix_success:
    mov     eax, 1
    jmp     prefix_done
prefix_fail:
    xor     eax, eax
prefix_done:
    pop     rdi
    pop     rsi
    ret
wcs_prefix_equal ENDP

; ---------------------------------------------------------------------------
; parse_warn_threshold
; rcx = argument string, rdx = prefix
; ---------------------------------------------------------------------------
parse_warn_threshold PROC
    sub     rsp, 32
    mov     qword ptr [rsp+16], rcx
    mov     qword ptr [rsp+24], rdx
    mov     rcx, qword ptr [rsp+16]
    mov     rdx, qword ptr [rsp+24]
    mov     r8d, WarnPrefixLen
    call    wcs_prefix_equal
    test    eax, eax
    jz      parse_threshold_done
    mov     rcx, qword ptr [rsp+16]
    add     rcx, WarnPrefixLen*2
    xor     rdx, rdx
    call    wcstod
    movsd   qword ptr [gWarnThreshold], xmm0
parse_threshold_done:
    add     rsp, 32
    ret
parse_warn_threshold ENDP

; ---------------------------------------------------------------------------
; InspectAndReport
; rcx = LPCWSTR path
; returns eax = severity (0/1/2)
; ---------------------------------------------------------------------------
InspectAndReport PROC
    sub     rsp, 208
    mov     qword ptr [rsp+32], rcx    ; path
    mov     qword ptr [rsp+40], 0      ; file handle
    mov     qword ptr [rsp+48], 0      ; mapping handle
    mov     qword ptr [rsp+56], 0      ; view pointer
    mov     qword ptr [rsp+64], 0      ; file size (LARGE_INTEGER)

    mov     dword ptr [gSectionCount], 0
    mov     dword ptr [gHeuristicFlags], 0
    mov     dword ptr [gSeverity], SEVERITY_OK
    mov     dword ptr [gImportSize], 0

    ; Open file
    invoke  CreateFileW, qword ptr [rsp+32], GENERIC_READ, FILE_SHARE_READ, 0, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0
    cmp     rax, INVALID_HANDLE_VALUE
    je      inspect_fail
    mov     qword ptr [rsp+40], rax

    ; File size
    invoke  GetFileSizeEx, qword ptr [rsp+40], addr [rsp+64]
    test    eax, eax
    jz      inspect_fail

    ; File mapping
    invoke  CreateFileMappingW, qword ptr [rsp+40], 0, PAGE_READONLY, 0, 0, 0
    test    rax, rax
    jz      inspect_fail
    mov     qword ptr [rsp+48], rax

    ; Map view
    invoke  MapViewOfFile, qword ptr [rsp+48], FILE_MAP_READ, 0, 0, 0
    test    rax, rax
    jz      inspect_fail
    mov     qword ptr [rsp+56], rax

    ; Process mapped image
    mov     rcx, qword ptr [rsp+56]
    mov     rdx, qword ptr [rsp+64]
    call    ProcessMappedImage
    test    eax, eax
    jnz     inspect_fail

    ; Output selection
    mov     eax, dword ptr [gOutputMode]
    cmp     eax, OUTPUT_CSV
    jne     emit_json
    mov     rcx, qword ptr [rsp+32]
    call    EmitCsv
    jmp     gather_result

emit_json:
    mov     rcx, qword ptr [rsp+32]
    call    EmitJson

gather_result:
    mov     eax, dword ptr [gSeverity]
    jmp     inspect_cleanup

inspect_fail:
    mov     eax, SEVERITY_HIGH

inspect_cleanup:
    mov     rax, qword ptr [rsp+56]
    test    rax, rax
    jz      skip_unmap
    invoke  UnmapViewOfFile, rax
skip_unmap:
    mov     rax, qword ptr [rsp+48]
    test    rax, rax
    jz      skip_map_close
    invoke  CloseHandle, rax
skip_map_close:
    mov     rax, qword ptr [rsp+40]
    test    rax, rax
    jz      skip_file_close
    invoke  CloseHandle, rax
skip_file_close:
    add     rsp, 208
    ret
InspectAndReport ENDP

; ---------------------------------------------------------------------------
; ProcessMappedImage
; rcx = base pointer
; rdx = file size
; returns eax = 0 success, non-zero failure
; ---------------------------------------------------------------------------
ProcessMappedImage PROC
    sub     rsp, 224
    mov     qword ptr [rsp+32], rcx    ; base
    mov     qword ptr [rsp+40], rdx    ; size
    mov     qword ptr [rsp+48], 0      ; nt header
    mov     qword ptr [rsp+56], 0      ; file header
    mov     qword ptr [rsp+64], 0      ; optional header
    mov     qword ptr [rsp+72], 0      ; section table
    mov     dword ptr [rsp+80], 0      ; import RVA
    mov     dword ptr [rsp+84], 0      ; optional header size

    mov     rax, qword ptr [rsp+32]
    mov     r8, qword ptr [rsp+40]
    cmp     r8, SIZEOF IMAGE_DOS_HEADER
    jb      process_fail

    movzx   ecx, WORD PTR [rax].IMAGE_DOS_HEADER.e_magic
    cmp     ecx, IMAGE_DOS_SIGNATURE
    jne     process_fail

    mov     edx, DWORD PTR [rax].IMAGE_DOS_HEADER.e_lfanew
    mov     dword ptr [rsp+88], edx
    movsxd  r9, edx
    add     r9, rax
    mov     qword ptr [rsp+48], r9

    ; basic bounds
    sub     r9, rax
    cmp     r9, r8
    jae     process_fail
    mov     r9, qword ptr [rsp+48]

    mov     eax, DWORD PTR [r9]
    cmp     eax, IMAGE_NT_SIGNATURE
    jne     process_fail

    lea     r10, [r9+4]
    mov     qword ptr [rsp+56], r10

    movzx   eax, WORD PTR (IMAGE_FILE_HEADER PTR [r10]).NumberOfSections
    mov     ecx, eax
    cmp     ecx, MAX_SECTIONS
    jbe     set_section_count
    mov     ecx, MAX_SECTIONS
set_section_count:
    mov     dword ptr [gSectionCount], ecx

    movzx   eax, WORD PTR (IMAGE_FILE_HEADER PTR [r10]).SizeOfOptionalHeader
    mov     dword ptr [rsp+84], eax
    lea     rax, [r10+SIZEOF IMAGE_FILE_HEADER]
    mov     qword ptr [rsp+64], rax

    ; Determine import directory
    mov     rax, qword ptr [rsp+64]
    movzx   eax, WORD PTR (IMAGE_OPTIONAL_HEADER64 PTR [rax]).Magic
    cmp     ax, IMAGE_NT_OPTIONAL_HDR64_MAGIC
    je      optional64
    cmp     ax, IMAGE_NT_OPTIONAL_HDR32_MAGIC
    je      optional32
    jmp     process_fail

optional64:
    mov     rax, qword ptr [rsp+64]
    mov     eax, DWORD PTR (IMAGE_OPTIONAL_HEADER64 PTR [rax]).NumberOfRvaAndSizes
    cmp     eax, IMAGE_DIRECTORY_ENTRY_IMPORT+1
    jb      no_import_dir
    mov     rax, qword ptr [rsp+64]
    lea     rax, [rax + IMAGE_OPTIONAL_HEADER64.DataDirectory]
    mov     edx, DWORD PTR [rax + IMAGE_DIRECTORY_ENTRY_IMPORT*SIZEOF IMAGE_DATA_DIRECTORY]
    mov     dword ptr [rsp+80], edx
    mov     edx, DWORD PTR [rax + IMAGE_DIRECTORY_ENTRY_IMPORT*SIZEOF IMAGE_DATA_DIRECTORY + 4]
    mov     dword ptr [gImportSize], edx
    jmp     after_import

optional32:
    mov     rax, qword ptr [rsp+64]
    mov     eax, DWORD PTR (IMAGE_OPTIONAL_HEADER32 PTR [rax]).NumberOfRvaAndSizes
    cmp     eax, IMAGE_DIRECTORY_ENTRY_IMPORT+1
    jb      no_import_dir
    mov     rax, qword ptr [rsp+64]
    lea     rax, [rax + IMAGE_OPTIONAL_HEADER32.DataDirectory]
    mov     edx, DWORD PTR [rax + IMAGE_DIRECTORY_ENTRY_IMPORT*SIZEOF IMAGE_DATA_DIRECTORY]
    mov     dword ptr [rsp+80], edx
    mov     edx, DWORD PTR [rax + IMAGE_DIRECTORY_ENTRY_IMPORT*SIZEOF IMAGE_DATA_DIRECTORY + 4]
    mov     dword ptr [gImportSize], edx
    jmp     after_import

no_import_dir:
    mov     dword ptr [rsp+80], 0
    mov     dword ptr [gImportSize], 0

after_import:
    mov     eax, dword ptr [rsp+84]
    movsxd  rax, eax
    mov     rdx, qword ptr [rsp+64]
    lea     rdx, [rdx+rax]
    mov     qword ptr [rsp+72], rdx

    mov     ecx, dword ptr [gSectionCount]
    cmp     ecx, 0
    je      post_sections

    mov     dword ptr [rsp+92], 0       ; loop index

section_loop:
    mov     eax, dword ptr [rsp+92]
    cmp     eax, ecx
    jge     post_sections

    mov     rdx, qword ptr [rsp+72]
    mov     rax, eax
    imul    rax, IMAGE_SECTION_HEADER_SIZE
    add     rdx, rax                    ; section header pointer

    mov     rax, dword ptr [rsp+92]
    imul    rax, SectionInfoSize
    lea     r10, gSectionInfos
    add     r10, rax                    ; SectionInfo pointer

    ; Copy basic metadata
    mov     rax, QWORD PTR [rdx + SEC_OFF_NAME]
    mov     QWORD PTR [r10 + SectionInfo.Name], rax
    mov     eax, DWORD PTR [rdx + SEC_OFF_VIRTUALSIZE]
    mov     DWORD PTR [r10 + SectionInfo.VirtualSize], eax
    mov     eax, DWORD PTR [rdx + SEC_OFF_RAWSIZE]
    mov     DWORD PTR [r10 + SectionInfo.RawSize], eax
    mov     eax, DWORD PTR [rdx + SEC_OFF_CHARACTERISTICS]
    mov     DWORD PTR [r10 + SectionInfo.Characteristics], eax
    mov     DWORD PTR [r10 + SectionInfo.Flags], 0

    mov     eax, DWORD PTR [rdx + SEC_OFF_POINTERTORAW]
    mov     dword ptr [rsp+96], eax     ; raw offset

    mov     rcx, qword ptr [rsp+32]
    mov     eax, dword ptr [rsp+96]
    movsxd  rax, eax
    add     rcx, rax
    mov     qword ptr [rsp+104], rcx    ; section data pointer

    mov     r9, qword ptr [rsp+40]      ; file size
    mov     eax, dword ptr [rsp+96]
    movsxd  r10, eax
    cmp     r10, r9
    jae     zero_entropy
    sub     r9, r10
    mov     eax, DWORD PTR [r10 + SectionInfo.RawSize]
    movsxd  r11, eax
    cmp     r11, r9
    jbe     size_ok
    mov     r11, r9
size_ok:
    test    r11, r11
    jz      zero_entropy
    mov     rcx, qword ptr [rsp+104]
    mov     rdx, r11
    call    ComputeEntropy
    movsd   QWORD PTR [r10 + SectionInfo.Entropy], xmm0
    jmp     entropy_done

zero_entropy:
    pxor    xmm0, xmm0
    movsd   QWORD PTR [r10 + SectionInfo.Entropy], xmm0

entropy_done:
    mov     eax, DWORD PTR [r10 + SectionInfo.Characteristics]
    test    eax, IMAGE_SCN_MEM_EXECUTE
    jz      skip_exec_flag
    or      DWORD PTR [r10 + SectionInfo.Flags], SECTION_FLAG_EXEC
skip_exec_flag:
    test    eax, IMAGE_SCN_MEM_WRITE
    jz      skip_write_flag
    or      DWORD PTR [r10 + SectionInfo.Flags], SECTION_FLAG_WRITE
skip_write_flag:

    ; high entropy heuristic for .text
    lea     rcx, [r10 + SectionInfo.Name]
    lea     rdx, TextSectionName
    mov     r8d, 5
    invoke  memcmp, rcx, rdx, r8d
    test    eax, eax
    jne     skip_text
    movsd   xmm1, QWORD PTR [r10 + SectionInfo.Entropy]
    movsd   xmm2, QWORD PTR [gWarnThreshold]
    comisd  xmm1, xmm2
    jb      skip_text
    or      dword ptr [gHeuristicFlags], HEURISTIC_HIGH_ENTROPY_TEXT
    or      DWORD PTR [r10 + SectionInfo.Flags], SECTION_FLAG_HIGH_ENTROPY
skip_text:

    ; Large section heuristic
    mov     eax, DWORD PTR [r10 + SectionInfo.RawSize]
    cmp     eax, LargeSectionThreshold
    jbe     skip_large
    or      dword ptr [gHeuristicFlags], HEURISTIC_LARGE_SECTION
skip_large:

    ; Suspicious flags (exec + write)
    mov     eax, DWORD PTR [r10 + SectionInfo.Characteristics]
    test    eax, IMAGE_SCN_MEM_EXECUTE
    jz      skip_suspicious
    test    eax, IMAGE_SCN_MEM_WRITE
    jz      skip_suspicious
    or      dword ptr [gHeuristicFlags], HEURISTIC_SUSPICIOUS_FLAGS
skip_suspicious:

    inc     dword ptr [rsp+92]
    jmp     section_loop

post_sections:
    ; No imports heuristic
    mov     eax, dword ptr [gImportSize]
    test    eax, eax
    jnz     imports_ok
    or      dword ptr [gHeuristicFlags], HEURISTIC_NO_IMPORTS
imports_ok:

    ; Single section heuristic
    mov     eax, dword ptr [gSectionCount]
    cmp     eax, 1
    jne     multi_section
    or      dword ptr [gHeuristicFlags], HEURISTIC_SINGLE_SECTION
multi_section:

    ; Severity computation
    mov     eax, dword ptr [gHeuristicFlags]
    mov     edx, SEVERITY_OK
    test    eax, HEURISTIC_HIGH_ENTROPY_TEXT or HEURISTIC_NO_IMPORTS
    jz      check_warn
    mov     edx, SEVERITY_HIGH
    jmp     store_severity
check_warn:
    test    eax, HEURISTIC_SINGLE_SECTION or HEURISTIC_LARGE_SECTION or HEURISTIC_SUSPICIOUS_FLAGS
    jz      store_severity
    mov     edx, SEVERITY_WARN
store_severity:
    mov     dword ptr [gSeverity], edx

    add     rsp, 224
    xor     eax, eax
    ret

process_fail:
    add     rsp, 224
    mov     eax, 1
    ret
ProcessMappedImage ENDP

; ---------------------------------------------------------------------------
; ComputeEntropy
; rcx = data pointer, rdx = length
; returns entropy in xmm0
; ---------------------------------------------------------------------------
ComputeEntropy PROC
    sub     rsp, 2080
    mov     qword ptr [rsp+16], rcx
    mov     qword ptr [rsp+24], rdx

    lea     rcx, [rsp+32]
    xor     edx, edx
    mov     r8d, 2048
    invoke  memset, rcx, edx, r8d

    mov     rdx, qword ptr [rsp+24]
    test    rdx, rdx
    jnz     entropy_count
    pxor    xmm0, xmm0
    add     rsp, 2080
    ret

entropy_count:
    mov     rcx, qword ptr [rsp+16]
    lea     r8, [rsp+32]
    xor     r9, r9

count_loop:
    cmp     r9, rdx
    jae     count_done
    movzx   eax, BYTE PTR [rcx+r9]
    lea     r10, [r8 + rax*8]
    inc     QWORD PTR [r10]
    inc     r9
    jmp     count_loop

count_done:
    cvtsi2sd xmm7, rdx
    movsd   xmm6, InvLn2
    pxor    xmm5, xmm5
    mov     ecx, 0

entropy_loop:
    cmp     ecx, 256
    jge     entropy_finish
    mov     rax, QWORD PTR [r8 + rcx*8]
    test    rax, rax
    jz      entropy_next
    cvtsi2sd xmm1, rax
    divsd   xmm1, xmm7
    movapd  xmm0, xmm1
    call    log
    mulsd   xmm0, xmm1
    mulsd   xmm0, xmm6
    subsd   xmm5, xmm0
entropy_next:
    inc     ecx
    jmp     entropy_loop

entropy_finish:
    movapd  xmm0, xmm5
    add     rsp, 2080
    ret
ComputeEntropy ENDP

; ---------------------------------------------------------------------------
; EmitJson
; rcx = LPCWSTR path
; ---------------------------------------------------------------------------
EmitJson PROC
    sub     rsp, 272
    mov     qword ptr [rsp+32], rcx
    mov     qword ptr [rsp+40], 0
    mov     dword ptr [rsp+48], 0
    mov     dword ptr [rsp+52], 0

    mov     rcx, qword ptr [rsp+32]
    call    ConvertPathToUtf8
    mov     qword ptr [rsp+40], rax
    test    rax, rax
    jne     json_path_ready
    lea     rax, UnknownFileStr
    mov     qword ptr [rsp+40], rax
json_path_ready:
    mov     rax, qword ptr [rsp+40]
    sub     rsp, 40
    mov     rcx, OFFSET JsonFileStart
    mov     rdx, rax
    call    printf
    add     rsp, 40

    mov     eax, dword ptr [gSectionCount]
    mov     dword ptr [rsp+48], eax
    mov     dword ptr [rsp+52], 0

json_section_loop:
    mov     eax, dword ptr [rsp+52]
    cmp     eax, dword ptr [rsp+48]
    jge     json_sections_done

    cmp     eax, 0
    je      json_skip_comma
    sub     rsp, 40
    mov     rcx, OFFSET JsonComma
    call    printf
    add     rsp, 40
json_skip_comma:
    mov     eax, dword ptr [rsp+52]
    imul    rax, SectionInfoSize
    lea     rcx, gSectionInfos
    add     rax, rcx
    mov     qword ptr [rsp+200], rax        ; SectionInfo pointer

    mov     rcx, qword ptr [rsp+200]
    lea     rdx, [rsp+64]
    call    PrepareSectionName
    mov     qword ptr [rsp+208], rax        ; name buffer

    mov     rcx, qword ptr [rsp+200]
    mov     eax, DWORD PTR [rcx + SectionInfo.Flags]
    mov     r10, OFFSET FalseStr
    test    eax, SECTION_FLAG_EXEC
    jz      json_exec_set
    mov     r10, OFFSET TrueStr
json_exec_set:
    mov     r11, OFFSET FalseStr
    test    eax, SECTION_FLAG_WRITE
    jz      json_write_set
    mov     r11, OFFSET TrueStr
json_write_set:
    mov     qword ptr [rsp+216], r10
    mov     qword ptr [rsp+224], r11

    mov     rax, qword ptr [rsp+200]
    mov     r8d, DWORD PTR [rax + SectionInfo.RawSize]
    mov     r9d, DWORD PTR [rax + SectionInfo.VirtualSize]
    movsd   xmm0, QWORD PTR [rax + SectionInfo.Entropy]
    mov     edx, DWORD PTR [rax + SectionInfo.Characteristics]
    mov     qword ptr [rsp+232], rdx

    mov     rdx, qword ptr [rsp+208]
    mov     rcx, OFFSET JsonSectionFmt
    mov     r10, qword ptr [rsp+216]
    mov     r11, qword ptr [rsp+224]

    sub     rsp, 64
    movsd   qword ptr [rsp+32], xmm0
    mov     qword ptr [rsp+40], r10
    mov     qword ptr [rsp+48], r11
    mov     rax, qword ptr [rsp+232]
    mov     qword ptr [rsp+56], rax
    call    printf
    add     rsp, 64

    inc     dword ptr [rsp+52]
    jmp     json_section_loop

json_sections_done:
    sub     rsp, 40
    mov     rcx, OFFSET JsonSectionsEnd
    call    printf
    add     rsp, 40

    call    EmitHeuristicsJson

    sub     rsp, 40
    mov     rcx, OFFSET JsonHeurEnd
    mov     edx, dword ptr [gSeverity]
    call    printf
    add     rsp, 40

    add     rsp, 272
    ret
EmitJson ENDP

; ---------------------------------------------------------------------------
; EmitHeuristicsJson
; ---------------------------------------------------------------------------
EmitHeuristicsJson PROC
    sub     rsp, 64
    mov     eax, dword ptr [gHeuristicFlags]
    test    eax, eax
    jz      json_heuristics_empty

    mov     qword ptr [rsp+32], OFFSET HeuristicTable
    mov     dword ptr [rsp+40], 0

json_heur_loop:
    mov     rax, qword ptr [rsp+32]
    mov     qword ptr [rsp+48], rax
    mov     rdx, qword ptr [rax]
    test    rdx, rdx
    jz      json_heur_done

    mov     eax, dword ptr [gHeuristicFlags]
    test    eax, edx
    jz      json_heur_next

    cmp     dword ptr [rsp+40], 0
    je      json_heur_print
    sub     rsp, 40
    mov     rcx, OFFSET JsonComma
    call    printf
    add     rsp, 40

json_heur_print:
    mov     rax, qword ptr [rsp+48]
    sub     rsp, 40
    mov     rcx, OFFSET JsonHeurFmt
    mov     rdx, qword ptr [rax+8]
    mov     r8, qword ptr [rax+16]
    call    printf
    add     rsp, 40
    inc     dword ptr [rsp+40]

json_heur_next:
    mov     rax, qword ptr [rsp+32]
    add     rax, 24
    mov     qword ptr [rsp+32], rax
    jmp     json_heur_loop

json_heur_done:
    add     rsp, 64
    ret

json_heuristics_empty:
    add     rsp, 64
    ret
EmitHeuristicsJson ENDP

; ---------------------------------------------------------------------------
; EmitCsv
; rcx = path (unused for now)
; ---------------------------------------------------------------------------
EmitCsv PROC
    sub     rsp, 272

    sub     rsp, 40
    mov     rcx, OFFSET CsvHeader
    call    printf
    add     rsp, 40

    mov     dword ptr [rsp+48], dword ptr [gSectionCount]
    mov     dword ptr [rsp+52], 0

csv_section_loop:
    mov     eax, dword ptr [rsp+52]
    cmp     eax, dword ptr [rsp+48]
    jge     csv_sections_done

    mov     eax, dword ptr [rsp+52]
    imul    rax, SectionInfoSize
    lea     rcx, gSectionInfos
    add     rax, rcx
    mov     qword ptr [rsp+200], rax

    mov     rcx, qword ptr [rsp+200]
    lea     rdx, [rsp+64]
    call    PrepareSectionName
    mov     qword ptr [rsp+208], rax

    mov     rcx, qword ptr [rsp+200]
    mov     eax, DWORD PTR [rcx + SectionInfo.Flags]
    test    eax, SECTION_FLAG_EXEC
    setnz   dl
    movzx   edx, dl
    mov     dword ptr [rsp+216], edx
    test    eax, SECTION_FLAG_WRITE
    setnz   dl
    movzx   edx, dl
    mov     dword ptr [rsp+220], edx

    mov     rax, qword ptr [rsp+200]
    mov     r8d, DWORD PTR [rax + SectionInfo.RawSize]
    mov     r9d, DWORD PTR [rax + SectionInfo.VirtualSize]
    movsd   xmm0, QWORD PTR [rax + SectionInfo.Entropy]
    mov     edx, DWORD PTR [rax + SectionInfo.Characteristics]
    mov     qword ptr [rsp+232], rdx

    mov     rcx, OFFSET CsvSectionFmt
    mov     rdx, qword ptr [rsp+208]

    sub     rsp, 64
    movsd   qword ptr [rsp+32], xmm0
    mov     eax, dword ptr [rsp+216]
    mov     qword ptr [rsp+40], rax
    mov     eax, dword ptr [rsp+220]
    mov     qword ptr [rsp+48], rax
    mov     rax, qword ptr [rsp+232]
    mov     qword ptr [rsp+56], rax
    call    printf
    add     rsp, 64

    inc     dword ptr [rsp+52]
    jmp     csv_section_loop

csv_sections_done:
    sub     rsp, 40
    mov     rcx, OFFSET CsvHeurHeader
    call    printf
    add     rsp, 40

    call    EmitHeuristicsCsv

    sub     rsp, 40
    mov     rcx, OFFSET CsvSummaryFmt
    mov     edx, dword ptr [gSeverity]
    call    printf
    add     rsp, 40

    add     rsp, 272
    ret
EmitCsv ENDP

; ---------------------------------------------------------------------------
; EmitHeuristicsCsv
; ---------------------------------------------------------------------------
EmitHeuristicsCsv PROC
    sub     rsp, 48
    mov     eax, dword ptr [gHeuristicFlags]
    test    eax, eax
    jz      csv_heur_empty

    mov     qword ptr [rsp+32], OFFSET HeuristicTable

csv_heur_loop:
    mov     rax, qword ptr [rsp+32]
    mov     qword ptr [rsp+40], rax
    mov     rdx, qword ptr [rax]
    test    rdx, rdx
    jz      csv_heur_done
    mov     eax, dword ptr [gHeuristicFlags]
    test    eax, edx
    jz      csv_heur_next
    mov     rax, qword ptr [rsp+40]
    sub     rsp, 40
    mov     rcx, OFFSET CsvHeurFmt
    mov     rdx, qword ptr [rax+8]
    mov     r8, qword ptr [rax+16]
    call    printf
    add     rsp, 40
csv_heur_next:
    mov     rax, qword ptr [rsp+32]
    add     rax, 24
    mov     qword ptr [rsp+32], rax
    jmp     csv_heur_loop

csv_heur_done:
    add     rsp, 48
    ret

csv_heur_empty:
    add     rsp, 48
    ret
EmitHeuristicsCsv ENDP

; ---------------------------------------------------------------------------
; PrepareSectionName
; rcx = SectionInfo pointer, rdx = destination buffer (>=9 bytes)
; returns rax = destination buffer
; ---------------------------------------------------------------------------
PrepareSectionName PROC
    mov     rax, QWORD PTR [rcx + SectionInfo.Name]
    mov     QWORD PTR [rdx], rax
    mov     BYTE PTR [rdx+8], 0
    mov     ecx, 0
prep_loop:
    cmp     ecx, 8
    jge     prep_done
    mov     al, BYTE PTR [rdx+ecx]
    cmp     al, 0
    je      prep_done
    cmp     al, 32
    jb      replace_char
    cmp     al, 126
    jbe     next_char
replace_char:
    mov     BYTE PTR [rdx+ecx], '_'
next_char:
    inc     ecx
    jmp     prep_loop
prep_done:
    mov     rax, rdx
    ret
PrepareSectionName ENDP

; ---------------------------------------------------------------------------
; ConvertPathToUtf8
; rcx = LPCWSTR
; returns rax = pointer to UTF-8 buffer or 0 on failure
; ---------------------------------------------------------------------------
ConvertPathToUtf8 PROC
    sub     rsp, 64
    mov     qword ptr [rsp+32], rcx

    invoke  WideCharToMultiByte, CP_UTF8, 0, qword ptr [rsp+32], -1, 0, 0, 0, 0
    test    eax, eax
    jz      convert_fail
    mov     dword ptr [rsp+44], eax
    lea     rax, gUtf8PathBuffer
    mov     qword ptr [rsp+24], rax
    invoke  WideCharToMultiByte, CP_UTF8, 0, qword ptr [rsp+32], -1, rax, dword ptr [rsp+44], 0, 0
    test    eax, eax
    jz      convert_fail
    lea     rax, gUtf8PathBuffer
    add     rsp, 64
    ret

convert_fail:
    xor     eax, eax
    add     rsp, 64
    ret
ConvertPathToUtf8 ENDP

END
