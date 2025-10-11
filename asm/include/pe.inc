; ---------------------------------------------------------------------------
; pe.inc
; Basic PE structure definitions and constants for the PE Inspector project.
; ---------------------------------------------------------------------------

option casemap:none

IMAGE_DOS_SIGNATURE      equ     5A4Dh          ; 'MZ'
IMAGE_NT_SIGNATURE       equ     00004550h      ; 'PE\0\0'

IMAGE_NUMBEROF_DIRECTORY_ENTRIES equ 16

IMAGE_DIRECTORY_ENTRY_EXPORT            equ 0
IMAGE_DIRECTORY_ENTRY_IMPORT            equ 1
IMAGE_DIRECTORY_ENTRY_RESOURCE          equ 2
IMAGE_DIRECTORY_ENTRY_EXCEPTION         equ 3
IMAGE_DIRECTORY_ENTRY_SECURITY          equ 4
IMAGE_DIRECTORY_ENTRY_BASERELOC         equ 5
IMAGE_DIRECTORY_ENTRY_DEBUG             equ 6
IMAGE_DIRECTORY_ENTRY_ARCHITECTURE      equ 7
IMAGE_DIRECTORY_ENTRY_GLOBALPTR         equ 8
IMAGE_DIRECTORY_ENTRY_TLS               equ 9
IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG       equ 10
IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT      equ 11
IMAGE_DIRECTORY_ENTRY_IAT               equ 12
IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT      equ 13
IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR    equ 14

; ---------------------------------------------------------------------------
; Structure definitions
; ---------------------------------------------------------------------------

IMAGE_DOS_HEADER STRUCT
    e_magic             WORD    ?
    e_cblp              WORD    ?
    e_cp                WORD    ?
    e_crlc              WORD    ?
    e_cparhdr           WORD    ?
    e_minalloc          WORD    ?
    e_maxalloc          WORD    ?
    e_ss                WORD    ?
    e_sp                WORD    ?
    e_csum              WORD    ?
    e_ip                WORD    ?
    e_cs                WORD    ?
    e_lfarlc            WORD    ?
    e_ovno              WORD    ?
    e_res               WORD    4 DUP(?)
    e_oemid             WORD    ?
    e_oeminfo           WORD    ?
    e_res2              WORD    10 DUP(?)
    e_lfanew            DWORD   ?
IMAGE_DOS_HEADER ENDS

IMAGE_FILE_HEADER STRUCT
    Machine                     WORD    ?
    NumberOfSections            WORD    ?
    TimeDateStamp               DWORD   ?
    PointerToSymbolTable        DWORD   ?
    NumberOfSymbols             DWORD   ?
    SizeOfOptionalHeader        WORD    ?
    Characteristics             WORD    ?
IMAGE_FILE_HEADER ENDS

IMAGE_DATA_DIRECTORY STRUCT
    VirtualAddress  DWORD ?
    Size            DWORD ?
IMAGE_DATA_DIRECTORY ENDS

IMAGE_OPTIONAL_HEADER64 STRUCT
    Magic                       WORD    ?
    MajorLinkerVersion          BYTE    ?
    MinorLinkerVersion          BYTE    ?
    SizeOfCode                  DWORD   ?
    SizeOfInitializedData       DWORD   ?
    SizeOfUninitializedData     DWORD   ?
    AddressOfEntryPoint         DWORD   ?
    BaseOfCode                  DWORD   ?
    ImageBase                   QWORD   ?
    SectionAlignment            DWORD   ?
    FileAlignment               DWORD   ?
    MajorOperatingSystemVersion WORD    ?
    MinorOperatingSystemVersion WORD    ?
    MajorImageVersion           WORD    ?
    MinorImageVersion           WORD    ?
    MajorSubsystemVersion       WORD    ?
    MinorSubsystemVersion       WORD    ?
    Win32VersionValue           DWORD   ?
    SizeOfImage                 DWORD   ?
    SizeOfHeaders               DWORD   ?
    CheckSum                    DWORD   ?
    Subsystem                   WORD    ?
    DllCharacteristics          WORD    ?
    SizeOfStackReserve          QWORD   ?
    SizeOfStackCommit           QWORD   ?
    SizeOfHeapReserve           QWORD   ?
    SizeOfHeapCommit            QWORD   ?
    LoaderFlags                 DWORD   ?
    NumberOfRvaAndSizes         DWORD   ?
    DataDirectory               IMAGE_DATA_DIRECTORY IMAGE_NUMBEROF_DIRECTORY_ENTRIES DUP(<>)
IMAGE_OPTIONAL_HEADER64 ENDS

IMAGE_SECTION_HEADER STRUCT
    Name                BYTE    8 DUP(?)
    VirtualSize         DWORD   ?
    VirtualAddress      DWORD   ?
    SizeOfRawData       DWORD   ?
    PointerToRawData    DWORD   ?
    PointerToRelocations    DWORD   ?
    PointerToLinenumbers    DWORD   ?
    NumberOfRelocations WORD ?
    NumberOfLinenumbers WORD ?
    Characteristics     DWORD ?
IMAGE_SECTION_HEADER ENDS

IMAGE_OPTIONAL_HEADER32 STRUCT
    Magic                       WORD    ?
    MajorLinkerVersion          BYTE    ?
    MinorLinkerVersion          BYTE    ?
    SizeOfCode                  DWORD   ?
    SizeOfInitializedData       DWORD   ?
    SizeOfUninitializedData     DWORD   ?
    AddressOfEntryPoint         DWORD   ?
    BaseOfCode                  DWORD   ?
    BaseOfData                  DWORD   ?
    ImageBase                   DWORD   ?
    SectionAlignment            DWORD   ?
    FileAlignment               DWORD   ?
    MajorOperatingSystemVersion WORD    ?
    MinorOperatingSystemVersion WORD    ?
    MajorImageVersion           WORD    ?
    MinorImageVersion           WORD    ?
    MajorSubsystemVersion       WORD    ?
    MinorSubsystemVersion       WORD    ?
    Win32VersionValue           DWORD   ?
    SizeOfImage                 DWORD   ?
    SizeOfHeaders               DWORD   ?
    CheckSum                    DWORD   ?
    Subsystem                   WORD    ?
    DllCharacteristics          WORD    ?
    SizeOfStackReserve          DWORD   ?
    SizeOfStackCommit           DWORD   ?
    SizeOfHeapReserve           DWORD   ?
    SizeOfHeapCommit            DWORD   ?
    LoaderFlags                 DWORD   ?
    NumberOfRvaAndSizes         DWORD   ?
    DataDirectory               IMAGE_DATA_DIRECTORY IMAGE_NUMBEROF_DIRECTORY_ENTRIES DUP(<>)
IMAGE_OPTIONAL_HEADER32 ENDS

; Optional header magic values
IMAGE_NT_OPTIONAL_HDR32_MAGIC    equ 010Bh
IMAGE_NT_OPTIONAL_HDR64_MAGIC    equ 020Bh

; Section characteristics bits (subset)
IMAGE_SCN_MEM_EXECUTE    equ 20000000h
IMAGE_SCN_MEM_READ       equ 40000000h
IMAGE_SCN_MEM_WRITE      equ 80000000h

; File characteristics
IMAGE_FILE_EXECUTABLE_IMAGE  equ 0002h
IMAGE_FILE_DLL               equ 2000h

; Severity codes
SEVERITY_OK         equ 0
SEVERITY_WARN       equ 1
SEVERITY_HIGH       equ 2

; CLI flags
OUTPUT_JSON         equ 1
OUTPUT_CSV          equ 2

; Buffer sizes
MAX_SECTIONS        equ 32
MAX_PATH_CHARS      equ 512
OUTPUT_BUFFER_SIZE  equ 16384

; Heuristic bit field flags
HEURISTIC_HIGH_ENTROPY_TEXT    equ 0001h
HEURISTIC_NO_IMPORTS           equ 0002h
HEURISTIC_SINGLE_SECTION       equ 0004h
HEURISTIC_LARGE_SECTION        equ 0008h
HEURISTIC_SUSPICIOUS_FLAGS     equ 0010h

SectionInfo STRUCT
    Name            BYTE    8 DUP(?)
    VirtualSize     DWORD   ?
    RawSize         DWORD   ?
    Entropy         REAL8   ?
    Characteristics DWORD   ?
    Flags           DWORD   ?
SectionInfo ENDS

; Win32 constants
GENERIC_READ            equ 80000000h
FILE_SHARE_READ         equ 00000001h
OPEN_EXISTING           equ 3
FILE_ATTRIBUTE_NORMAL   equ 00000080h
PAGE_READONLY           equ 2
FILE_MAP_READ           equ 00000004h
INVALID_HANDLE_VALUE    equ -1

STD_OUTPUT_HANDLE       equ -11
STD_ERROR_HANDLE        equ -12

CP_UTF8                 equ 65001

SECTION_FLAG_EXEC           equ 0001h
SECTION_FLAG_WRITE          equ 0002h
SECTION_FLAG_HIGH_ENTROPY   equ 0004h
