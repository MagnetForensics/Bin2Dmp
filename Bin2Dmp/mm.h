/*++
    Copyright (C) 2010 Matthieu Suiche http://www.msuiche.net 
    Copyright (C) 2010 MoonSols. <http://www.moonsols.com>
    Copyright (c) 2017 - 2018, Comae Technologies DMCC
    All rights reserved.

Module Name:

    - mm.h

Abstract:

    - 


Environment:

    - User mode

Revision History:

    - Matthieu Suiche (Jan-2010)

--*/

//
// Page-Map-Level-4 Table Entry
//
typedef struct _X64_PML4TE {
    union {
        struct {
            ULONGLONG Present:1;
            ULONGLONG ReadWrite:1;
            ULONGLONG UserSupervisor:1;
            ULONGLONG WriteThrough:1;
            ULONGLONG CacheDisabled:1;
            ULONGLONG Accessed:1;
            ULONGLONG Reserved00:3;
            ULONGLONG Available00:3;
            ULONGLONG PageFrameNumber:28;
            ULONGLONG Reserved01:12;
            ULONGLONG Available01:11;
            ULONGLONG ExecuteDisabled:1;
        } Entry;
        LARGE_INTEGER Data;
    };
} X64_PML4TE, *PX64_PML4TE;

typedef struct _X64_PDPTE {
    union {
        struct {
            ULONGLONG Present:1;
            ULONGLONG ReadWrite:1;
            ULONGLONG UserSupervisor:1;
            ULONGLONG WriteThrough:1;
            ULONGLONG CacheDisabled:1;
            ULONGLONG Accessed:1;
            ULONGLONG Reserved00:3;
            ULONGLONG Available00:3;
            ULONGLONG PageFrameNumber:28;
            ULONGLONG Reserved01:12;
            ULONGLONG Available01:11;
            ULONGLONG eXecuteDisabled:1;
        } Entry;
        LARGE_INTEGER Data;
    };
} X64_PDPTE, *PX64_PDPTE;

typedef struct _X64_PDE {
    union {
        struct {
            ULONGLONG Present:1;
            ULONGLONG ReadWrite:1;
            ULONGLONG UserSupervisor:1;
            ULONGLONG WriteThrough:1;
            ULONGLONG CacheDisabled:1;
            ULONGLONG Accessed:1;
            ULONGLONG Dirty:1;
            ULONGLONG PageSize:1;
            ULONGLONG Global:1;
            ULONGLONG Available00:3;
            ULONGLONG PageFrameNumber:28;
            ULONGLONG Reserved01:12;
            ULONGLONG Available01:11;
            ULONGLONG eXecuteDisabled:1;
        } Entry;
        LARGE_INTEGER Data;
    };
} X64_PDE, *PX64_PDE;

typedef struct _X64_PDE_LARGE {
    union {
        struct {
            ULONGLONG Present:1;
            ULONGLONG ReadWrite:1;
            ULONGLONG UserSupervisor:1;
            ULONGLONG WriteThrough:1;
            ULONGLONG CacheDisabled:1;
            ULONGLONG Accessed:1;
            ULONGLONG Dirty:1;
            ULONGLONG PageSize:1;
            ULONGLONG Global:1;
            ULONGLONG Available00:3;
            ULONGLONG PageTableAttributeIndex:1;
            ULONGLONG Reserved00:8;
            ULONGLONG PageFrameNumber:19;
            ULONGLONG Reserved01:12;
            ULONGLONG Available01:11;
            ULONGLONG eXecuteDisabled:1;
        } Entry;
        LARGE_INTEGER Data;
    };
} X64_PDE_LARGE, *PX64_PDE_LARGE;

typedef struct _X64_PTE {
    union {
        struct {
            ULONGLONG Present:1;
            ULONGLONG ReadWrite:1;
            ULONGLONG UserSupervisor:1;
            ULONGLONG WriteThrough:1;
            ULONGLONG CacheDisabled:1;
            ULONGLONG Accessed:1;
            ULONGLONG Dirty:1;
            ULONGLONG PageSize:1;
            ULONGLONG Global:1;
            ULONGLONG Available00:3;
            ULONGLONG PageFrameNumber:28;
            ULONGLONG Reserved01:12;
            ULONGLONG Available01:11;
            ULONGLONG eXecuteDisabled:1;
        } Entry;
        LARGE_INTEGER Data;
    };
} X64_PTE, *PX64_PTE;
//
// x64 memory management
//

#define X64_LARGE_PAGE_SIZE         (2 * 1024 * 1024)

#define X64_GET_PML4TI(Va)          (ULONG)((((ULONGLONG)Va) >> 39) & 0x1ff)
#define X64_GET_PDPTI(Va)           (ULONG)((((ULONGLONG)Va) >> 30) & 0x1ff)
#define X64_GET_PDTI(Va)            (ULONG)((((ULONGLONG)Va) >> 21) & 0x1ff)
#define X64_GET_OFFSET_LARGE(Va)    (ULONG)(((ULONGLONG)Va) & 0x1fffff)
#define X64_GET_PTTI(Va)            (ULONG)((((ULONGLONG)Va) >> 12) & 0x1ff)
#define X64_GET_OFFSET(Va)          (ULONG)(((ULONGLONG)Va) & 0xfff)

//
// x86 memory management
//

//
// Page-Directory-Pointer Table Entry
//
#define X86_LARGE_PAGE_SIZE_PAE         (2 * 1024 * 1024)

#define X86_GET_PDPTI_PAE(Va)           (ULONG)((((ULONGLONG)Va) >> 30) & 0x3)
#define X86_GET_PDTI_PAE(Va)            (ULONG)((((ULONGLONG)Va) >> 21) & 0x1ff)
#define X86_GET_OFFSET_LARGE_PAE(Va)    (ULONG)(((ULONGLONG)Va) & (X86_LARGE_PAGE_SIZE_PAE - 1))
#define X86_GET_PTTI_PAE(Va)            (ULONG)((((ULONGLONG)Va) >> 12) & 0x1ff)
#define X86_GET_OFFSET_PAE(Va)          (ULONG)(((ULONGLONG)Va) & 0xfff)

//
// NO PAE x86
//
#define X86_LARGE_PAGE_SIZE             (4 * 1024 * 1024)
#define X86_GET_PDTI(Va)          (ULONG)((((ULONGLONG)Va) >> 22) & 0x3ff)
#define X86_GET_OFFSET_LARGE(Va)  (ULONG)(((ULONGLONG)Va) & 0x3fffff)
#define X86_GET_PTTI(Va)          (ULONG)((((ULONGLONG)Va) >> 12) & 0x3ff)
#define X86_GET_OFFSET(Va)        (ULONG)(((ULONGLONG)Va) & 0xfff)

#define MAX_PDPT_ENTRY 4
typedef struct _X86_PDPTE {
    union {
        struct {
            ULONGLONG Present:1;
            ULONGLONG Reserved00:2;
            ULONGLONG WriteThrough:1;
            ULONGLONG CacheDisabled:1;
            ULONGLONG Reserved01:4;
            ULONGLONG Available00:3;
            ULONGLONG PageFrameNumber:24;
            ULONGLONG Reserved02:28;
        } Entry;
        LARGE_INTEGER Data;
    };
} X86_PDPTE, *PX86_PDPTE;

typedef struct _X86_PDE_PAE {
    union {
        struct {
            ULONGLONG Present:1;
            ULONGLONG ReadWrite:1;
            ULONGLONG UserSupervisor:1;
            ULONGLONG WriteThrough:1;
            ULONGLONG CacheDisabled:1;
            ULONGLONG Accessed:1;
            ULONGLONG Reserved00:1;
            ULONGLONG PageSize:1;
            ULONGLONG Global:1;
            ULONGLONG Available00:3;
            ULONGLONG PageFrameNumber:24;
            ULONGLONG Reserved02:28;
        } Entry;
        LARGE_INTEGER Data;
    };
} X86_PDE_PAE, *PX86_PDE_PAE;

typedef struct _X86_PDE_PAE_LARGE {
    union {
        struct {
            ULONGLONG Present:1;
            ULONGLONG ReadWrite:1;
            ULONGLONG UserSupervisor:1;
            ULONGLONG WriteThrough:1;
            ULONGLONG CacheDisabled:1;
            ULONGLONG Accessed:1;
            ULONGLONG Dirty:1;
            ULONGLONG PageSize:1;
            ULONGLONG Global:1;
            ULONGLONG Available00:3;
            ULONGLONG PageTableAttributeIndex:1;
            ULONGLONG Reserved01:8;
            ULONGLONG PageFrameNumber:15;
            ULONGLONG Reserved02:28;
        } Entry;
        LARGE_INTEGER Data;
    };
} X86_PDE_PAE_LARGE, *PX86_PDE_PAE_LARGE ;

typedef struct _X86_PTE_PAE {
    union {
        struct {
            ULONGLONG Present:1;
            ULONGLONG ReadWrite:1;
            ULONGLONG UserSupervisor:1;
            ULONGLONG WriteThrough:1;
            ULONGLONG CacheDisabled:1;
            ULONGLONG Accessed:1;
            ULONGLONG Dirty:1;
            ULONGLONG PageTableAttributeIndex:1;
            ULONGLONG Global:1;
            ULONGLONG Available00:3;
            ULONGLONG PageFrameNumber:24;
            ULONGLONG Reserved02:28;
        } Entry;
        LARGE_INTEGER Data;
    };
} X86_PTE_PAE, *PX86_PTE_PAE;
//
// NO PAE.
//
typedef struct _X86_PDE {
    union {
        struct {
            ULONG Present:1;
            ULONG ReadWrite:1;
            ULONG UserSupervisor:1;
            ULONG WriteThrough:1;
            ULONG CacheDisabled:1;
            ULONG Accessed:1;
            ULONG Reserved00:1;
            ULONG PageSize:1;
            ULONG Global:1;
            ULONG Available00:3;
            ULONG PageFrameNumber:20;
        } Entry;
        ULONG Data;
    };
} X86_PDE, *PX86_PDE;

typedef struct _X86_PDE_LARGE {
    union {
        struct {
            ULONG Present:1;
            ULONG ReadWrite:1;
            ULONG UserSupervisor:1;
            ULONG WriteThrough:1;
            ULONG CacheDisabled:1;
            ULONG Accessed:1;
            ULONG Dirty:1;
            ULONG PageSize:1;
            ULONG Global:1;
            ULONG Available00:3;
            ULONG PageTableAttributeIndex:1;
            ULONG Reserved01:9;
            ULONG PageFrameNumber:10;
        } Entry;
        ULONG Data;
    };
} X86_PDE_LARGE, *PX86_PDE_LARGE;

typedef struct _X86_PTE {
    union {
        struct {
            ULONG Present:1;
            ULONG ReadWrite:1;
            ULONG UserSupervisor:1;
            ULONG WriteThrough:1;
            ULONG CacheDisabled:1;
            ULONG Accessed:1;
            ULONG Dirty:1;
            ULONG PageTableAttributeIndex:1;
            ULONG Global:1;
            ULONG Available00:3;
            ULONG PageFrameNumber:20;
        } Entry;
        ULONG Data;
    };
} X86_PTE, *PX86_PTE;

//
// Physical address extensions
//
#define X86_CR4_PAE 0x00000020
#define IS_PAE(regCr4) (regCr4 & X86_CR4_PAE) ? TRUE : FALSE

ULARGE_INTEGER
MmGetx86NoPaePhysicalAddress(
    HANDLE Handle,
    ULARGE_INTEGER PageDirectoryTable,
    ULONGLONG Va
);

ULARGE_INTEGER
MmGetx86PaePhysicalAddress(
    HANDLE Handle,
    ULARGE_INTEGER PageDirectoryTable,
    ULONGLONG Va
);


ULARGE_INTEGER
MmGetx86PaePhysicalAddress(
    HANDLE Handle,
    ULARGE_INTEGER PageDirectoryTable,
    ULONGLONG Va
);

ULARGE_INTEGER
MmGetPhysicalAddress(
    HANDLE Handle,
    ULONGLONG PageDirectoryTable,
    ULONGLONG Va
);

BOOL
MmReadVirtualAddress(
    HANDLE Handle,
    ULONGLONG PageDirectoryTable,
    ULONGLONG Va,
    PVOID Buffer,
    SIZE_T SizeOfBuffer
);