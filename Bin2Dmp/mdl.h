/*++
    Copyright (C) 2010 Matthieu Suiche http://www.msuiche.net 
    Copyright (C) 2010 MoonSols. <http://www.moonsols.com>
    All rights reserved.

Module Name:

    - mdl.h

Abstract:

    - 


Environment:

    - User mode

Revision History:

    - Matthieu Suiche (Jan-2010)

--*/

//
// BUGBUG: Fix me.
//
#define MDL_COUNT 0x10000

#define MAX_CACHED_PAGES 0x10

#define PAGE_SIZE 0x1000

typedef struct _ADDRESS_RANGE {
    ULARGE_INTEGER Minimum;
    ULARGE_INTEGER Maximum;
} ADDRESS_RANGE, *PADDRESS_RANGE;

typedef struct _MEMORY_DESCRIPTOR {
    BOOL IsCompressed;
    BOOL NoHeader;
    ULONG CompressedSize;
    union {
        struct {
            ULARGE_INTEGER BaseOffset;
        } Uncompressed;
        struct {
            ULARGE_INTEGER XpressHeader;
            ULONG XpressIndex;
        } Compressed;
    };
    ADDRESS_RANGE Range;
    ULONG PageCount;
} MEMORY_DESCRIPTOR, *PMEMORY_DESCRIPTOR;

typedef struct _MEMORY_DESCRIPTOR_LIST {
#if MM_GENERIC
    LIST_ENTRY Entry;
    PLIST_ENTRY Head;
#endif
    MEMORY_DESCRIPTOR MemoryDescriptor;
} MEMORY_DESCRIPTOR_LIST, *PMEMORY_DESCRIPTOR_LIST;

typedef struct _MEMORY_CACHE_ENTRY {
    ULARGE_INTEGER Pa;
    ULONGLONG Priority;
    //
    // BUGBUG: Does not work for IA64 which is PAGE_SIZE * 2
    //
    UCHAR Page[PAGE_SIZE];
} MEMORY_CACHE_ENTRY, *PMEMORY_CACHE_ENTRY;

typedef enum _FILE_TYPE {
    TypeInvalid = 0,
    TypeRaw,
    TypeDmp,
    TypeHibr
} FILE_TYPE;

BOOL
ReadFileAsynchronous(
    HANDLE Handle,
    ULARGE_INTEGER Offset,
    PVOID Dest,
    ULONG Size
);

BOOL
MmInitializeMdl(
    HANDLE Handle,
    FILE_TYPE Type
);

BOOL
MmDestroyMdl(
    VOID
);

BOOL
MmRawInitializeMdl(
    HANDLE Handle
);

BOOL
MmDmpInitializeMdl(
    HANDLE Handle
);

BOOL
MmHibrInitializeMdl(
    HANDLE Handle
);

BOOL
MmSortMdl(
    VOID
);

BOOL
MmExtractSlackBlocks(
    HANDLE hHandle,
    LPWSTR OutputDir,
    PULONG SlackBlockCount
);

extern PMEMORY_DESCRIPTOR_LIST MmMdlAvailable;

#if CACHE_ENABLED
extern PMEMORY_CACHE_ENTRY MmCachedPages;
#endif

extern ULARGE_INTEGER MmMaximumPhysicalAddress;
extern ULONG MmMaximumPhysicalPage;

extern SIZE_T MmMdlCount;

extern BOOL InternalErrorCode;