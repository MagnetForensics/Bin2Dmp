/*++
    Copyright (C) 2010 Matthieu Suiche http://www.msuiche.net 
    Copyright (C) 2010 MoonSols. <http://www.moonsols.com>
    Copyright (c) 2017 - 2018, Comae Technologies DMCC
    All rights reserved.

Module Name:

    - kernel.h

Abstract:

    - 


Environment:

    - User mode

Revision History:

    - Matthieu Suiche (Jan-2010)

--*/

#define MAX_PROCESSORS 256

typedef enum _ARCHITECTURE_TYPE {
    MACHINE_X86 = 1,
    MACHINE_X64 = 2,
    MACHINE_AMD64 = 2,
    MACHINE_IA64 = 3
} ARCHITECTURE_TYPE;

typedef enum _WINDOWS_NT_VERSION {
    // NT 5.0
    WINDOWS_NT50_X86 = 0,
    // NT 5.1
    WINDOWS_NT51_X86,
    // NT 5.2
    WINDOWS_NT52_X86,
    WINDOWS_NT52_X64,
    WINDOWS_NT52_IA64,
    // NT 6.0
    WINDOWS_NT60_X86,
    WINDOWS_NT60_X64,
    WINDOWS_NT60_IA64,
    // NT 6.1
    WINDOWS_NT61_X86,
    WINDOWS_NT61_X64,
    WINDOWS_NT61_IA64,
	// NT 10 (1803)
	WINDOWS_NT10_x64_1803,
	// NT 10 (1804)
	WINDOWS_NT10_x64_1804
} WINDOWS_NT_VERSION;

typedef struct _EXCALIBUR_DATA {
    ULONG     MachineType;
    ULONG     NtVersion;
    ULONG    MajorVersion;
    ULONG    MinorVersion;
    ULONG     NtBuildNumber;
    ULONGLONG DirectoryTableBase;
    BOOL      PaeEnabled;

    ULONGLONG KernelBase;
    ULONG     SizeOfKernelImage;
    GUID      KernelGuid;

    ULONGLONG KdDebuggerDataBlock;
    BOOL      IsEncodedDbgDataBlock;
    PKDDEBUGGER_DATA64 DbgData;

    ULONGLONG KiProcessorBlock;
    ULONG     NumberProcessors;

    ULONGLONG MmPfnDatabase;
    ULONGLONG PsLoadedModuleList;
    ULONGLONG PsActiveProcessHead;
    ULONGLONG PspCidTable;

    PVOID     ContextData;
    ULONG     SizeOfContextData;

    PVOID     SpecialRegsData;
    ULONG     SizeOfSpecialRegsData;

    ULONG64   KdpDataBlockEncodedOffset;
} EXCALIBUR_DATA, *PEXCALIBUR_DATA;

#define MAX_SUPPORTED_VERSION (WINDOWS_NT10_x64_1804 + 1)

extern EXCALIBUR_DATA g_KiExcaliburData;

BOOL
KeInitializeData(
    HANDLE Handle,
    FILE_TYPE Type
);

BOOL
KeRawInitializeData(
    HANDLE Handle
);

BOOL
KeFindKernelImageBase(
    HANDLE Handle
);

BOOL
KeFindDbgDataBlock(
    HANDLE Handle,
    ULONG64 KernelImagePointer
);