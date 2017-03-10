/*++
    Copyright (C) 2010 Matthieu Suiche http://www.msuiche.net 
    Copyright (C) 2010 MoonSols. <http://www.moonsols.com>
    All rights reserved.

Module Name:

    - debug.c

Abstract:

    - 


Environment:

    - User mode

Revision History:

    - Matthieu Suiche (Mar-2010)

--*/

#include "stdafx.h"
#include "avalon.h"

#if DEBUG_ENABLED
VOID
DumpExcalibur(HANDLE Handle)
{
ULARGE_INTEGER Pa;

    Pa = MmGetPhysicalAddress(Handle, g_KiExcaliburData.DirectoryTableBase, g_KiExcaliburData.KernelBase);

    wprintf(L"Machine Type: %d\n", g_KiExcaliburData.MachineType);
    wprintf(L"Nt Version: %d\n", g_KiExcaliburData.NtVersion);
    wprintf(L"NT Version: %d.%d\n", g_KiExcaliburData.MajorVersion, g_KiExcaliburData.MinorVersion);

    wprintf(L"DirectoryTableBase: 0x%I64X\n", g_KiExcaliburData.DirectoryTableBase);
    wprintf(L"PAE ? %d\n", g_KiExcaliburData.PaeEnabled);

    wprintf(L"KernelBase: 0x%I64X (Pa: 0x%I64X)\n",
        g_KiExcaliburData.KernelBase, Pa.QuadPart);

    wprintf(L"SizeOfKernelImage: 0x%X\n", g_KiExcaliburData.SizeOfKernelImage);
    wprintf(L"KdDebuggerDataBlock: 0x%I64X\n", g_KiExcaliburData.KdDebuggerDataBlock);
    wprintf(L"KiProcessorBlock: 0x%I64X\n", g_KiExcaliburData.KiProcessorBlock);
    wprintf(L"NumberProcessors: 0x%d\n", g_KiExcaliburData.NumberProcessors); 
    wprintf(L"MmPfnDatabase: 0x%I64X\n", g_KiExcaliburData.MmPfnDatabase); 
    wprintf(L"PsLoadedModuleList: 0x%I64X\n", g_KiExcaliburData.PsLoadedModuleList); 
    wprintf(L"PsActiveProcessHead: 0x%I64X\n", g_KiExcaliburData.PsActiveProcessHead); 
    wprintf(L"PspCidTable: 0x%I64X\n", g_KiExcaliburData.PspCidTable);
}

VOID
DumpCache()
{
#if CACHE_ENABLED
ULONG CacheIndex;

    for (CacheIndex = 0; CacheIndex < MAX_CACHED_PAGES; CacheIndex += 1)
    {
        wprintf(L"#%02d : Pa: 0x%I64X %d P\n",
                CacheIndex,
                MmCachedPages[CacheIndex].Pa.QuadPart,
                MmCachedPages[CacheIndex].Priority);

    }
#endif
}

VOID
DumpMdl()
{
ULONG i;

    for (i = 0; i < MmMdlCount; i += 1)
    {
        wprintf(L"#%5d 0x%I64X - 0x%I64X\n",
           i,
           MmMdlAvailable[i].MemoryDescriptor.Range.Minimum.QuadPart,
           MmMdlAvailable[i].MemoryDescriptor.Range.Maximum.QuadPart);
    }
}
#endif