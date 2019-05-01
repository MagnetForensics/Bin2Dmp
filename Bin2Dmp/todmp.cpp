/*++
    Copyright (c) Comae Technologies DMCC. All rights reserved.

Module Name:

    - todmp.c

Abstract:

    - 


Environment:

    - User mode

Revision History:

    - Matthieu Suiche (Mar-2010)

--*/

#include "stdafx.h"
#include "avalon.h"

BOOL
ConvertToDmp(HANDLE Input,
             HANDLE CrashDumpFile
             )
/*++

Routine Description:

    Desc.

Arguments:

    Arg1 - Desc.

    Arg2 - Desc.

    Arg3 - Desc.

Return Value:

    Ret1 - Desc.

    Ret2 - Desc.

--*/
{
BOOL Ret;

    Ret = FALSE;

    if (g_KiExcaliburData.MachineType == MACHINE_X86)
    {
        Ret = ConvertToDmp32(Input, CrashDumpFile);
    }
#ifdef PRO_EDITION
    else if (g_KiExcaliburData.MachineType == MACHINE_X64)
    {
        Ret = ConvertToDmp64(Input, CrashDumpFile);
    }
#endif
    else
    {
        wprintf(L"");
    }

    return Ret;
}

BOOL
ConvertToDmp32(HANDLE Input,
               HANDLE CrashDumpFile
)
/*++

Routine Description:

    Desc.

Arguments:

    Arg1 - Desc.

    Arg2 - Desc.

    Arg3 - Desc.

Return Value:

    Ret1 - Desc.

    Ret2 - Desc.

--*/
{
    PHYSICAL_MEMORY_DESCRIPTOR32 MmPhysicalMemoryBlock32;
    EXCEPTION_RECORD32 Exception32;
    PDUMP_HEADER32 Header32;

    SYSTEMTIME SystemTime;

    PUCHAR Cache, Page;

    ULARGE_INTEGER Offset;
    ULONG CacheOffset;

    BOOL Ret;
    ULONG i;

    ULONG64 ContextVa;
    ULARGE_INTEGER ContextPa;

    //
    // Console
    //
    HANDLE Handle = NULL;
    COORD Initial, ContextInfo;

    MD5_CONTEXT Md5Context;

    Ret = FALSE;

    Cache = NULL;
    Page = NULL;
    Header32 = NULL;

    if (g_KiExcaliburData.MachineType != MACHINE_X86) goto finish;

    //
    // Create a one Mb Cache.
    //
    Cache = (PUCHAR)malloc(WRITE_CACHE_SIZE);
    if (Cache == NULL) goto finish;
    memset(Cache, 0, WRITE_CACHE_SIZE);

    Page = (PUCHAR)malloc(PAGE_SIZE);
    if (Page == NULL) goto finish;
    memset(Page, 0, PAGE_SIZE);

    Header32 = (PDUMP_HEADER32)malloc(sizeof(DUMP_HEADER32));
    if (Header32 == NULL) goto finish;

    for (i = 0; i < sizeof(DUMP_HEADER32) / sizeof(ULONG); i += 1)
    {
        ((PULONG)Header32)[i] = DUMP_SIGNATURE;
    }

    // memset(Header32, DUMP_SIGNATURE, sizeof(DUMP_HEADER32));

    //
    // Initialize header.
    //
    Header32->Signature = DUMP_SIGNATURE;
    Header32->ValidDump = DUMP_VALID_DUMP;
    Header32->DumpType = DUMP_TYPE_FULL;
    Header32->MachineImageType = IMAGE_FILE_MACHINE_I386;

    Header32->MinorVersion = g_KiExcaliburData.NtBuildNumber & 0xFFFF;
    Header32->MajorVersion = g_KiExcaliburData.NtBuildNumber >> 28; 

    Header32->DirectoryTableBase = (ULONG)g_KiExcaliburData.DirectoryTableBase;
    Header32->PfnDataBase = (ULONG)g_KiExcaliburData.MmPfnDatabase;
    Header32->PsLoadedModuleList = (ULONG)g_KiExcaliburData.PsLoadedModuleList;
    Header32->PsActiveProcessHead = (ULONG)g_KiExcaliburData.PsActiveProcessHead;
    Header32->NumberProcessors = (ULONG)g_KiExcaliburData.NumberProcessors;
    Header32->KdDebuggerDataBlock = (ULONG)g_KiExcaliburData.KdDebuggerDataBlock;

    Header32->BugCheckCode = 'MATT';
    Header32->BugCheckParameter1 = 0x1;
    Header32->BugCheckParameter2 = 0x2;
    Header32->BugCheckParameter3 = 0x3;
    Header32->BugCheckParameter4 = 0x4;

    RtlZeroMemory(Header32->VersionUser, sizeof(Header32->VersionUser));

    Header32->PaeEnabled = g_KiExcaliburData.PaeEnabled;

    MmPhysicalMemoryBlock32.NumberOfPages = MmMaximumPhysicalPage;
    MmPhysicalMemoryBlock32.NumberOfRuns = 1;
    MmPhysicalMemoryBlock32.Run[0].BasePage = 0;
    MmPhysicalMemoryBlock32.Run[0].PageCount = MmMaximumPhysicalPage;

    RtlCopyMemory(&Header32->PhysicalMemoryBlock,
                  &MmPhysicalMemoryBlock32,
                  sizeof(PHYSICAL_MEMORY_DESCRIPTOR32));

    //
    // Exception record.
    //
    Exception32.ExceptionCode = STATUS_BREAKPOINT;
    Exception32.ExceptionRecord = 0;
    Exception32.NumberParameters = 0;
    Exception32.ExceptionFlags = EXCEPTION_NONCONTINUABLE;
    Exception32.ExceptionAddress = 0xDEADBABE;

    RtlCopyMemory(&Header32->ExceptionRecord,
                  &Exception32,
                  sizeof(EXCEPTION_RECORD32));

    GetSystemTime(&SystemTime);
    SystemTimeToFileTime(&SystemTime, &Header32->SystemTime);

    RtlZeroMemory(&Header32->RequiredDumpSpace, sizeof(LARGE_INTEGER));

    //
    // BUGBUG: Safe int.
    //
    Header32->RequiredDumpSpace.QuadPart = 
        (MmMaximumPhysicalPage * PAGE_SIZE) + sizeof(DUMP_HEADER32);

    //
    // BUGBUG: Fill me with a real context.
    //
    RtlZeroMemory(Header32->ContextRecord, sizeof(Header32->ContextRecord));

    RtlZeroMemory(Header32->Comment, sizeof(Header32->Comment));
    strcpy_s(Header32->Comment, sizeof(Header32->Comment),
        "Microsoft Crash Dump file generated with Comae Toolkit - More information on http://www.comae.io");

    Offset.QuadPart = 0;
    CacheOffset = 0;

    memcpy_s(Cache + CacheOffset,
             WRITE_CACHE_SIZE,
             Header32,
             sizeof(DUMP_HEADER32));

    CacheOffset += sizeof(DUMP_HEADER32);
    Offset.QuadPart = 0;

    ContextVa = 0ULL;

    //
    // Read first entry of Process Block to get KPRCB address.
    //
    Ret = MmReadVirtualAddress(Input, 0ULL, g_KiExcaliburData.KiProcessorBlock,
                               &ContextVa, sizeof(ULONG));
    if (Ret == FALSE) goto finish;

    if (ContextVa)
    {
        //
        // If Win7/Win2008 R2 and above.
        //
        if ((g_KiExcaliburData.NtBuildNumber & 0xFFFF) > 7000)
        {
            ContextVa += (X86_NT61_KPROCESSOR_STATE_OFFSET + X86_CONTEXT_OFFSET);
        }
        else
        {
            ContextVa += (X86_KPROCESSOR_STATE_OFFSET + X86_CONTEXT_OFFSET);
        }

        //
        // Get physical address of the CONTEXT from KPRCB.
        //
        ContextPa = MmGetPhysicalAddress(Input, 0ULL, ContextVa);
        if (ContextPa.QuadPart == 0ULL) goto finish;
    }

    i = 0;
    Handle = GetStdHandle(STD_OUTPUT_HANDLE);
    GetCursorPosition(Handle, &Initial);
    ContextInfo = Initial;
    //
    // Because we print context information.
    //
    Initial.Y += 9;

    MD5Init(&Md5Context);

    while (i < MmMdlCount)
    {
        ULONG BytesToWrite;

        while ((CacheOffset < WRITE_CACHE_SIZE) && (i < MmMdlCount))
        {
            while ((Offset.QuadPart < MmMdlAvailable[i].MemoryDescriptor.Range.Minimum.QuadPart) &&
                   (CacheOffset < WRITE_CACHE_SIZE))
            {
                memset(Cache + CacheOffset,
                       0,
                       PAGE_SIZE);
                Offset.QuadPart += PAGE_SIZE;
                CacheOffset += PAGE_SIZE;
            }

            if (CacheOffset < WRITE_CACHE_SIZE)
            {
                /*
                wprintf(L"== (%d, %d) = 0x%I64X (offset: 0x%I64X)\n",
                        i, MmMdlCount,
                        MmMdlAvailable[i].MemoryDescriptor.Range.Minimum.QuadPart,
                        Offset.QuadPart);
                */

                Ret = MmReadPhysicalAddress(Input,
                                            Offset,
                                            Cache + CacheOffset,
                                            PAGE_SIZE);
                if (Ret == FALSE)
                {
                    wprintf(L"Error: MmReadPhysicalAddress(%I64X)\n", Offset.QuadPart);
                    goto finish;
                }

                //
                // WinDbg bug auto-fix.
                //
                if (ContextVa &&
                    (ContextPa.QuadPart >= Offset.QuadPart) &&
                    (ContextPa.QuadPart < (Offset.QuadPart + PAGE_SIZE)))
                {
                    PX86_CONTEXT Context;
                    //
                    // We have to set the Segment Registers from Context inside the KPCR/KPRCB.
                    //
                    Context = (PX86_CONTEXT)(Cache + CacheOffset + (ContextPa.LowPart & (PAGE_SIZE - 1)));

                    SetConsoleCursorPosition(Handle, ContextInfo);
                    White(L"\nRewritting CONTEXT for Windbg...\n");
                    if (Context->SegCs != KGDT_R0_CODE)
                    {
                        wprintf(L"   -> Context->SegCs at physical address 0x%08X%08X modified from ",
                            ContextPa.HighPart, ContextPa.LowPart + (DWORD)(ULONG_PTR)&((PX86_CONTEXT)0)->SegCs);
                        White(L"%02x", Context->SegCs);
                        wprintf(L" into ");
                        Green(L"%02x\n", KGDT_R0_CODE);
                        Context->SegCs = KGDT_R0_CODE;
                    }
                    else
                    {
                        wprintf(L"   -> Context->SegCs at physical address 0x%08X%08X is ",
                            ContextPa.HighPart, ContextPa.LowPart + (DWORD)(ULONG_PTR)&((PX86_CONTEXT)0)->SegCs);
                        White(L"already ");
                        wprintf(L"equal to ");
                        Green(L"%02x\n", KGDT_R0_CODE);
                    }

                    if (Context->SegDs != (KGDT_R3_DATA | RPL_MASK))
                    {
                        wprintf(L"   -> Context->SegDs at physical address 0x%08X%08X modified from ",
                            ContextPa.HighPart, ContextPa.LowPart + (DWORD)(ULONG_PTR)&((PX86_CONTEXT)0)->SegDs);
                        White(L"%02x", Context->SegDs);
                        wprintf(L" into ");
                        Green(L"%02x\n", (KGDT_R3_DATA | RPL_MASK));
                        Context->SegDs = (KGDT_R3_DATA | RPL_MASK);
                    }
                    else
                    {
                        wprintf(L"   -> Context->SegDs at physical address 0x%08X%08X is ",
                            ContextPa.HighPart, ContextPa.LowPart + (DWORD)(ULONG_PTR)&((PX86_CONTEXT)0)->SegDs);
                        White(L"already ");
                        wprintf(L"equal to ");
                        Green(L"%02x\n", (KGDT_R3_DATA | RPL_MASK));
                    }

                    if (Context->SegEs != (KGDT_R3_DATA | RPL_MASK))
                    {
                        wprintf(L"   -> Context->SegEs at physical address 0x%08X%08X modified from ",
                            ContextPa.HighPart, ContextPa.LowPart + (DWORD)(ULONG_PTR)&((PX86_CONTEXT)0)->SegEs);
                        White(L"%02x", Context->SegEs);
                        wprintf(L" into ");
                        Green(L"%02x\n", (KGDT_R3_DATA | RPL_MASK));
                        Context->SegEs = (KGDT_R3_DATA | RPL_MASK);
                    }
                    else
                    {
                        wprintf(L"   -> Context->SegEs at physical address 0x%08X%08X is ",
                            ContextPa.HighPart, ContextPa.LowPart + (DWORD)(ULONG_PTR)&((PX86_CONTEXT)0)->SegEs);
                        White(L"already ");
                        wprintf(L"equal to ");
                        Green(L"%02x\n", (KGDT_R3_DATA | RPL_MASK));
                    }

                    if (Context->SegFs != KGDT_R0_PCR)
                    {
                        wprintf(L"   -> Context->SegFs at physical address 0x%08X%08X modified from ",
                            ContextPa.HighPart, ContextPa.LowPart + (DWORD)(ULONG_PTR)&((PX86_CONTEXT)0)->SegFs);
                        White(L"%02x", Context->SegFs);
                        wprintf(L" into ");
                        Green(L"%02x\n", KGDT_R0_PCR);
                        Context->SegFs = KGDT_R0_PCR;
                    }
                    else
                    {
                        wprintf(L"   -> Context->SegFs at physical address 0x%08X%08X is ",
                            ContextPa.HighPart, ContextPa.LowPart + (DWORD)(ULONG_PTR)&((PX86_CONTEXT)0)->SegFs);
                        White(L"already ");
                        wprintf(L"equal to ");
                        Green(L"%02x\n", KGDT_R0_PCR);
                    }

                    if (Context->SegGs != 0)
                    {
                        wprintf(L"   -> Context->SegGs at physical address 0x%08X%08X modified from ",
                            ContextPa.HighPart, ContextPa.LowPart + (DWORD)(ULONG_PTR)&((PX86_CONTEXT)0)->SegGs);
                        White(L"%02x", Context->SegGs);
                        wprintf(L" into ");
                        Green(L"%02x\n", 0);
                        Context->SegGs = 0;
                    }
                    else
                    {
                        wprintf(L"   -> Context->SegGs at physical address 0x%08X%08X is ",
                            ContextPa.HighPart, ContextPa.LowPart + (DWORD)(ULONG_PTR)&((PX86_CONTEXT)0)->SegGs);
                        White(L"already ");
                        wprintf(L"equal to ");
                        Green(L"%02x\n", 0);
                    }

                    if (Context->SegSs != KGDT_R0_DATA)
                    {
                        wprintf(L"   -> Context->SegSs at physical address 0x%08X%08X modified from ",
                            ContextPa.HighPart, ContextPa.LowPart + (DWORD)(ULONG_PTR)&((PX86_CONTEXT)0)->SegSs);
                        White(L"%02x", Context->SegSs);
                        wprintf(L" into ");
                        Green(L"%02x\n", KGDT_R0_DATA);
                        Context->SegSs = KGDT_R0_DATA;
                    }
                    else
                    {
                        wprintf(L"   -> Context->SegSs at physical address 0x%08X%08X is ",
                            ContextPa.HighPart, ContextPa.LowPart + (DWORD)(ULONG_PTR)&((PX86_CONTEXT)0)->SegSs);
                        White(L"already ");
                        wprintf(L"equal to ");
                        Green(L"%02x\n", KGDT_R0_DATA);
                    }
                }

                // wprintf(L"Offset: 0x%I64X\n", Offset.QuadPart);

                Offset.QuadPart += PAGE_SIZE;
                CacheOffset += PAGE_SIZE;

                //
                // Next Mdl.
                //
                if (Offset.QuadPart >= MmMdlAvailable[i].MemoryDescriptor.Range.Maximum.QuadPart)
                {
                    // wprintf(L"Mdl: 0x%I64X\n", Offset.QuadPart);
                    i += 1;
                }
            }
        }

        BytesToWrite = CacheOffset;

        SetConsoleCursorPosition(Handle, Initial);
        White(L"   [0x%08X%08X of 0x%08X%08X]",
              Offset.HighPart, Offset.LowPart - BytesToWrite,
              MmMaximumPhysicalAddress.HighPart, MmMaximumPhysicalAddress.LowPart);

        MD5Update(&Md5Context, Cache, BytesToWrite);

        Ret = WriteFileSynchronous(CrashDumpFile, Cache, BytesToWrite);
        if (Ret == FALSE)
        {
            wprintf(L"An error occured while writing on disk. WriteFileSynchronous()\n");
            goto finish;
        }

        CacheOffset = 0;

        memset(Cache, 0, WRITE_CACHE_SIZE);
    }

    MD5Final(&Md5Context);

    Ret = TRUE;

finish:
    if (Ret == TRUE)
    {
        SetConsoleCursorPosition(Handle, Initial);
        Green(L"   [0x%08X%08X of 0x%08X%08X] \n",
              Offset.HighPart, Offset.LowPart,
              MmMaximumPhysicalAddress.HighPart, MmMaximumPhysicalAddress.LowPart);
    }
    else
    {
        SetConsoleCursorPosition(Handle, Initial);
        Red(L"   [0x%08X%08X of 0x%08X%08X] \n",
          Offset.HighPart, Offset.LowPart,
          MmMaximumPhysicalAddress.HighPart, MmMaximumPhysicalAddress.LowPart);

#ifdef PRO_EDITION
        White(L"   MD5 = ");
        for (i = 0; i < 16; i += 1) wprintf(L"%02X", Md5Context.Digest[i]);
        wprintf(L"\n");
#endif
    }

#if DEBUG_ENABLED
    wprintf(L"ContextPa: %I64X\n", ContextPa.QuadPart);
    wprintf(L"ContextVa: %I64X\n", ContextVa);
#endif

    if (Header32) free(Header32);
    if (Cache) free(Cache);
    if (Page) free(Page);

    return Ret;
}

#ifdef PRO_EDITION
BOOL
ConvertToDmp64(HANDLE Input,
               HANDLE CrashDumpFile
)
/*++

Routine Description:

    Desc.

Arguments:

    Arg1 - Desc.

    Arg2 - Desc.

    Arg3 - Desc.

Return Value:

    Ret1 - Desc.

    Ret2 - Desc.

--*/
{
    PHYSICAL_MEMORY_DESCRIPTOR64 MmPhysicalMemoryBlock64;
    EXCEPTION_RECORD64 Exception64;
    PDUMP_HEADER64 Header64;

    SYSTEMTIME SystemTime;

    PUCHAR Cache, Page;

    ULARGE_INTEGER Offset;
    ULONG CacheOffset;

    BOOL Ret;
    ULONG i;

    ULONG64 ContextVa;
    ULARGE_INTEGER ContextPa;

    ULARGE_INTEGER DbgDataPa = {0};
    ULARGE_INTEGER KdpDataBlockEncodedPa = {0};

    //
    // Console
    //
    HANDLE Handle = NULL;
    COORD Initial, ContextInfo;

    MD5_CONTEXT Md5Context;

    Ret = FALSE;

    Cache = NULL;
    Page = NULL;
    Header64 = NULL;

    if (g_KiExcaliburData.MachineType != MACHINE_X64) goto finish;

    //
    // Create a one Mb Cache.
    //
    Cache = (PUCHAR)malloc(WRITE_CACHE_SIZE);
    if (Cache == NULL) goto finish;
    memset(Cache, 0, WRITE_CACHE_SIZE);

    Page = (PUCHAR)malloc(PAGE_SIZE);
    if (Page == NULL) goto finish;
    memset(Page, 0, PAGE_SIZE);

    Header64 = (PDUMP_HEADER64)malloc(sizeof(DUMP_HEADER64));
    if (Header64 == NULL) goto finish;

    for (i = 0; i < sizeof(DUMP_HEADER64) / sizeof(ULONG); i += 1)
    {
        ((PULONG)Header64)[i] = DUMP_SIGNATURE;
    }

    // memset(Header64, DUMP_SIGNATURE, sizeof(DUMP_HEADER64));

    //
    // Initialize header.
    //
    Header64->Signature = DUMP_SIGNATURE;
    Header64->ValidDump = DUMP_VALID_DUMP64;
    Header64->DumpType = DUMP_TYPE_FULL;
    Header64->MachineImageType = IMAGE_FILE_MACHINE_AMD64;

    Header64->MinorVersion = g_KiExcaliburData.NtBuildNumber & 0xFFFF;
    Header64->MajorVersion = g_KiExcaliburData.NtBuildNumber >> 28; 

    Header64->DirectoryTableBase = g_KiExcaliburData.DirectoryTableBase;
    Header64->PfnDataBase = g_KiExcaliburData.MmPfnDatabase;
    Header64->PsLoadedModuleList = g_KiExcaliburData.PsLoadedModuleList;
    Header64->PsActiveProcessHead = g_KiExcaliburData.PsActiveProcessHead;
    Header64->NumberProcessors = g_KiExcaliburData.NumberProcessors;
    Header64->KdDebuggerDataBlock = g_KiExcaliburData.KdDebuggerDataBlock;

    Header64->BugCheckCode = 'MATT';
    Header64->BugCheckParameter1 = 0x1;
    Header64->BugCheckParameter2 = 0x2;
    Header64->BugCheckParameter3 = 0x3;
    Header64->BugCheckParameter4 = 0x4;

    RtlZeroMemory(Header64->VersionUser, sizeof(Header64->VersionUser));

    MmPhysicalMemoryBlock64.NumberOfPages = MmMaximumPhysicalPage;
    MmPhysicalMemoryBlock64.NumberOfRuns = 1;
    MmPhysicalMemoryBlock64.Run[0].BasePage = 0;
    MmPhysicalMemoryBlock64.Run[0].PageCount = MmMaximumPhysicalPage;

    RtlCopyMemory(&Header64->PhysicalMemoryBlock,
                  &MmPhysicalMemoryBlock64,
                  sizeof(PHYSICAL_MEMORY_DESCRIPTOR64));

    //
    // Exception record.
    //
    Exception64.ExceptionCode = STATUS_BREAKPOINT;
    Exception64.ExceptionRecord = 0;
    Exception64.NumberParameters = 0;
    Exception64.ExceptionFlags = EXCEPTION_NONCONTINUABLE;
    Exception64.ExceptionAddress = 0xDEADBABE;

    RtlCopyMemory(&Header64->ExceptionRecord,
                  &Exception64,
                  sizeof(EXCEPTION_RECORD64));

    GetSystemTime(&SystemTime);

    SystemTimeToFileTime(&SystemTime, &Header64->SystemTime);

    RtlZeroMemory(&Header64->RequiredDumpSpace, sizeof(LARGE_INTEGER));

    //
    // BUGBUG: Safe int.
    //
    Header64->RequiredDumpSpace.QuadPart = 
        (MmMaximumPhysicalPage * PAGE_SIZE) + sizeof(DUMP_HEADER64);

    //
    // BUGBUG: Fill me with a real context.
    //
    RtlZeroMemory(Header64->ContextRecord, sizeof(Header64->ContextRecord));

    RtlZeroMemory(Header64->Comment, sizeof(Header64->Comment));
    strcpy_s(Header64->Comment, sizeof(Header64->Comment),
        "File converted with Comae Toolkit");

    Offset.QuadPart = 0;
    CacheOffset = 0;

    memcpy_s(Cache + CacheOffset,
             WRITE_CACHE_SIZE,
             Header64,
             sizeof(DUMP_HEADER64));

    CacheOffset += sizeof(DUMP_HEADER64);
    Offset.QuadPart = 0;

    ContextVa = 0ULL;

    //
    // Read first entry of Process Block to get KPRCB address.
    //
    Ret = MmReadVirtualAddress(Input, 0ULL, g_KiExcaliburData.KiProcessorBlock,
                               &ContextVa, sizeof(ULONGLONG));
    if (Ret == FALSE) goto finish;

    // wprintf(L"nt!KiProcessorBlock = 0x%I64X\n", g_KiExcaliburData.KiProcessorBlock);
    // wprintf(L"nt!KiProcessorBlock.Prcb = 0x%I64X\n", ContextVa);
    // wprintf(L"g_KiExcaliburData.DbgData->OffsetPrcbProcStateContext = %x\n", g_KiExcaliburData.DbgData->OffsetPrcbProcStateContext);
    if (g_KiExcaliburData.DbgData &&
        ((g_KiExcaliburData.MajorVersion > 5) ||
        ((g_KiExcaliburData.MajorVersion == 5) && (g_KiExcaliburData.MinorVersion >= 1))))
    {
        // wprintf(L"+= g_KiExcaliburData.DbgData->OffsetPrcbProcStateContext\n");
        ContextVa += g_KiExcaliburData.DbgData->OffsetPrcbProcStateContext;
    }
    else
    {
        ContextVa += (X64_KPROCESSOR_STATE_OFFSET + X64_CONTEXT_OFFSET);
    }
    wprintf(L"nt!KiProcessorBlock.Prcb.Context = 0x%I64X\n", ContextVa);
    wprintf(L"nt!KdpDataBlockEncodedOffset = 0x%I64X\n", g_KiExcaliburData.KdpDataBlockEncodedOffset);
    wprintf(L"IsEncodedDbgDataBlock = 0x%d\n", g_KiExcaliburData.IsEncodedDbgDataBlock);
    wprintf(L"KdDebuggerDataBlock = 0x%I64X\n", g_KiExcaliburData.KdDebuggerDataBlock); 

    //
    // Get physical address of the CONTEXT from KPRCB.
    //
    ContextPa = MmGetPhysicalAddress(Input, 0ULL, ContextVa);
    if (ContextPa.QuadPart == 0ULL) goto finish;

    if (g_KiExcaliburData.IsEncodedDbgDataBlock)
    {
        DbgDataPa = MmGetPhysicalAddress(Input, 0ULL, g_KiExcaliburData.KdDebuggerDataBlock);
        if (DbgDataPa.QuadPart == 0ULL) goto finish;

        KdpDataBlockEncodedPa = MmGetPhysicalAddress(Input, 0ULL, g_KiExcaliburData.KdpDataBlockEncodedOffset);
        if (KdpDataBlockEncodedPa.QuadPart == 0ULL) goto finish;
    }

    i = 0;

    Handle = GetStdHandle(STD_OUTPUT_HANDLE);
    GetCursorPosition(Handle, &Initial);
    ContextInfo = Initial;
    //
    // Because we print context information.
    //
    Initial.Y += 9;

    MD5Init(&Md5Context);

    while (i < MmMdlCount)
    {
        ULONG BytesToWrite;

        while ((CacheOffset < WRITE_CACHE_SIZE) && (i < MmMdlCount))
        {
            while ((Offset.QuadPart < MmMdlAvailable[i].MemoryDescriptor.Range.Minimum.QuadPart) &&
                   (CacheOffset < WRITE_CACHE_SIZE))
            {
                memset(Cache + CacheOffset,
                       0,
                       PAGE_SIZE);
                Offset.QuadPart += PAGE_SIZE;
                CacheOffset += PAGE_SIZE;
            }

            if (CacheOffset < WRITE_CACHE_SIZE)
            {
                Ret = MmReadPhysicalAddress(Input,
                                            Offset,
                                            Cache + CacheOffset,
                                            PAGE_SIZE);
                if (Ret == FALSE) goto finish;

                //
                // WinDbg bug auto-fix.
                //
                if ((ContextPa.QuadPart >= Offset.QuadPart) &&
                    (ContextPa.QuadPart < (Offset.QuadPart + PAGE_SIZE)))
                {
                    PX64_CONTEXT Context;
                    //
                    // We have to set the Segment Registers from Context inside the KPCR/KPRCB.
                    //
                    Context = (PX64_CONTEXT)(Cache + CacheOffset + (ContextPa.LowPart & (PAGE_SIZE - 1)));

                    SetConsoleCursorPosition(Handle, ContextInfo);

                    if (g_KiExcaliburData.ContextData && g_KiExcaliburData.SpecialRegsData)
                    {
                        PUCHAR ProcState = NULL;
                        RtlCopyMemory(Context, g_KiExcaliburData.ContextData, g_KiExcaliburData.SizeOfContextData);
                        ProcState = (PUCHAR)Context - g_KiExcaliburData.SizeOfSpecialRegsData;
                        RtlCopyMemory(Context, g_KiExcaliburData.SpecialRegsData, g_KiExcaliburData.SizeOfSpecialRegsData);
                    }
                    else
                    {
                        if (Context->SegCs != KGDT64_R0_CODE) Context->SegCs = KGDT64_R0_CODE;
                        if (Context->SegDs != (KGDT64_R3_DATA | RPL_MASK)) Context->SegDs = (KGDT64_R3_DATA | RPL_MASK);
                        if (Context->SegEs != (KGDT64_R3_DATA | RPL_MASK)) Context->SegEs = (KGDT64_R3_DATA | RPL_MASK);
                        if (Context->SegFs != (KGDT64_R3_CMTEB | RPL_MASK)) Context->SegFs = (KGDT64_R3_CMTEB | RPL_MASK);
                        if (Context->SegGs != 0) Context->SegGs = 0;
                        if (Context->SegSs != KGDT64_R0_DATA) Context->SegSs = KGDT64_R0_DATA;
                    }
                }
                else if (g_KiExcaliburData.IsEncodedDbgDataBlock &&
                         (DbgDataPa.QuadPart >= Offset.QuadPart) &&
                         (DbgDataPa.QuadPart < (Offset.QuadPart + PAGE_SIZE)))
                {
                    PKDDEBUGGER_DATA64 DstDbgData;

                    DstDbgData = (PKDDEBUGGER_DATA64)(Cache + CacheOffset + (DbgDataPa.LowPart & (PAGE_SIZE - 1)));
                    RtlCopyMemory(DstDbgData, g_KiExcaliburData.DbgData, g_KiExcaliburData.DbgData->Header.Size);
                }
                else if (g_KiExcaliburData.IsEncodedDbgDataBlock &&
                         (KdpDataBlockEncodedPa.QuadPart >= Offset.QuadPart) &&
                         (KdpDataBlockEncodedPa.QuadPart < (Offset.QuadPart + PAGE_SIZE)))
                {
                    PULONG IsEncoded = NULL;

                    IsEncoded = (PULONG)(Cache + CacheOffset + (KdpDataBlockEncodedPa.LowPart & (PAGE_SIZE - 1)));
                    *IsEncoded = FALSE;
                }


                Offset.QuadPart += PAGE_SIZE;
                CacheOffset += PAGE_SIZE;

                //
                // Next Mdl.
                //
                if (Offset.QuadPart >= MmMdlAvailable[i].MemoryDescriptor.Range.Maximum.QuadPart)
                {
                    // wprintf(L"Mdl: 0x%I64X\n", Offset.QuadPart);
                    i += 1;
                }
            }
        }

        if (CacheOffset == WRITE_CACHE_SIZE)
        {
            BytesToWrite = WRITE_CACHE_SIZE;
        }
        else
        {
            BytesToWrite = CacheOffset;
        }

        SetConsoleCursorPosition(Handle, Initial);
        White(L"   [0x%08X%08X of 0x%08X%08X] ",
              Offset.HighPart, Offset.LowPart,
              MmMaximumPhysicalAddress.HighPart, MmMaximumPhysicalAddress.LowPart);

        MD5Update(&Md5Context, Cache, BytesToWrite);

        Ret = WriteFileSynchronous(CrashDumpFile, Cache, BytesToWrite);
        if (Ret == FALSE) goto finish;

        CacheOffset = 0;

        memset(Cache, 0, WRITE_CACHE_SIZE);
    }

    MD5Final(&Md5Context);

    Ret = TRUE;

finish:

    if (Ret == TRUE)
    {
        SetConsoleCursorPosition(Handle, Initial);
        Green(L"   [0x%08X%08X of 0x%08X%08X] \n",
              Offset.HighPart, Offset.LowPart,
              MmMaximumPhysicalAddress.HighPart, MmMaximumPhysicalAddress.LowPart);

#ifdef PRO_EDITION
        White(L"   MD5 = ");
        for (i = 0; i < 16; i += 1) wprintf(L"%02X", Md5Context.Digest[i]);
        wprintf(L"\n");
#endif
    }
    else
    {
        SetConsoleCursorPosition(Handle, Initial);
        Red(L"   [0x%08X%08X of 0x%08X%08X] \n",
          Offset.HighPart, Offset.LowPart,
          MmMaximumPhysicalAddress.HighPart, MmMaximumPhysicalAddress.LowPart);
    }

#if DEBUG_ENABLED
    wprintf(L"ContextPa: %I64X\n", ContextPa.QuadPart);
    wprintf(L"ContextVa: %I64X\n", ContextVa);
#endif

    if (Header64) free(Header64);
    if (Cache) free(Cache);
    if (Page) free(Page);

    return Ret;
}
#endif