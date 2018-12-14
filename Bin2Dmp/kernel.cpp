/*++
    Copyright (C) 2010 Matthieu Suiche http://www.msuiche.net 
    Copyright (C) 2010 MoonSols. <http://www.moonsols.com>
    Copyright (c) 2017 - 2018, Comae Technologies DMCC
    All rights reserved.

Module Name:

    - kernel.c

Abstract:

    - 


Environment:

    - User mode

Revision History:

    - Matthieu Suiche (Jan-2010)

--*/

#include "stdafx.h"
#include "avalon.h"

//
// warning C4996: '_strlwr': This function or variable may be unsafe. Consider using _strlwr_s instead
//
#pragma warning(disable : 4996)

EXCALIBUR_DATA g_KiExcaliburData = {0};

ULONGLONG KernelCr3[] = {
	//
	// NT 5.0, Windows 2000
	//
	0ULL, // 0x0039000ULL,

	//
	// NT 5.1, Windows XP
	//
	0x0039000ULL, // (x86)

	//
	// NT 5.2, Windows 2003 and XP 64-bits
	//
	0x0039000ULL, // (x86, Windows 2003 Server)
	0ULL, // (amd64, Windows XP Professional x64 Edition)
	0ULL, // (IA64, Windows XP 64-bit Edition)
	// Maybe Home Server too

	//
	// NT 6.0, Windows Vista and Windows 2008
	//
	0x00122000ULL, // (x86)
#ifdef PRO_EDITION
	0x00124000ULL, // (amd64)
#else
	0x0ULL,
#endif
	0ULL, // (IA64)

	//
	// NT 6.1, Windows 7 and Windows 2008 R2
	// NT 6.2  Windows 8
	//
#ifdef PRO_EDITION
	0x00185000ULL, // (x86)
	0x00187000ULL, // (amd64)
	// 0x1A7000ULL // (amd64)
#else
	0x0ULL,
	0x0ULL,
#endif
	0ULL, // (IA64)

	// 0x001a5000ULL // Win 9 // 6.3.6374
	0x1ad000ULL, //Windows Server 2019 PreBuild 17666 and Windows 10 17666 (1803)
	0x4d2000ULL, //Windows 10 17666 (1804)
};

ULONGLONG KernelKPCR[] = {
    //
    // NT 5.0, Windows 2000
    //
    0ULL, // 0x0040000ULL,

    //
    // NT 5.1, Windows XP
    //
    0x0040000ULL, // (x86)

    //
    // NT 5.2, Windows 2003 and XP 64-bits
    //
    0x0040000ULL, // (x86, Windows 2003 Server)
#ifdef PRO_EDITION
    0x1174000ULL, // (amd64, Windows XP Professional x64 Edition)
#else
    0x0ULL,
#endif
    0ULL, // (IA64, Windows XP 64-bit Edition)
    // Maybe Home Server too

    //
    // NT 6.0, Windows Vista and Windows 2008
    //
    0ULL, // (x86)
    0ULL, // (amd64, CHECKME)
    0ULL, // (IA64)

    //
    // NT 6.1, Windows 7 and Windows 2008 R2
    //
    0ULL, // (x86)
    0ULL, // (amd64)
    0ULL, // (IA64)

};

BOOL
KeInitializeData(
    HANDLE Handle,
    FILE_TYPE Type
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
    switch (Type)
    {
        case TypeRaw:
            Ret = KeRawInitializeData(Handle);
        break;
        case TypeDmp:
            Ret = KeDmpInitializeData(Handle);
        break;
        case TypeHibr:
            Ret = KeHibrInitializeData(Handle);
        break;
        default:
            wprintf(L"Not supported.\n");
        break;
    }

    return Ret;
}

BOOL
KeDmpInitializeData(
    HANDLE Handle
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
PDUMP_HEADER32 Header32;
#ifdef PRO_EDITION
PDUMP_HEADER64 Header64;
#endif

PKDDEBUGGER_DATA64 DbgData;

ULARGE_INTEGER Address;

BOOL Ret;

    Ret = TRUE;

    // Header32 = (PDUMP_HEADER32)LocalAlloc(LPTR, sizeof(DUMP_HEADER64));
    Header32 = (PDUMP_HEADER32)malloc(sizeof(DUMP_HEADER64));
    if (Header32 == NULL) return FALSE;

    Address.QuadPart = 0;
    Ret = ReadFileAsynchronous(Handle, Address, Header32, sizeof(DUMP_HEADER64));
    if (Ret == FALSE)
    {
        goto finish;
    }

    if (Header32->Signature != DUMP_SIGNATURE)
    {
        Ret = FALSE;
        goto finish;
    }

    if (Header32->ValidDump == DUMP_VALID_DUMP)
    {
        g_KiExcaliburData.MachineType = MACHINE_X86;
        g_KiExcaliburData.PaeEnabled = Header32->PaeEnabled;
        g_KiExcaliburData.DirectoryTableBase = Header32->DirectoryTableBase;
        g_KiExcaliburData.KdDebuggerDataBlock = Header32->KdDebuggerDataBlock;
        g_KiExcaliburData.NumberProcessors = Header32->NumberProcessors;

        g_KiExcaliburData.MajorVersion = Header32->MajorVersion;
        g_KiExcaliburData.MinorVersion = Header32->MinorVersion;
        g_KiExcaliburData.MmPfnDatabase = Header32->PfnDataBase;
        g_KiExcaliburData.PsActiveProcessHead = Header32->PsActiveProcessHead;
        g_KiExcaliburData.PsLoadedModuleList = Header32->PsLoadedModuleList;
    }

    else if (Header32->ValidDump == DUMP_VALID_DUMP64)
    {
#ifdef PRO_EDITION
        g_KiExcaliburData.MachineType = MACHINE_AMD64;
        g_KiExcaliburData.PaeEnabled = TRUE;
        Header64 = (PDUMP_HEADER64)Header32;
        g_KiExcaliburData.DirectoryTableBase = Header64->DirectoryTableBase;
        g_KiExcaliburData.KdDebuggerDataBlock = Header64->KdDebuggerDataBlock;

        g_KiExcaliburData.NumberProcessors = Header64->NumberProcessors;
        g_KiExcaliburData.MajorVersion = Header64->MajorVersion;
        g_KiExcaliburData.MinorVersion = Header64->MinorVersion;
        g_KiExcaliburData.MmPfnDatabase = Header64->PfnDataBase;
        g_KiExcaliburData.PsActiveProcessHead = Header64->PsActiveProcessHead;
        g_KiExcaliburData.PsLoadedModuleList = Header64->PsLoadedModuleList;
#else
        Ret = FALSE;
#endif
    }

    if (Ret == FALSE) goto finish;

    // DbgData = (PKDDEBUGGER_DATA64)LocalAlloc(LPTR, sizeof(KDDEBUGGER_DATA64));
    DbgData = (PKDDEBUGGER_DATA64)malloc(sizeof(KDDEBUGGER_DATA64));

    if (DbgData == NULL)
    {
        Ret = FALSE;
        goto finish;
    }

    Ret = MmReadVirtualAddress(Handle,
                               0ULL,
                               g_KiExcaliburData.KdDebuggerDataBlock,
                               DbgData,
                               sizeof(KDDEBUGGER_DATA64));

    if (Ret == FALSE) goto freedbgdata;

    if ((DbgData->Header.OwnerTag != KDBG_TAG) || (DbgData->KernBase == 0))
    {
        //
        // Hardcore-way. Please use KdDebuggerDataBlock in the future.
        // This should never be reached.
        //

        //Ret = KeFindKernelImageBase(Handle);
        Ret = FALSE;
    }
    else
    {
        g_KiExcaliburData.KernelBase = DbgData->KernBase;
    }

#if DEBUG_ENABLED
    wprintf(L"Kernel Image Base: %I64X\n", g_KiExcaliburData.KernelBase);
#endif

freedbgdata:
    // LocalFree(DbgData);
    free(DbgData);

finish:
    // LocalFree(Header32);
    free(Header32);

    return Ret;
}

BOOL
KeRawInitializeData(
    HANDLE Handle
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

    ULONG VersionId;

    PUCHAR Page;

    ULARGE_INTEGER Pa;

    BOOL bValidTable;

    Ret = FALSE;
    bValidTable = FALSE;

    // Page = LocalAlloc(LPTR, PAGE_SIZE);
    Page = (PUCHAR)malloc(PAGE_SIZE);
    if (Page == NULL) return FALSE;

    for (VersionId = 0; VersionId < MAX_SUPPORTED_VERSION; VersionId += 1)
    {
#if DEBUG_ENABLED
        wprintf(L"Index = %d Cr3 = %I64X\n", VersionId, KernelCr3[VersionId]);
#endif

        if ((VersionId == WINDOWS_NT52_X86) ||
            (VersionId == WINDOWS_NT51_X86) ||
            (VersionId == WINDOWS_NT50_X86))
        {
            if (!(KernelKPCR[VersionId] && KernelCr3[VersionId])) continue;

#if DEBUG_ENABLED
            wprintf(L"if (VersionId == (WINDOWS_NT52_X86 || WINDOWS_NT51_X86 || WINDOWS_NT50_X86)\n");
#endif

            //
            // N.B. Coule be MmGetPhysicalAddress32(KernelCr3[VersionId], 0xffdff000) == 0x40000
            //
            Pa.QuadPart = KernelKPCR[VersionId];
            Ret = MmReadPhysicalAddress(Handle,
                                        Pa,
                                        Page,
                                        PAGE_SIZE);

            if (Ret == FALSE) continue;

            bValidTable = FALSE;

#if DEBUG_ENABLED
            wprintf(L"KernelKPCR[VersionId] = %X\n KernelCr3[VersionId] = %X\n",
                    KernelKPCR[VersionId],
                    KernelCr3[VersionId]);
#endif
            if (MmValidatex86KPCR(Handle, Page))
            {
                PX86_KSPECIAL_REGISTERS SpecialRegs;

                //
                // 00319000ULL (PAE)
                // 00039000ULL
                //

                //
                // Valid DirectoryTableBase
                //

#if DEBUG_ENABLED
                wprintf(L"MmValidatex86KPCR(0x%I64X) == TRUE\n", Pa.QuadPart);
#endif

                bValidTable = TRUE;

                SpecialRegs = (PX86_KSPECIAL_REGISTERS)(&Page[X86_KPRCB_OFFSET 
                                                              + X86_KPROCESSOR_STATE_OFFSET 
                                                              + X86_CONTEXT_OFFSET 
                                                              + X86_KSPECIAL_REGISTERS_OFFSET]);

                Pa.QuadPart = (ULONGLONG)(SpecialRegs->Cr3);
                Pa.QuadPart &= ~0x1FULL;

                Ret = MmReadPhysicalAddress(Handle,
                                            Pa,
                                            Page,
                                            PAGE_SIZE);

                if (Ret == FALSE) continue;

                //
                // We manually check if PAE is activated.
                //
                g_KiExcaliburData.PaeEnabled = MmValidatex86PaePageDirectoryPointerTable(Handle, Pa);
                g_KiExcaliburData.DirectoryTableBase = Pa.QuadPart;

#if DEBUG_ENABLED
                wprintf(L"g_KiExcaliburData.DirectoryTableBase = 0x%I64X;\n", Pa.QuadPart);
#endif

                //
                // Additional test: We compare our home-made PAE detection vs. CR4 value.
                // Doesn't work well. Cr4 can be broken.
                //
                // if (g_KiExcaliburData.PaeEnabled != IS_PAE(SpecialRegs->Cr4)) continue;

                g_KiExcaliburData.MachineType = MACHINE_X86;

                //
                // Guessed NT Version.
                //
                if (VersionId == WINDOWS_NT51_X86)
                {
                    g_KiExcaliburData.MajorVersion = 5;
                    g_KiExcaliburData.MinorVersion = 1;
                }
                else if (VersionId == WINDOWS_NT52_X86)
                {
                    g_KiExcaliburData.MajorVersion = 5;
                    g_KiExcaliburData.MinorVersion = 2;
                }

                goto success;
            }
        }
#ifdef PRO_EDITION
        else if (VersionId == WINDOWS_NT52_X64)
        {
            //
            // Invalid KPCR address
            //
            if (!(KernelKPCR[VersionId])) continue;


            Pa.QuadPart = KernelKPCR[VersionId];
#if DEBUG_ENABLED
            wprintf(L"(VersionId == WINDOWS_NT52_X64)\n");
            wprintf(L"XP64bits : KPCR: %I64X\n", Pa.QuadPart);
#endif
            Ret = MmReadPhysicalAddress(Handle,
                                        Pa,
                                        Page,
                                        PAGE_SIZE);

            if (Ret == FALSE) continue;

            bValidTable = FALSE;

            if (MmValidatex64KPCR(Page))
            {
                PX64_KSPECIAL_REGISTERS SpecialRegs;

#if DEBUG_ENABLED
                wprintf(L"MmValidatex64KPCR(0x%I64X) == TRUE\n", Pa.QuadPart);
#endif

                //
                // Valid DirectoryTableBase
                //

                bValidTable = TRUE;

                SpecialRegs = (PX64_KSPECIAL_REGISTERS)(&Page[X64_KPRCB_OFFSET 
                                                              + X64_KPROCESSOR_STATE_OFFSET 
                                                              + X64_KSPECIAL_REGISTERS_OFFSET]);

                Pa.QuadPart = (ULONGLONG)SpecialRegs->Cr3;
                Pa.QuadPart &= ~0x1FULL;

                g_KiExcaliburData.DirectoryTableBase = Pa.QuadPart;
                g_KiExcaliburData.MachineType = MACHINE_AMD64;

#if DEBUG_ENABLED
                wprintf(L"g_KiExcaliburData.DirectoryTableBase = 0x%I64X;\n", Pa.QuadPart);
#endif

                //
                // Guessed NT Version.
                //
                g_KiExcaliburData.MajorVersion = 5;
                g_KiExcaliburData.MinorVersion = 2;

                goto success;
            }
#if DEBUG_ENABLED
            wprintf(L"MmValidatex64KPCR = FALSE\n");
#endif
        }
#endif
        else if ((VersionId == WINDOWS_NT60_X86) || 
                 (VersionId == WINDOWS_NT61_X86))
        {
            if (!KernelCr3[VersionId]) continue;

#if DEBUG_ENABLED
            wprintf(L"(VersionId == WINDOWS_NT60_X86 ||  WINDOWS_NT61_X86)\n");
            wprintf(L"DTB? = 0x%I64X\n", KernelCr3[VersionId]);
#endif
            Pa.QuadPart = KernelCr3[VersionId];
            Ret = MmReadPhysicalAddress(Handle,
                                        Pa,
                                        Page,
                                        PAGE_SIZE);

            if (Ret == FALSE) continue;

            bValidTable = MmValidatex86PaePageDirectoryPointerTable(Handle, Pa);

#if DEBUG_ENABLED
            wprintf(L"MmValidatex86PaePageDirectoryPointerTable(0x%I64X) == %s\n", Pa.QuadPart, bValidTable ? L"TRUE" : L"FALSE");
#endif
            if (bValidTable == TRUE)
            {
                g_KiExcaliburData.PaeEnabled = TRUE;
            }
            else
            {
                bValidTable = MmValidatex86NoPaePageDirectoryTable(Handle, Pa);
#if DEBUG_ENABLED
                wprintf(L"MmValidatex86NoPaePageDirectoryTable(0x%I64X) == %s\n", Pa.QuadPart, bValidTable ? L"TRUE" : L"FALSE");
#endif
            }

            if (bValidTable == FALSE) continue;

            //
            // Valid DirectoryTableBase
            //
            g_KiExcaliburData.DirectoryTableBase = Pa.QuadPart;
            g_KiExcaliburData.MachineType = MACHINE_X86;

#if DEBUG_ENABLED
                wprintf(L"g_KiExcaliburData.DirectoryTableBase = 0x%I64X;\n", Pa.QuadPart);
#endif

            //
            // Guessed NT Version.
            //
            if (VersionId == WINDOWS_NT60_X86)
            {
                g_KiExcaliburData.MajorVersion = 6;
                g_KiExcaliburData.MinorVersion = 0;
            }
            else if (VersionId == WINDOWS_NT61_X86)
            {
                g_KiExcaliburData.MajorVersion = 6;
                g_KiExcaliburData.MinorVersion = 1;
            }

            goto success;
        }
#ifdef PRO_EDITION
        else if ((VersionId == WINDOWS_NT60_X64) ||
                 (VersionId == WINDOWS_NT61_X64) ||
				 (VersionId == WINDOWS_NT10_x64_1803) ||
				 (VersionId == WINDOWS_NT10_x64_1804)
				 )
        {
            if (!KernelCr3[VersionId]) continue;

#if DEBUG_ENABLED
                wprintf(L"(VersionId == WINDOWS_NT60_X64 || WINDOWS_NT61_X64) || WINDOWS_NT10_X64_1803\n");
#endif

            Pa.QuadPart = KernelCr3[VersionId];
            Ret = MmReadPhysicalAddress(Handle,
                                        Pa,
                                        Page,
                                        PAGE_SIZE);

            if (Ret == FALSE) continue;

            bValidTable = MmValidatex64PageMapLevel4Table(Handle, Pa);

#if DEBUG_ENABLED
            wprintf(L"MmValidatex64PageMapLevel4Table(0x%I64X) == %s\n", Pa.QuadPart, bValidTable ? L"TRUE" : L"FALSE");
#endif

            if (bValidTable == FALSE) continue;

            //
            // Valid DirectoryTableBase
            //
            g_KiExcaliburData.DirectoryTableBase = Pa.QuadPart;
            g_KiExcaliburData.MachineType = MACHINE_AMD64;

#if DEBUG_ENABLED
                wprintf(L"g_KiExcaliburData.DirectoryTableBase = 0x%I64X;\n", Pa.QuadPart);
#endif

            if (VersionId == WINDOWS_NT60_X64)
            {
                g_KiExcaliburData.MajorVersion = 6;
                g_KiExcaliburData.MinorVersion = 0;
            }
            else if (VersionId == WINDOWS_NT61_X64)
            {
                g_KiExcaliburData.MajorVersion = 6;
                g_KiExcaliburData.MinorVersion = 1;
            }
			else if (VersionId == WINDOWS_NT10_x64_1803 || VersionId == WINDOWS_NT10_x64_1804)
			{
				g_KiExcaliburData.MajorVersion = 10;
				g_KiExcaliburData.MinorVersion = 0;
			}

            goto success;
        }
#endif
    }

#ifdef PRO_EDITION
    if (bValidTable == FALSE)
    {
        wprintf(L"Brute force\n");
        //
        // Not found -> Generic Method.
        //
        for (Pa.QuadPart = 0x30000ULL;
             Pa.QuadPart < 0x400000ULL;
             Pa.QuadPart += PAGE_SIZE)
        {
            //
            // MmReadPhysicalAddress does check if address is out of range or not.
            //
            Ret = MmReadPhysicalAddress(Handle,
                                        Pa,
                                        Page,
                                        PAGE_SIZE);

            if (Ret == FALSE) break;

            if (bValidTable = MmValidatex86PaePageDirectoryPointerTable(Handle, Pa))
            {
#if DEBUG_ENABLED
            wprintf(L"MmValidatex86PaePageDirectoryPointerTable(0x%I64X) == %s\n", Pa.QuadPart, bValidTable ? L"TRUE" : L"FALSE");
#endif
                g_KiExcaliburData.PaeEnabled = TRUE;
                g_KiExcaliburData.MachineType = MACHINE_X86;
            }
            else if (bValidTable = MmValidatex86NoPaePageDirectoryTable(Handle, Pa))
            {
#if DEBUG_ENABLED
            wprintf(L"MmValidatex86NoPaePageDirectoryTable(0x%I64X) == %s\n", Pa.QuadPart, bValidTable ? L"TRUE" : L"FALSE");
#endif
                g_KiExcaliburData.PaeEnabled = FALSE;
                g_KiExcaliburData.MachineType = MACHINE_X86;
            }
            else if (bValidTable = MmValidatex64PageMapLevel4Table(Handle, Pa))
            {
#if DEBUG_ENABLED
            wprintf(L"MmValidatex64PageMapLevel4Table(0x%I64X) == %s\n", Pa.QuadPart, bValidTable ? L"TRUE" : L"FALSE");
#endif
                g_KiExcaliburData.PaeEnabled = TRUE;
                g_KiExcaliburData.MachineType = MACHINE_AMD64;
            }

            if (bValidTable)
            {
                g_KiExcaliburData.DirectoryTableBase = Pa.QuadPart;

                goto success;
            }
#if DEBUG_ENABLED
            wprintf(L"None(0x%I64X) == %s\n", Pa.QuadPart, bValidTable ? L"TRUE" : L"FALSE");
#endif
        }
    }
#endif

success:

    if (bValidTable == TRUE)
    {
#if TRUE
        wprintf(L"Directory Table Base is 0x%I64x",
            g_KiExcaliburData.DirectoryTableBase);

        if (g_KiExcaliburData.MachineType == MACHINE_X86)
        {
            wprintf(L" %s PAE",
            g_KiExcaliburData.PaeEnabled ? L"with" : L"without");
        }

        wprintf(L"\n");
#endif
    }
    else
    {
#ifndef PRO_EDITION
        Red(L"Error: This file format is not supported in this product version.\n"
            L"       Don't wait any longer ! Upgrade to Professional Edition ! \n");
        White(L"       More information on http://www.moonsols.com\n\n");
#endif
        Ret = FALSE;
    }

    // LocalFree(Page);
    free(Page);

    if (g_KiExcaliburData.MachineType == MACHINE_AMD64)
    {
        wprintf(L"Looking for Kernel Base...\n");
        Ret = KeFindKernelImageBase(Handle);

        if (Ret == FALSE) return Ret;
    }

    if (bValidTable)
    {
        White(L"Looking for kernel variables... \n");
        Ret = KeFindDbgDataBlock(Handle, g_KiExcaliburData.KernelBase);
        if (Ret == TRUE)
        {
            Green(L"Done.\n");
        }
        else
        {
            Red(L"Failed.\n");
        }
    }
    else
    {
        White(L"Looking for Directory Table Base... ");
        Red(L"Failed.\n");
    }

    return Ret;
}

BOOL
KeHibrInitializeData(
    HANDLE Handle
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
    ULARGE_INTEGER Address;
    PUCHAR Buffer;

    ULONG PageIndex;

    BOOL Ret;

    ULONG64 RegRip = 0;

    Ret = FALSE;

    Buffer = (PUCHAR)malloc(PAGE_SIZE * 0x10); // (PUCHAR)LocalAlloc(LPTR, PAGE_SIZE * 0x10);
    if (Buffer == NULL) return Ret;

    Address.QuadPart = 0;
    if ((Ret = ReadFileAsynchronous(Handle, Address, Buffer, PAGE_SIZE * 0x10)) == FALSE)
    {
        InternalErrorCode = TRUE;
        goto finish;
    }

    Ret = FALSE;
    for (PageIndex = 0;
         PageIndex < 0x10;
         PageIndex += 1)
    {
        if (MmValidationx86KProcState(Handle, Buffer + (PageIndex * PAGE_SIZE)) == TRUE)
        {
            PX86_KSPECIAL_REGISTERS SpecialRegs;
            PX86_CONTEXT Context = NULL;
            ULARGE_INTEGER Pa;
            PUCHAR p;

            p = Buffer + (PageIndex * PAGE_SIZE);
            SpecialRegs = (PX86_KSPECIAL_REGISTERS)&p[X86_KSPECIAL_REGISTERS_OFFSET];
            Context = (PX86_CONTEXT)&p[X86_CONTEXT_OFFSET];
            RegRip = Context->Eip;

            g_KiExcaliburData.DirectoryTableBase = (ULONGLONG)SpecialRegs->Cr3;
            g_KiExcaliburData.DirectoryTableBase &= ~0x1FULL;

            Pa.QuadPart = g_KiExcaliburData.DirectoryTableBase;

            g_KiExcaliburData.PaeEnabled = IS_PAE(SpecialRegs->Cr4);

            g_KiExcaliburData.MachineType = MACHINE_X86;

            Ret = TRUE;
            break;
        }
#ifdef PRO_EDITION
        else if (MmValidationx64KProcState(Buffer + (PageIndex * PAGE_SIZE)))
        {
            PX64_KSPECIAL_REGISTERS SpecialRegs;
            PX64_CONTEXT Context = NULL;
            PUCHAR p;

            p = Buffer + (PageIndex * PAGE_SIZE);

            Context = (PX64_CONTEXT)&p[X64_CONTEXT_OFFSET];
            g_KiExcaliburData.ContextData = malloc(sizeof(X64_CONTEXT));
            if (g_KiExcaliburData.ContextData == NULL) goto finish;
            RtlCopyMemory(g_KiExcaliburData.ContextData, Context, sizeof(X64_CONTEXT));
            g_KiExcaliburData.SizeOfContextData = sizeof(X64_CONTEXT);

            SpecialRegs = (PX64_KSPECIAL_REGISTERS)&p[X64_KSPECIAL_REGISTERS_OFFSET];
            g_KiExcaliburData.SpecialRegsData = malloc(sizeof(X64_KSPECIAL_REGISTERS));
            if (g_KiExcaliburData.SpecialRegsData == NULL) goto finish;
            RtlCopyMemory(g_KiExcaliburData.SpecialRegsData, SpecialRegs, sizeof(X64_KSPECIAL_REGISTERS));
            g_KiExcaliburData.SizeOfSpecialRegsData = sizeof(X64_KSPECIAL_REGISTERS);

            RegRip = Context->Rip;

            g_KiExcaliburData.DirectoryTableBase = SpecialRegs->Cr3;
            g_KiExcaliburData.DirectoryTableBase &= ~(PAGE_SIZE - 1);

            g_KiExcaliburData.MachineType = MACHINE_AMD64;
            g_KiExcaliburData.PaeEnabled = TRUE;

            Ret = TRUE;
            break;
        }
#endif
    }

#if DEBUG_ENABLED
    wprintf(L"KPROCESSOR_STATE at 0x%x\n", PageIndex * PAGE_SIZE);

    wprintf(L"Ret = %d\n", Ret);
    wprintf(L"Cr3: 0x%I64X\n", g_KiExcaliburData.DirectoryTableBase);
    wprintf(L"Type: %d\n", g_KiExcaliburData.MachineType);
    wprintf(L"Pae: %d\n", g_KiExcaliburData.PaeEnabled);
#endif

    if (Ret == TRUE)
    {
        White(L"Looking for kernel variables... ");
        Ret = KeFindDbgDataBlock(Handle, RegRip);
        if (Ret == TRUE)
        {
            Green(L"Done.\n");
        }
        else
        {
            Red(L"Failed.\n");
        }
#if DEBUG_ENABLED
        wprintf(L"(ret = %d) KdDebuggerDataBlock: 0x%I64X\n",
                Ret,
                g_KiExcaliburData.KdDebuggerDataBlock);
        getchar();
#endif
    }

finish:
    free(Buffer); // LocalFree(Buffer);

    return Ret;
}

BOOL
KeFindKernelBaseFromPointer(
    HANDLE Handle,
    ULONG64 KernelImagePointer,
    PULONG64 KernelVa
    )
{
    BOOL Ret = FALSE;

    PUCHAR Page = (PUCHAR)malloc(PAGE_SIZE);
    ULONG MaxSize = (0x100 * PAGE_SIZE) * 32; // 32MB
    ULONG64 CurrentVa = KernelImagePointer & ~(PAGE_SIZE - 1);
    ULONG Offset;

    BOOL Found = FALSE;

    if (!Page) goto CleanUp;

    for (Offset = 0; Offset < MaxSize; Offset += PAGE_SIZE, CurrentVa -= PAGE_SIZE)
    {
        Ret = MmReadVirtualAddress(Handle,
                                   0ULL,
                                   CurrentVa,
                                   Page,
                                   PAGE_SIZE);
        if (!Ret) continue;

        if ((Page[0] == 'M') && (Page[1] == 'Z'))
        {
            Found = TRUE;
            break;
        }
    }

    Ret = Found;

    if (!Found) goto CleanUp;

    *KernelVa = CurrentVa;

CleanUp:
    if (Page) free(Page);

    return Ret;
}

BOOL
KeGetTimerValues(
    HANDLE Handle,
    ULONG64 KeSetTimer,
    PULONG64 KiWaitNever,
    PULONG64 KiWaitAlways
    )
{
    BOOL Ret = FALSE;

    ULONG DeltaOffset;
    ULONGLONG DeltaValue;
    ULONG64 KdMagicValue;
    ULONG Index;

    ULONG ValueCount = 0;

    ULONG64 pKiWaitNever = 0ULL;
    ULONG64 pKiWaitAlways = 0ULL;

    UCHAR pKeSetTimer[0x30] = {0};

    Ret = MmReadVirtualAddress(Handle,
                               0ULL,
                               KeSetTimer,
                               pKeSetTimer,
                               sizeof(pKeSetTimer));
    if (!Ret) goto CleanUp;

    // PeDumpHexa(pKeSetTimer, sizeof(pKeSetTimer));

    for (Index = 0; Index < sizeof(pKeSetTimer); Index += 1)
    {
        if ((pKeSetTimer[Index] == 0x48) && (pKeSetTimer[Index + 1] == 0x8B))
        {
            Index += sizeof(USHORT) + sizeof(UCHAR);

            DeltaOffset = (pKeSetTimer[Index + 3] << 24) | (pKeSetTimer[Index + 2] << 16) | (pKeSetTimer[Index + 1] << 8) | pKeSetTimer[Index];
            wprintf(L"DeltaOffset = %x\n", DeltaOffset);
            DeltaValue = 0xFFFFFFFF00000000;
            DeltaValue += DeltaOffset;

            if (DeltaOffset >= 0x80000000) 
				KdMagicValue = KeSetTimer + Index + sizeof(ULONG) - DeltaOffset;
            else 
				KdMagicValue = KeSetTimer + Index + sizeof(ULONG) + DeltaOffset;

			if (g_KiExcaliburData.MajorVersion == 10) { // for Windows 10 1803
				switch (ValueCount)
				{
				case 0:
					wprintf(L"pKiWaitNever = %I64X\n", KdMagicValue);
					pKiWaitNever = KdMagicValue;
					break;
				case 1:
					Index -= sizeof(USHORT) + sizeof(UCHAR) - 1;
					break;
				case 2:
					wprintf(L"pKiWaitAlways = %I64X\n", KdMagicValue);
					pKiWaitAlways = KdMagicValue;
					break;
				}
			}

			if (g_KiExcaliburData.MajorVersion < 10) { // for Windows 10 1803
				switch (ValueCount)
				{
				case 0:
					wprintf(L"pKiWaitNever = %I64X\n", KdMagicValue);
					pKiWaitNever = KdMagicValue;
					break;
				case 1:
					wprintf(L"pKiWaitAlways = %I64X\n", KdMagicValue);
					pKiWaitAlways = KdMagicValue;
					break;
				}
			}
         ValueCount += 1;
        }
    }

    if (pKiWaitNever)
    {
        Ret = MmReadVirtualAddress(Handle,
                                   0ULL,
                                   pKiWaitNever,
                                   KiWaitNever,
                                   sizeof(ULONG64));
        if (!Ret) goto CleanUp;
         wprintf(L"KiWaitNever = %I64X\n", *KiWaitNever);
    }

    if (pKiWaitAlways)
    {
        Ret = MmReadVirtualAddress(Handle,
                                   0ULL,
                                   pKiWaitAlways,
                                   KiWaitAlways,
                                   sizeof(ULONG64));
		wprintf(L"KiWaitAlways = %I64X\n", *KiWaitAlways);
        if (!Ret) goto CleanUp;
    }

    if (*KiWaitAlways && *KiWaitNever) Ret = TRUE;

CleanUp:
    return Ret;
}

void
KdCopyDataBlock_Decode(
    PULONG64 Data,
    ULONG Size,
    PULONG64 Output,
    ULONG64 KiWaitNever,
    ULONG64 KiWaitAlways,
    OPTIONAL IN ULONG64 InKdpDataBlockEncodedOffset,
    BOOLEAN Verbose
)
{
    //
    // Test function
    //
    ULONG64 rax;
    ULONG i;

    for (i = 0; i < (Size / sizeof(ULONG64)); i += 1)
    {
        rax = Data[i];
        if (Verbose) wprintf(L"rax = 0x%I64X\n", rax);
        rax ^= KiWaitNever;
        // if (Verbose) wprintf(L"rax ^= KiWaitNever => 0x%I64X\n", rax);
        rax = _rotl64(rax, (int)(KiWaitNever & 0xff));
        // if (Verbose) wprintf(L"_rotl64(rax, (int)(KiWaitNever & 0xff)) => 0x%I64X\n", rax);
        rax ^= InKdpDataBlockEncodedOffset;
        // if (Verbose) wprintf(L"rax ^= InKdpDataBlockEncodedOffset => 0x%I64X\n", rax);
        rax = _byteswap_uint64(rax);
        // if (Verbose) wprintf(L"_byteswap_uint64(rax) => 0x%I64X\n", rax);
        rax ^= KiWaitAlways;
        // if (Verbose) wprintf(L"rax ^= KiWaitAlways => 0x%I64X\n", rax);
        Output[i] = rax;
    }
}

void
FindKdpDataBlockEncodedOffset(
    ULONG64 EncodedInput,
    ULONG64 ExpectDecoded,
    ULONG64 KiWaitNever,
    ULONG64 KiWaitAlways,
    PULONG64 MyKdpDataBlockEncodedOffset)
{
    ULONG64 rax_decoded, rax_encoded;

    if (!MyKdpDataBlockEncodedOffset) return;

    // wprintf(L"\n*-*-START-*-*\n");
    rax_decoded = EncodedInput;
    // wprintf(L"rax_decoded = 0x%I64X\n", rax_decoded);
    rax_decoded ^= KiWaitNever;
    // wprintf(L"rax_decoded ^= KiWaitNever = 0x%I64X\n", rax_decoded);
    rax_decoded = _rotl64(rax_decoded, (int)(KiWaitNever & 0xff));
    // wprintf(L"_rotl64(rax_decoded, (int)(KiWaitNever & 0xff) = 0x%I64X\n", rax_decoded);

    rax_encoded = ExpectDecoded;
    // wprintf(L"rax_encoded = 0x%I64X\n", rax_encoded);
    rax_encoded ^= KiWaitAlways;
    // wprintf(L"rax_encoded ^= KiWaitAlways = 0x%I64X\n", rax_encoded);
    rax_encoded = _byteswap_uint64(rax_encoded);
    // wprintf(L"_byteswap_uint64(rax_encoded) = 0x%I64X\n", rax_encoded);

    *MyKdpDataBlockEncodedOffset = rax_decoded ^ rax_encoded;
    // wprintf(L"(guessed) KdpDataBlockEncodedOffset = 0x%I64X\n", *MyKdpDataBlockEncodedOffset);

    // wprintf(L"*-*-END-*-*\n\n");
}

BOOL
KeGetDecodedKdbg(
    HANDLE Handle,
    ULONG64 KernelImagePointer,
    PULONG64 OutDbgDataBlockVa,
    PKDDEBUGGER_DATA64 *OutDbgData
    )
{
    BOOL ReturnRet = FALSE;
    BOOL Ret = FALSE;
    ULONG64 ImageBase;

    ULONG64 KiWaitNever = 0ULL;
    ULONG64 KiWaitAlways = 0ULL;
    ULONG64 KeSetTimer = 0ULL;

    UCHAR pKeSetTimer[0x30] = {0};

    ULONG DataSectionVa = 0;
    ULONG DataSectionOffset = 0;
    ULONG DataSectionSize = 0;

    PULONG Data = NULL;
    PULONG DecodedData = NULL;
    PVOID EncodedData = NULL;

    ULONG64 KdDebuggerDataBlock = 0;
    ULONG64 KdpDataBlockEncodedOffset = 0;
    ULONG64 EncodedKdDebuggerDataBlock = 0;

    ULONG i;
    *OutDbgData = NULL;

    Ret = KeFindKernelBaseFromPointer(Handle, KernelImagePointer, &ImageBase);
    if (!Ret) goto CleanUp;
    wprintf(L"-> ImageBase = 0x%I64X\n", ImageBase);

    Ret = PeGetSection(Handle, ImageBase, (PUCHAR)".data", &DataSectionVa, &DataSectionOffset, &DataSectionSize);
    if (!Ret) goto CleanUp;
    wprintf(L"-> DataSectionVa = 0x%x DataSectionOffset = 0x%X DataSectionSize = 0x%X\n", DataSectionVa, DataSectionOffset, DataSectionSize);

    Data = (PULONG)malloc(DataSectionSize);
    if (Data == NULL) goto CleanUp;
    RtlZeroMemory(Data, DataSectionSize);

    Ret = MmReadVirtualAddress(Handle,
                               0ULL,
                               ImageBase + DataSectionVa,
                               Data,
                               DataSectionSize);
    if (!Ret) goto CleanUp;

    if (g_KiExcaliburData.MachineType == MACHINE_AMD64)
    {
		if (g_KiExcaliburData.MajorVersion < 10) {
			KeSetTimer = PeGetProcAddress(Handle, ImageBase, "KeSetTimer");//
		}

		if (g_KiExcaliburData.MajorVersion == 10) {
			KeSetTimer = PeGetProcAddress(Handle, ImageBase, "KeSetTimerEx");// for Windows 10 1803
		}
        if (KeSetTimer == 0ULL) goto CleanUp;
         wprintf(L"-> KeSetTimer = 0x%I64X\n", KeSetTimer);

        Ret = KeGetTimerValues(Handle, KeSetTimer, &KiWaitNever, &KiWaitAlways);
        if (Ret)
        {
            wprintf(L"-> KiWaitNever = 0x%I64X KiWaitAlways = 0x%I64X\n", KiWaitNever, KiWaitAlways);

            DecodedData = (PULONG)malloc(DataSectionSize);
            if (DecodedData == NULL) goto CleanUp;
            RtlZeroMemory(DecodedData, DataSectionSize);

            KdCopyDataBlock_Decode((PULONG64)Data,
                                   DataSectionSize,
                                   (PULONG64)DecodedData,
                                   KiWaitNever,
                                   KiWaitAlways,
                                   (ImageBase & 0xffffffff00000000),
                                   FALSE);
        }
    }

    for (i = 0; i < DataSectionSize / sizeof(ULONG); i += 1)
    {
        if (DecodedData && (DecodedData[i] == KDBG_TAG))
        {
            PDBGKD_DEBUG_DATA_HEADER64 DbgDataHeader = NULL;

            g_KiExcaliburData.IsEncodedDbgDataBlock = TRUE;

            wprintf(L"KDBG signature found!\n");
            KdDebuggerDataBlock = ImageBase + DataSectionVa + (i * sizeof(ULONG)) - sizeof(LIST_ENTRY64);
            wprintf(L"Mistaken: KdDebuggerDataBlock = %I64X\n", KdDebuggerDataBlock);
            KdDebuggerDataBlock = (ImageBase & 0xffffffff00000000) | DecodedData[i - (sizeof(LIST_ENTRY64)/sizeof(ULONG))];
            wprintf(L"Real: KdDebuggerDataBlock = %I64X\n", KdDebuggerDataBlock);
            EncodedData = (PDBGKD_DEBUG_DATA_HEADER64)&Data[i - (sizeof(LIST_ENTRY64)/sizeof(ULONG))];

            wprintf(L"KdDebuggerDataBlock = 0x%I64x\n", KdDebuggerDataBlock);

            EncodedKdDebuggerDataBlock = ((PULONG64)EncodedData)[0];
            wprintf(L"KdDebuggerDataBlock = 0x%I64X\n[EncodedKdDebuggerDataBlock] = 0x%I64X\n", KdDebuggerDataBlock, EncodedKdDebuggerDataBlock);
            FindKdpDataBlockEncodedOffset(EncodedKdDebuggerDataBlock, KdDebuggerDataBlock, KiWaitNever, KiWaitAlways, &KdpDataBlockEncodedOffset);

            KdCopyDataBlock_Decode((PULONG64)EncodedData, sizeof(DBGKD_DEBUG_DATA_HEADER64), (PULONG64)DecodedData, KiWaitNever, KiWaitAlways, KdpDataBlockEncodedOffset, FALSE);
            DbgDataHeader = (PDBGKD_DEBUG_DATA_HEADER64)DecodedData;

            //
            // Asserts.
            //
            if ((DbgDataHeader->List.Blink != DbgDataHeader->List.Flink) ||
                (DbgDataHeader->OwnerTag != KDBG_TAG))
            {
                break;
            }

            *OutDbgData = (PKDDEBUGGER_DATA64)malloc(DbgDataHeader->Size);
            if (*OutDbgData == NULL) goto CleanUp;

            KdCopyDataBlock_Decode((PULONG64)EncodedData, DbgDataHeader->Size, (PULONG64)*OutDbgData, KiWaitNever, KiWaitAlways, KdpDataBlockEncodedOffset, FALSE);

            g_KiExcaliburData.DbgData = *OutDbgData;
            g_KiExcaliburData.KdpDataBlockEncodedOffset = KdpDataBlockEncodedOffset;

            KdDebuggerDataBlock = ImageBase + DataSectionVa + (i * sizeof(ULONG)) - sizeof(LIST_ENTRY64);
            *OutDbgDataBlockVa = KdDebuggerDataBlock;

            // wprintf(L"DECODED DATA:\n");
            // PeDumpHexa(DecodedData, 0x40);
            ReturnRet = TRUE;

            break;
        }
        else if (Data[i] == KDBG_TAG)
        {
            PDBGKD_DEBUG_DATA_HEADER64 DbgDataHeader = NULL;

            DbgDataHeader = (PDBGKD_DEBUG_DATA_HEADER64)&Data[i - (sizeof(LIST_ENTRY64)/sizeof(ULONG))];

            *OutDbgData = (PKDDEBUGGER_DATA64)malloc(DbgDataHeader->Size);
            if (*OutDbgData == NULL) goto CleanUp;

            RtlCopyMemory(*OutDbgData, DbgDataHeader, DbgDataHeader->Size);
            *OutDbgDataBlockVa = ImageBase + DataSectionVa + (i * sizeof(ULONG)) - sizeof(LIST_ENTRY64);

            ReturnRet = TRUE;

            break;
        }
    }

CleanUp:
    if (Data) free(Data);
    if (DecodedData) free(DecodedData);

    return ReturnRet;
}

BOOL
KeFindDbgDataBlock(
    HANDLE Handle,
    ULONG64 KernelImagePointer
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
    PKDDEBUGGER_DATA64 DbgData = NULL, AllocatedDbgData = NULL;

    ULONG Index, DwIndex;

    ULONGLONG Base, Va;

    BOOL Ret = FALSE;

    PULONG Page = NULL;

    BOOLEAN ReadVirtualSpace = TRUE;

    ULONG64 KernelBase = 0ULL;

    PDBGKD_GET_VERSION64 DbgKdGetVersion64 = NULL;

    Ret = FALSE;

    Page = (PULONG)malloc(PAGE_SIZE);
    if (Page == NULL) return Ret;

    wprintf(L"KeFindDbgDataBlock(): g_KiExcaliburData.MachineType = %d\n", g_KiExcaliburData.MachineType );

    if (g_KiExcaliburData.MachineType == MACHINE_X86)
    {
        BOOL FirstTry = TRUE;
        ULONG MaxNumberOfPages = 0x10000;

        ReadVirtualSpace = TRUE;

        if (KernelImagePointer)
        {
            if (!KeFindKernelBaseFromPointer(Handle, KernelImagePointer, &Base)) goto finish;
        }
        else
        {
            Base = 0x80000000ULL;
        }

TryAgain:
        if (!ReadVirtualSpace)
        {
            Base = 0ULL;
            MaxNumberOfPages = (ULONG)(MmMaximumPhysicalAddress.QuadPart / PAGE_SIZE);
        }

        for (Index = 0; Index < MaxNumberOfPages; Index += 1, Base += PAGE_SIZE)
        {
#if DEBUG_ENABLED
            // wprintf(L"0x%08X ", Base);
#endif
            if (ReadVirtualSpace)
            {
                Ret = MmReadVirtualAddress(Handle,
                                           0ULL,
                                           Base,
                                           Page,
                                           PAGE_SIZE);
            }
            else
            {
                ULARGE_INTEGER Pa = {0};

                Pa.QuadPart = Base;
                Ret = MmReadPageAtPhysicalAddress(Handle, Pa, Page, PAGE_SIZE);
            }

            if (Ret)
            {
                for (DwIndex = 4; DwIndex < (PAGE_SIZE / sizeof(ULONG)); DwIndex += 1)
                {
                    if (Page[DwIndex] == KDBG_TAG)
                    {
                        PLIST_ENTRY32 List;

                        DbgData = (PKDDEBUGGER_DATA64)((PUCHAR)(&Page[DwIndex]) - sizeof(LIST_ENTRY64));

                        wprintf(L"DbgData->Header.Size = %X\n", DbgData->Header.Size);
                        if (DbgData->Header.Size >= 0x400) continue;
                        // wprintf(L"Step 1 . Ok\n");

                        // wprintf(L"DbgData->Header.List.Blink = %I64X\n", DbgData->Header.List.Blink);
                        // wprintf(L"DbgData->Header.List.Flink = %I64X\n", DbgData->Header.List.Flink);
                        if (DbgData->Header.List.Blink != 0) continue;
                        // wprintf(L"Step 2 . Ok\n");

                        List = (PLIST_ENTRY32)(DbgData);
                        // wprintf(L"List->Flink = %X\n", List->Flink);
                        // wprintf(L"List->Blink = %X\n", List->Blink);
                        if (List->Flink != List->Blink) continue;
                        // wprintf(L"Step 3 . Ok\n");

                        Ret = TRUE;

                        Va = Base + DwIndex * sizeof(ULONG) - sizeof(LIST_ENTRY64);

                        goto success;
                    }
                }

                Ret = FALSE;
            }
        }

        if (ReadVirtualSpace)
        {
            //
            // /3GB and /LARGEADDRESSAWARE option compability.
            //
            if (Ret == FALSE && FirstTry)
            {
                Base = 0xC0000000ULL;
                FirstTry = FALSE;
                goto TryAgain;
            }
            else
            {
                ReadVirtualSpace = FALSE;
                goto TryAgain;
            }
        }
    }
    else if (g_KiExcaliburData.MachineType == MACHINE_AMD64)
    {
        //
        // Faster to walk through the physical address space first.
        //
        ReadVirtualSpace = TRUE;

#if DEBUG_ENABLED
        wprintf(L"KernelImagePointer = %I64X\n", KernelImagePointer);
#endif

        if (KernelImagePointer)
        {
            if (!KeFindKernelBaseFromPointer(Handle, KernelImagePointer, &KernelBase)) goto finish;
            Ret = KeGetDecodedKdbg(Handle, KernelImagePointer, &Va, &AllocatedDbgData);
            if (!Ret) goto finish;

            DbgData = AllocatedDbgData;
        }
        else
        {
            ULONG MaxNumberOfPages;

            Base = 0ULL;
            MaxNumberOfPages = (ULONG)(MmMaximumPhysicalAddress.QuadPart / PAGE_SIZE);

            for (Index = 0; Index < MaxNumberOfPages; Index += 1, Base += PAGE_SIZE)
            {
                if (ReadVirtualSpace)
                {
                    Ret = MmReadVirtualAddress(Handle,
                                               0ULL,
                                               Base,
                                               Page,
                                               PAGE_SIZE);
                }
                else
                {
                    ULARGE_INTEGER Pa = {0};

                    Pa.QuadPart = Base;
                    Ret = MmReadPageAtPhysicalAddress(Handle, Pa, Page, PAGE_SIZE);
                }

                if (Ret)
                {
                    for (DwIndex = 4; DwIndex < (PAGE_SIZE / sizeof(ULONG)); DwIndex += 1)
                    {
                        if (Page[DwIndex] == KDBG_TAG)
                        {
                            DbgData = (PKDDEBUGGER_DATA64)((PUCHAR)(&Page[DwIndex]) - sizeof(LIST_ENTRY64));

                            if (DbgData->Header.Size >= 0x400) continue;

                            if (DbgData->Header.List.Blink != DbgData->Header.List.Flink) continue;

                            Ret = TRUE;

                            Va = Base + DwIndex * sizeof(ULONG) - sizeof(LIST_ENTRY64);

                            goto success;
                        }
                    }
                    Ret = FALSE;
                }
            }
        }
    }

success:
    g_KiExcaliburData.KdDebuggerDataBlock = Va;

    if ((g_KiExcaliburData.KernelBase == 0) || (g_KiExcaliburData.KernelBase != DbgData->KernBase))
    {
        g_KiExcaliburData.KernelBase = DbgData->KernBase;
    }

    g_KiExcaliburData.MmPfnDatabase = DbgData->MmPfnDatabase;
    g_KiExcaliburData.PsLoadedModuleList = DbgData->PsLoadedModuleList;
    g_KiExcaliburData.PsActiveProcessHead = DbgData->PsActiveProcessHead;
    g_KiExcaliburData.PspCidTable = DbgData->PspCidTable;

#if DEBUG_ENABLED
    wprintf(L"KernelBase = %I64X\n"
            L"MmPfnDatabase = %I64X\n"
            L"PsLoadedModuleList = %I64X\n"
            L"PsActiveProcessHead = %I64X\n"
            L"PspCidTable = %I64X\n",
            SIGN_EXTEND(g_KiExcaliburData.KernelBase),
            g_KiExcaliburData.MmPfnDatabase,
            g_KiExcaliburData.PsLoadedModuleList,
            g_KiExcaliburData.PsActiveProcessHead,
            g_KiExcaliburData.PspCidTable);
#endif

    //
    // Count number of entries.
    //
    g_KiExcaliburData.KiProcessorBlock = DbgData->KiProcessorBlock;

    if (g_KiExcaliburData.MachineType == MACHINE_X86)
    {
        PULONG ProcBlock;
        ULONG ProcBlockSize;
        ULONG NumberProcessors;

        ProcBlockSize = sizeof(ULONG) * MAX_PROCESSORS;

        // ProcBlock = LocalAlloc(LPTR, ProcBlockSize);
        ProcBlock = (PULONG)malloc(ProcBlockSize);
        if (ProcBlock == NULL) goto finish;

        Ret = MmReadVirtualAddress(Handle,
                       0ULL,
                       g_KiExcaliburData.KiProcessorBlock,
                       ProcBlock,
                       ProcBlockSize);

        if (Ret == FALSE)
        {
            // LocalFree(ProcBlock);
            free(ProcBlock);
            goto finish;
        }

#if DEBUG_ENABLED
        wprintf(L"Get Proc ... \n");
#endif
        for (NumberProcessors = 0;
             ProcBlock[NumberProcessors] != 0;
             NumberProcessors += 1)
        {
            if (NumberProcessors >= MAX_PROCESSORS) break;
#if DEBUG_ENABLED
            wprintf(L"#%d 0x%08X\n", NumberProcessors, ProcBlock[NumberProcessors]);
#endif
        }

        g_KiExcaliburData.NumberProcessors = NumberProcessors;
        // LocalFree(ProcBlock);
        free(ProcBlock);
    }
    else if (g_KiExcaliburData.MachineType == MACHINE_AMD64)
    {
        PULONGLONG ProcBlock;
        ULONG ProcBlockSize;

        ULONG NumberProcessors;

        ProcBlockSize = sizeof(ULONGLONG) * MAX_PROCESSORS;
        // ProcBlock = LocalAlloc(LPTR, ProcBlockSize);
        ProcBlock = (PULONGLONG)malloc(ProcBlockSize);
        if (ProcBlock == NULL) goto finish;

        Ret = MmReadVirtualAddress(Handle,
                       0ULL,
                       g_KiExcaliburData.KiProcessorBlock,
                       ProcBlock,
                       ProcBlockSize);

        if (Ret == FALSE)
        {
            // LocalFree(ProcBlock);
            free(ProcBlock);
            goto finish;
        }

#if DEBUG_ENABLED
        wprintf(L"Get Proc ... \n");
#endif
        for (NumberProcessors = 0;
             ProcBlock[NumberProcessors] != 0;
             NumberProcessors += 1)
        {
            if (NumberProcessors >= MAX_PROCESSORS) break;
#if DEBUG_ENABLED
            wprintf(L"#%d 0x%I64X\n", NumberProcessors, ProcBlock[NumberProcessors]);
#endif
        }

        g_KiExcaliburData.NumberProcessors = NumberProcessors;

        // LocalFree(ProcBlock);
        free(ProcBlock);
    }

    Va = PeGetProcAddress(Handle, g_KiExcaliburData.KernelBase, "NtBuildNumber");
    if (Va)
    {
        Ret = MmReadVirtualAddress(Handle, 0ULL, Va, &g_KiExcaliburData.NtBuildNumber, sizeof(g_KiExcaliburData.NtBuildNumber));
    }

#if DEBUG_ENABLED
    wprintf(L"1) g_KiExcaliburData.NtBuildNumber: %x\n",
        g_KiExcaliburData.NtBuildNumber); 
#endif

    if (g_KiExcaliburData.NtBuildNumber == 0)
    {
        PULONG Ptr = NULL;

        Ret = FALSE;
        // ?? (Hibr2Dmp!_DBGKD_GET_VERSION64 *)((PUCHAR)DbgData + sizeof(Hibr2Dmp!_KDDEBUGGER_DATA64))

        // goto finish;

        DbgKdGetVersion64 = (PDBGKD_GET_VERSION64)(DbgData + 1);
#if DEBUG_ENABLED
        //
        // Assert
        //
        wprintf(L"DbgKdGetVersion64 = %p\n", DbgKdGetVersion64);
        wprintf(L"[0x%x] KernBase = 0x%I64x\n", 0, DbgKdGetVersion64->KernBase);
        wprintf(L"[0x%x] PsLoadedModuleList = 0x%I64x\n", 0, DbgKdGetVersion64->PsLoadedModuleList);
        getchar();
#endif

#if DEBUG_ENABLED
        wprintf(L"Retrieve DBGKD_GET_VERSION64\n");
        getchar();
#endif
        for (DwIndex = 0; DwIndex < ((PAGE_SIZE - sizeof(DBGKD_GET_VERSION64)) / sizeof(ULONG)); DwIndex += 1)
        {
            //
            // Page must contain the physical page that has the KDBG structure.
            //
            DbgKdGetVersion64 = (PDBGKD_GET_VERSION64)&Page[DwIndex];

#if DEBUG_ENABLED
            wprintf(L"DbgKdGetVersion64 = %p\n", DbgKdGetVersion64);
            wprintf(L"[0x%x] KernBase = 0x%I64x\n", DwIndex, DbgKdGetVersion64->KernBase);
            wprintf(L"[0x%x] PsLoadedModuleList = 0x%I64x\n", DwIndex, DbgKdGetVersion64->PsLoadedModuleList);
            getchar();

            // _asm int 3;
#endif

            if ((SIGN_EXTEND(DbgKdGetVersion64->KernBase) == SIGN_EXTEND(g_KiExcaliburData.KernelBase)) &&
                (SIGN_EXTEND(DbgKdGetVersion64->PsLoadedModuleList) == SIGN_EXTEND(g_KiExcaliburData.PsLoadedModuleList)))
            {
                g_KiExcaliburData.NtBuildNumber = (DbgKdGetVersion64->MajorVersion << 16) | (DbgKdGetVersion64->MinorVersion);

                Ret = TRUE;

#if DEBUG_ENABLED
                wprintf(L"-> (Major: %d, Minor %d)\n", DbgKdGetVersion64->MajorVersion, DbgKdGetVersion64->MinorVersion);
#endif
                break;
            }
        }
        // goto finish;
    }

#if DEBUG_ENABLED
    wprintf(L"g_KiExcaliburData.NtBuildNumber: %x\n",
        g_KiExcaliburData.NtBuildNumber); 
#endif

finish:
    // if (AllocatedDbgData) free(AllocatedDbgData);
    free(Page); // LocalFree(Page);

    return Ret;
}

BOOL
KeFindKernelImageBase(
    HANDLE Handle
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
PUCHAR Page;

ULONGLONG ImageBase;
ULONG Index;

BOOL Ret;

BYTE PdbFileName[MAX_PATH];

    Ret = FALSE;

    // Page = LocalAlloc(LPTR, PAGE_SIZE);
    Page = (PUCHAR)malloc(PAGE_SIZE);
    if (Page == NULL) return Ret;

    switch (g_KiExcaliburData.MachineType)
    {
        case MACHINE_X86:
            ImageBase = 0x80000000ULL;
            for (Index = 0; Index < 0x10000; Index += 1, ImageBase += PAGE_SIZE)
            {
                Ret = MmReadVirtualAddress(Handle,
                                           0ULL,
                                           ImageBase,
                                           Page,
                                           PAGE_SIZE);

                if (Ret)
                {
                    if ((Page[0] == 'M') && (Page[1] == 'Z'))
                    {
                        ULONG ImageSize;
                        ULONG DebugDirRva;

                        Ret = PeGetPdbName(Handle,
                                           ImageBase,
                                           PdbFileName,
                                           sizeof(PdbFileName),
                                           &ImageSize,
                                           &DebugDirRva);

                        if (Ret && 
                            (strstr(_strlwr((PCHAR)PdbFileName), "ntkrnlmp") ||
                             strstr(_strlwr((PCHAR)PdbFileName), "ntkrnlpa") ||
                             strstr(_strlwr((PCHAR)PdbFileName), "ntoskrnl") ||
                             strstr(_strlwr((PCHAR)PdbFileName), "ntkrnlup") ||
                             strstr(_strlwr((PCHAR)PdbFileName), "ntkrpamp")))
                        {
#if DEBUG_ENABLED
                            wprintf(L"\nKernel Image Base: 0x%I64x (0x%x)\n",
                                    ImageBase,
                                    ImageSize);
#endif
                            g_KiExcaliburData.KernelBase = ImageBase;
                            g_KiExcaliburData.SizeOfKernelImage = ImageSize;

#if LOAD_SYMBOLS
                            SymInit();
                            SymLoadForImageBase(Handle, ImageBase, ImageSize);
                            SymDestroy();
#endif
                            goto success;
                        }
                    }
                }
            }
        break;
        case MACHINE_AMD64:
            ImageBase = 0xfffff80000000000ULL;
            for (Index = 0; Index < 0x1100000; Index += 1, ImageBase += PAGE_SIZE) // need add GetRawFileSize/PAGE_SIZE
            {
                Ret = MmReadVirtualAddress(Handle,
                                           0ULL,
                                           ImageBase,
                                           Page,
                                           PAGE_SIZE);

                if (Ret)
                {
                    if ((Page[0] == 'M') && (Page[1] == 'Z'))
                    {
                        ULONG ImageSize;
                        ULONG DebugDirRva;

						wprintf(L"\Scanning image Base: 0x%I64x \n", ImageBase);

                        Ret = PeGetPdbName(Handle,
                                           ImageBase,
                                           PdbFileName,
                                           sizeof(PdbFileName),
                                           &ImageSize,
                                           &DebugDirRva);

                        if (Ret && 
                            (strstr(_strlwr((PCHAR)PdbFileName), "ntkrnlmp") ||
                             strstr(_strlwr((PCHAR)PdbFileName), "ntkrnlpa") ||
                             strstr(_strlwr((PCHAR)PdbFileName), "ntoskrnl") ||
                             strstr(_strlwr((PCHAR)PdbFileName), "ntkrnlup") ||
                             strstr(_strlwr((PCHAR)PdbFileName), "ntkrpamp")))
                        {
#if DEBUG_ENABLED
                            wprintf(L"\nKernel Image Base: 0x%I64x (0x%x)\n",
                                    ImageBase,
                                    ImageSize);
#endif

                            g_KiExcaliburData.KernelBase = ImageBase;
                            g_KiExcaliburData.SizeOfKernelImage = ImageSize;

#if LOAD_SYMBOLS
                            SymInit();
                            SymLoadForImageBase(Handle, ImageBase, ImageSize);
                            SymDestroy();
#endif

                            goto success;
                        }
                    }
                }
            }

        break;
    }

success:
    // LocalFree(Page);
    free(Page);

    return Ret;
}