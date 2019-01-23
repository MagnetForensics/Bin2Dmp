/*++
    Copyright (c) Comae Technologies DMCC. All rights reserved.

Module Name:

    - validate.c

Abstract:

    - 


Environment:

    - User mode

Revision History:

    - Matthieu Suiche (Jan-2010)

--*/

#include "stdafx.h"
#include "avalon.h"

BOOL
MmValidatex86PaePageDirectoryPointerTable(
    HANDLE Handle,
    ULARGE_INTEGER Pa
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
BOOL bValidTable;

PX86_PDPTE PdpteEntry;

ULONG EntryIndex;

PVOID Page;

    //
    // ? Maybe check if Page value is, page aligned.
    //

    bValidTable = TRUE;

    // Page = LocalAlloc(LMEM_ZEROINIT, PAGE_SIZE);
    Page = malloc(PAGE_SIZE);
    if (Page == NULL) return FALSE;

    if (MmReadPhysicalAddress(Handle,
                              Pa,
                              Page,
                              PAGE_SIZE) == FALSE)
    {
        bValidTable = FALSE;
        goto finish;
    }

    PdpteEntry = (PX86_PDPTE)Page;

    if (PdpteEntry[0].Data.QuadPart == 0)
    {
#if DEBUG_ENABLED
        wprintf(L"Err: First entry 0\n");
#endif
        bValidTable = FALSE;
        goto finish;
    }

    //
    // We assume PAE is always enabled.
    // Moreover, even if PAE only uses 4 entries we assume the rest of the page
    // must be null according the the osloader Physical Page algorithm.
    //

    for (EntryIndex = 0;
         EntryIndex < (PAGE_SIZE / sizeof(*PdpteEntry));
         EntryIndex += 1)
    {
        if ((PdpteEntry[EntryIndex].Entry.Reserved00 != 0) ||
            (PdpteEntry[EntryIndex].Entry.Reserved01 != 0) ||
            (PdpteEntry[EntryIndex].Entry.Reserved02 != 0))
        {
#if DEBUG_ENABLED
            wprintf(L"Err: Reserved bits\n");
#endif
            bValidTable = FALSE;
            break;
        }

        if (EntryIndex < (MAX_PDPT_ENTRY - 1))
        {
            //
            // We assume the next entry has increment PFN value.
            //
            if (PdpteEntry[EntryIndex].Entry.PageFrameNumber !=
                (PdpteEntry[EntryIndex + 1].Entry.PageFrameNumber - 1))
            {
#if DEBUG_ENABLED
                wprintf(L"Err: n = n +1\n");
#endif
                bValidTable = FALSE;
                break;
            }
        }
    }

#if 0
    if (bValidTable)
    {
        BOOL OldPaeEnabled;
        ULONG OldMachineType;

        ULARGE_INTEGER UPa, KPa;
        OldPaeEnabled = g_KiExcaliburData.PaeEnabled;
        OldMachineType = g_KiExcaliburData.MachineType;

        g_KiExcaliburData.PaeEnabled = TRUE;
        g_KiExcaliburData.MachineType = MACHINE_X86;

        KPa = MmGetPhysicalAddress(Handle, Pa.QuadPart, X86_KUSER_SHARED_DATA_VA);
        UPa = MmGetPhysicalAddress(Handle, Pa.QuadPart, X86_USER_SHARED_DATA_VA);

        if (!KPa.QuadPart || !UPa.QuadPart || (KPa.QuadPart != UPa.QuadPart))
        {
            bValidTable = FALSE;
        }

        g_KiExcaliburData.PaeEnabled = OldPaeEnabled;
        g_KiExcaliburData.MachineType = OldMachineType;
    }
#endif

finish:
    // LocalFree(Page);
    if (Page) free(Page);

    return bValidTable;
}

BOOL
MmValidatex86NoPaePageDirectoryTable(
    HANDLE Handle,
    ULARGE_INTEGER Pa
)
{
BOOL bValidTable;

PX86_PDE PdeEntry;
PX86_PDE_LARGE PdeLargeEntry;

ULONG EntryIndex;

PVOID Page;

    //
    // ? Maybe check if Page value is, page aligned.
    //
    bValidTable = TRUE;

    // Page = LocalAlloc(LMEM_ZEROINIT, PAGE_SIZE);
    Page = malloc(PAGE_SIZE);
    if (Page == NULL) return FALSE;

    if (MmReadPhysicalAddress(Handle,
                              Pa,
                              Page,
                              PAGE_SIZE) == FALSE)
    {
        bValidTable = FALSE;
        goto finish;
    }

    PdeEntry = (PX86_PDE)Page;
    PdeLargeEntry = (PX86_PDE_LARGE)Page;

    //
    // First entry must be different from 0.
    //
    if (PdeEntry[0].Data == 0)
    {
        bValidTable = FALSE;
        goto finish;
    }

    for (EntryIndex = 0;
         EntryIndex < (PAGE_SIZE / sizeof(*PdeEntry));
         EntryIndex += 1)
    {
        //
        // Invalid if 
        // #2: PS = 1  && Reserved01 != 0
        // #4: (P = 1 || RW = 1 || A = 1) && PFN = 0 <- first page is only mapped by BIOS not O.S.
        // #5: PFN > MaxPage
        // Condition below are not used.
        // #1: PS = 0 && Reserved00 != 0  <- doesnt work
        // Condition below restored because it had an issue with strings on a win7x64 dump
        // #3: P = 0 && CD = 1 <- not sure.
        //

#if 0
        if (((PdeEntry[EntryIndex].Entry.PageSize == FALSE) &&
             (PdeEntry[EntryIndex].Entry.Reserved00 != FALSE)) ||
            ((PdeLargeEntry[EntryIndex].Entry.PageSize == TRUE) &&
             (PdeLargeEntry[EntryIndex].Entry.Reserved01 != FALSE))||
            ((PdeEntry[EntryIndex].Entry.Present == FALSE) &&
             (PdeEntry[EntryIndex].Entry.CacheDisabled == TRUE)))
        {
#endif

        if ((((PdeEntry[EntryIndex].Entry.Present == TRUE) ||
             (PdeEntry[EntryIndex].Entry.ReadWrite == TRUE) ||
             (PdeEntry[EntryIndex].Entry.Accessed == TRUE)) &&
            (PdeEntry[EntryIndex].Entry.PageFrameNumber == 0)) || 
            ((PdeLargeEntry[EntryIndex].Entry.PageSize == TRUE) &&
             (PdeLargeEntry[EntryIndex].Entry.Reserved01 != FALSE)) ||
             (PdeLargeEntry[EntryIndex].Entry.PageFrameNumber >= MmMaximumPhysicalPage) ||
             ((PdeEntry[EntryIndex].Entry.Present == FALSE) &&
             (PdeEntry[EntryIndex].Entry.CacheDisabled == TRUE)))
        {
            bValidTable = FALSE;
            break;
        }
    }

#if FALSE
    if (bValidTable)
    {
        BOOL OldPaeEnabled;
        ULONG OldMachineType;

        ULARGE_INTEGER UPa, KPa;
        OldPaeEnabled = g_KiExcaliburData.PaeEnabled;
        OldMachineType = g_KiExcaliburData.MachineType;

        g_KiExcaliburData.PaeEnabled = FALSE;
        g_KiExcaliburData.MachineType = MACHINE_X86;

        KPa = MmGetPhysicalAddress(Handle, Pa.QuadPart, X86_KUSER_SHARED_DATA_VA);
        UPa = MmGetPhysicalAddress(Handle, Pa.QuadPart, X86_USER_SHARED_DATA_VA);

        if (!KPa.QuadPart || !UPa.QuadPart || (KPa.QuadPart != UPa.QuadPart))
        {
            bValidTable = FALSE;
        }

        g_KiExcaliburData.PaeEnabled = OldPaeEnabled;
        g_KiExcaliburData.MachineType = OldMachineType;
    }
#endif

finish:
    // LocalFree(Page);
    if (Page) free(Page);
    return bValidTable;
}

#ifdef PRO_EDITION
BOOL
MmValidatex64PageMapLevel4Table(
    HANDLE Handle,
    ULARGE_INTEGER Pa
)
{
BOOL bValidTable;

PX64_PML4TE Pml4Entry;

ULONG EntryIndex;

PVOID Page;

    bValidTable = TRUE;

    // Page = LocalAlloc(LMEM_ZEROINIT, PAGE_SIZE);
    Page = malloc(PAGE_SIZE);
    if (Page == NULL) return FALSE;

    if (MmReadPhysicalAddress(Handle,
                              Pa,
                              Page,
                              PAGE_SIZE) == FALSE)
    {
        bValidTable = FALSE;
        goto finish;
    }

    Pml4Entry = (PX64_PML4TE)Page;

    if (Pml4Entry[0].Data.QuadPart == 0)
    {
        bValidTable = FALSE;
        goto finish;
    }

    for (EntryIndex = 0;
         EntryIndex < (PAGE_SIZE / sizeof(*Pml4Entry));
         EntryIndex += 1)
    {
        if (/*(Pml4Entry[EntryIndex].Entry.Reserved00 != 0) ||*/
            (Pml4Entry[EntryIndex].Entry.Reserved01 != 0) ||
            (Pml4Entry[EntryIndex].Entry.PageFrameNumber >= MmMaximumPhysicalPage))
        {
            bValidTable = FALSE;
            break;
        }

        if ((EntryIndex == 0) &&
            (Pml4Entry[EntryIndex].Entry.Present == FALSE))
        {
            bValidTable = FALSE;
            break;
        }
    }

    if (bValidTable)
    {
#if DEBUG_ENABLED
        for (EntryIndex = 0;
             EntryIndex < 8;
             EntryIndex += 1)
        {
            wprintf(L"-> #%4d 0x%08X%08X bValidTable = %d ", EntryIndex,
                                        Pml4Entry[EntryIndex].Data.HighPart,
                                        Pml4Entry[EntryIndex].Data.LowPart,
                                        bValidTable);
            wprintf(L"Res %x\n", Pml4Entry[EntryIndex].Entry.Reserved01);

            wprintf(L"Present: %x\n"
                    L"ReadWrite: %x\n"
                    L"UserSupervisor: %x\n"
                    L"WriteThrough: %x\n"
                    L"CacheDisabled: %x\n"
                    L"Accessed: %x\n"
                    L"Reserved00: %x\n"
                    L"Available00: %x\n"
                    L"PFN: %x\n"
                    L"Reserved01: %x\n"
                    L"Available01: %x\n"
                    L"ExecuteDisabled: %x\n",
                    Pml4Entry[EntryIndex].Entry.Present,
                    Pml4Entry[EntryIndex].Entry.ReadWrite,
                    Pml4Entry[EntryIndex].Entry.UserSupervisor,
                    Pml4Entry[EntryIndex].Entry.WriteThrough,
                    Pml4Entry[EntryIndex].Entry.CacheDisabled,
                    Pml4Entry[EntryIndex].Entry.Accessed,
                    Pml4Entry[EntryIndex].Entry.Reserved00,
                    Pml4Entry[EntryIndex].Entry.Available00,
                    Pml4Entry[EntryIndex].Entry.PageFrameNumber,
                    Pml4Entry[EntryIndex].Entry.Reserved01,
                    Pml4Entry[EntryIndex].Entry.Available01,
                    Pml4Entry[EntryIndex].Entry.ExecuteDisabled);
        }
#endif

#if FALSE
        ULARGE_INTEGER UPa, KPa;

        BOOL OldPaeEnabled;
        ULONG OldMachineType;

        OldPaeEnabled = g_KiExcaliburData.PaeEnabled;
        OldMachineType = g_KiExcaliburData.MachineType;

        g_KiExcaliburData.PaeEnabled = TRUE;
        g_KiExcaliburData.MachineType = MACHINE_X64;

        KPa = MmGetPhysicalAddress(Handle, Pa.QuadPart, X64_KUSER_SHARED_DATA_VA);
        UPa = MmGetPhysicalAddress(Handle, Pa.QuadPart, X64_USER_SHARED_DATA_VA);

        if (!KPa.QuadPart || !UPa.QuadPart || (KPa.QuadPart != UPa.QuadPart))
        {
            bValidTable = FALSE;
        }

        g_KiExcaliburData.PaeEnabled = OldPaeEnabled;
        g_KiExcaliburData.MachineType = OldMachineType;
#endif
    }

finish:
    if (Page) free(Page);
    return bValidTable;
}
#endif

//
// MmValidatex86KPCR and MmValidatex64KPCR only works for NT 6.0 and below. 
//

BOOL
MmValidatex86KPCR(
    HANDLE Handle,
    PVOID Page
)
{
BOOL bValid;
PUCHAR p;

    bValid = FALSE;

    p = (PUCHAR)Page;

    bValid = MmValidationx86KProcState(
                Handle,
                &p[X86_KPRCB_OFFSET + X86_KPROCESSOR_STATE_OFFSET]);

#if DEBUG_ENABLED
    wprintf(L"MmValidatex86KPCR() = %d\n", bValid);
#endif

    return bValid;
}

BOOL
MmValidationx86KProcState(
    HANDLE Handle,
    PVOID Page
)
{
PX86_CONTEXT Context;
PX86_KSPECIAL_REGISTERS SpecialRegs;
PUCHAR p;

BOOL bValid;

    bValid = FALSE;

    p = (PUCHAR)Page;
    Context = (PX86_CONTEXT)&p[X86_CONTEXT_OFFSET];

#if DEBUG_ENABLED
    wprintf(L"===\n");
    wprintf(L"Context->SegCs: %4x (expected %x)\n",
        Context->SegCs, KGDT_R0_CODE);
    wprintf(L"Context->SegDs: %4x (expected %x or %x)\n",
        Context->SegDs, (KGDT_R3_DATA | RPL_MASK), KGDT_R3_DATA);
    wprintf(L"Context->SegEs: %4x (expected %x or %x)\n",
        Context->SegEs, (KGDT_R3_DATA | RPL_MASK), KGDT_R3_DATA);
    wprintf(L"Context->SegFs: %4x (expected %x)\n",
        Context->SegFs, KGDT_R0_PCR);
    wprintf(L"Context->SegGs: %4x (expected %x)\n",
        Context->SegGs, 0);
    wprintf(L"Context->SegSs: %4x (expected %x)\n",
        Context->SegSs, KGDT_R0_DATA);
    wprintf(L"===\n");
#endif

    if ((Context->SegCs == KGDT_R0_CODE) &&
        ((Context->SegDs == (KGDT_R3_DATA | RPL_MASK)) || (Context->SegDs == KGDT_R3_DATA)) &&
        ((Context->SegEs == (KGDT_R3_DATA | RPL_MASK)) || (Context->SegEs == KGDT_R3_DATA)) &&
        (Context->SegFs == KGDT_R0_PCR) &&
        (Context->SegGs == 0) &&
        ((Context->SegSs == KGDT_R0_DATA)))
    {
#if DEBUG_ENABLED
    wprintf(L"Context->SegCs == KGDT_R0_CODE) (..) => bValid = TRUE;\n");
#endif
        bValid = TRUE;
    }

    if ((Context->SegCs > 0xff) ||
        (Context->SegDs > 0xff) ||
        (Context->SegEs > 0xff) ||
        (Context->SegFs > 0xff) ||
        (Context->SegGs > 0xff) ||
        (Context->SegSs  > 0xff))
    {
#if DEBUG_ENABLED
    wprintf(L"Context->SegXX > FF; Finish;\n");
#endif
        bValid = FALSE;
        goto Finish;
    }

    //
    // Additional mesure.
    //
    if (bValid == FALSE)
    {
        ULARGE_INTEGER Pa;

        SpecialRegs = (PX86_KSPECIAL_REGISTERS)&p[X86_CONTEXT_OFFSET + X86_KSPECIAL_REGISTERS_OFFSET];

        if (SpecialRegs->Cr3 == 0) goto Finish;

        Pa.QuadPart = SpecialRegs->Cr3;

        bValid = MmValidatex86NoPaePageDirectoryTable(Handle, Pa);
#if DEBUG_ENABLED
            wprintf(L"MmValidationx86KProcState::MmValidatex86NoPaePageDirectoryTable() = %d\n", bValid);
#endif
        if (bValid == TRUE) goto Finish;
        /*
        if ((bValid == TRUE) && (SpecialRegs->Cr3 == 00039000ULL))
        {
            // if 00039000ULL
            goto Finish;
        }
        else
        {
            bValid = FALSE;
            goto Finish;
        }
        */

        bValid = MmValidatex86PaePageDirectoryPointerTable(Handle, Pa);
        /*
        if ((bValid == TRUE) && (SpecialRegs->Cr3 != 00319000ULL))
        {
            bValid = FALSE;
        }
        */
    }

Finish:
    return bValid;
}

#ifdef PRO_EDITION
BOOL
MmValidatex64KPCR(
    PVOID Page
)
{
BOOL bValid;

PUCHAR p;

    bValid = FALSE;

    p = (PUCHAR)Page;
    bValid = MmValidationx64KProcState(&p[X64_KPRCB_OFFSET + X64_KPROCESSOR_STATE_OFFSET]);

    return bValid;
}
#endif

#ifdef PRO_EDITION
BOOL
MmValidationx64KProcState(
    PVOID Page
)
{
PX64_CONTEXT Context;
BOOL bValid;

PUCHAR p;

    bValid = FALSE;

    p = (PUCHAR)Page;
    Context = (PX64_CONTEXT)&p[X64_CONTEXT_OFFSET];

#if DEBUG_ENABLED
    wprintf(L"===\n");
    wprintf(L"Context->SegCs: %4x (expected %x)\n",
        Context->SegCs, KGDT64_R0_CODE);
    wprintf(L"Context->SegDs: %4x (expected %x or %x)\n",
        Context->SegDs, (KGDT64_R3_DATA | RPL_MASK), KGDT64_R3_DATA);
    wprintf(L"Context->SegEs: %4x (expected %x or %x)\n",
        Context->SegEs, (KGDT64_R3_DATA | RPL_MASK), KGDT64_R3_DATA);
    wprintf(L"Context->SegFs: %4x (expected %x or %x)\n",
        Context->SegFs, (KGDT64_R3_CMTEB | RPL_MASK), KGDT64_R3_CMTEB);
    wprintf(L"Context->SegGs: %4x (expected %x or %x or 0)\n",
        Context->SegGs, (KGDT64_R3_DATA | RPL_MASK), KGDT64_R3_DATA);
    wprintf(L"Context->SegSs: %4x (expected %x or 0)\n",
        Context->SegSs, KGDT64_R0_DATA);
    wprintf(L"===\n");
#endif

    if ((Context->SegCs == KGDT64_R0_CODE) &&
        ((Context->SegDs == (KGDT64_R3_DATA | RPL_MASK)) || (Context->SegDs == KGDT64_R3_DATA)) &&
        ((Context->SegEs == (KGDT64_R3_DATA | RPL_MASK)) || (Context->SegEs == KGDT64_R3_DATA)) &&
        ((Context->SegFs == (KGDT64_R3_CMTEB | RPL_MASK)) || (Context->SegFs == KGDT64_R3_CMTEB)) &&
        ((Context->SegGs == (KGDT64_R3_DATA | RPL_MASK)) || (Context->SegGs == KGDT64_R3_DATA)
         || (Context->SegGs == 0)) &&
        ((Context->SegSs == KGDT64_R0_DATA) || (Context->SegSs == 0))
        )
    {
        bValid = TRUE;
    }

    return bValid;
}
#endif