/*++
    Copyright (C) 2010 Matthieu Suiche http://www.msuiche.net 
    Copyright (C) 2010 MoonSols. <http://www.moonsols.com>
    Copyright (c) 2017 - 2018, Comae Technologies DMCC
    All rights reserved.

Module Name:

    - translate.c

Abstract:

    - 


Environment:

    - User mode

Revision History:

    - Matthieu Suiche (Jan-2010)

--*/

#include "stdafx.h"
#include "avalon.h"

ULARGE_INTEGER
MmGetx86NoPaePhysicalAddress(
    HANDLE Handle,
    ULARGE_INTEGER PageDirectoryTable,
    ULONGLONG Va
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
ULARGE_INTEGER Pa;
ULONG PDTIndex, PTTIndex;

X86_PDE Pde;
X86_PDE_LARGE PdeL;
X86_PTE Pte;

BOOL Ret;

    PDTIndex = X86_GET_PDTI(Va);

    Pa = PageDirectoryTable;
    Pa.QuadPart += PDTIndex * sizeof(X86_PDE);

    Ret = MmReadPhysicalAddress(Handle, Pa, &Pde, sizeof(X86_PDE));
    if (Ret == FALSE)
    {
        goto error;
    }

    if (Pde.Entry.PageSize == TRUE)
    {
        PdeL.Data = Pde.Data;
        Pa.QuadPart = PdeL.Entry.PageFrameNumber * X86_LARGE_PAGE_SIZE;
        Pa.QuadPart += X86_GET_OFFSET_LARGE(Va);
    }
    else
    {
        PTTIndex = X86_GET_PTTI(Va);

        Pa.QuadPart = Pde.Entry.PageFrameNumber * PAGE_SIZE;
        Pa.QuadPart += PTTIndex * sizeof(X86_PTE);

        Ret = MmReadPhysicalAddress(Handle, Pa, &Pte, sizeof(X86_PTE));
        if (Ret == FALSE)
        {
            goto error;
        }

        Pa.QuadPart = Pte.Entry.PageFrameNumber * PAGE_SIZE;
        Pa.QuadPart += X86_GET_OFFSET(Va);
    }

    return Pa;

error:
    Pa.QuadPart = 0;
    return Pa;
}

ULARGE_INTEGER
MmGetx86PaePhysicalAddress(
    HANDLE Handle,
    ULARGE_INTEGER PageDirectoryTable,
    ULONGLONG Va
)
{
ULARGE_INTEGER Pa;

ULONG PDPTIndex, PDTIndex, PTTIndex;

X86_PDPTE Pdpte;
X86_PDE_PAE Pde;
X86_PDE_PAE_LARGE PdeL;
X86_PTE_PAE Pte;

BOOL Ret;

    PDPTIndex = X86_GET_PDPTI_PAE(Va);

    Pa = PageDirectoryTable;
    Pa.QuadPart += PDPTIndex * sizeof(X86_PDPTE);

    Ret = MmReadPhysicalAddress(Handle, Pa, &Pdpte, sizeof(X86_PDPTE));
    if (Ret == FALSE)
    {
        goto error;
    }

    PDTIndex = X86_GET_PDTI_PAE(Va);

    Pa.QuadPart = Pdpte.Entry.PageFrameNumber * PAGE_SIZE;
    Pa.QuadPart += PDTIndex * sizeof(X86_PDE_PAE);

    Ret = MmReadPhysicalAddress(Handle, Pa, &Pde, sizeof(X86_PDE_PAE));
    if (Ret == FALSE)
    {
        goto error;
    }

    if (Pde.Entry.PageSize == TRUE)
    {
        PdeL.Data = Pde.Data;
        Pa.QuadPart = PdeL.Entry.PageFrameNumber * X86_LARGE_PAGE_SIZE_PAE;
        Pa.QuadPart += X86_GET_OFFSET_LARGE_PAE(Va);
    }
    else
    {
        PTTIndex = X86_GET_PTTI_PAE(Va);

        Pa.QuadPart = Pde.Entry.PageFrameNumber * PAGE_SIZE;
        Pa.QuadPart += PTTIndex * sizeof(X86_PTE_PAE);

        Ret = MmReadPhysicalAddress(Handle, Pa, &Pte, sizeof(X86_PTE_PAE));
        if (Ret == FALSE)
        {
            goto error;
        }

        Pa.QuadPart = Pte.Entry.PageFrameNumber * PAGE_SIZE;
        Pa.QuadPart += X86_GET_OFFSET_PAE(Va);
    }

    return Pa;

error:
    Pa.QuadPart = 0;
    return Pa;
}

#ifdef PRO_EDITION
ULARGE_INTEGER
MmGetx64PhysicalAddress(
    HANDLE Handle,
    ULARGE_INTEGER PageDirectoryTable,
    ULONGLONG Va
)
{
X64_PML4TE Pml4te;
X64_PDPTE Pdpte;
X64_PDE Pde;
X64_PDE_LARGE PdeL;
X64_PTE Pte;

ULARGE_INTEGER Pa;

ULONG PML4TIndex, PDPTIndex, PDTIndex, PTTIndex;

BOOL Ret;

    PML4TIndex = X64_GET_PML4TI(Va);

    Pa = PageDirectoryTable;
    Pa.QuadPart += PML4TIndex * sizeof(X64_PML4TE);

    Ret = MmReadPhysicalAddress(Handle, Pa, &Pml4te, sizeof(X64_PML4TE));
    if (Ret == FALSE)
    {
        goto error;
    }

    PDPTIndex = X64_GET_PDPTI(Va);
    Pa.QuadPart = Pml4te.Entry.PageFrameNumber * PAGE_SIZE;
    Pa.QuadPart += PDPTIndex * sizeof(X64_PDPTE);

    if (!Pml4te.Entry.Present) goto error;

    Ret = MmReadPhysicalAddress(Handle, Pa, &Pdpte, sizeof(X64_PDPTE));
    if (Ret == FALSE)
    {
        goto error;
    }

    PDTIndex = X64_GET_PDTI(Va);
    Pa.QuadPart = Pdpte.Entry.PageFrameNumber * PAGE_SIZE;
    Pa.QuadPart += PDTIndex * sizeof(X64_PDE);

    if (!Pdpte.Entry.Present) goto error;

    Ret = MmReadPhysicalAddress(Handle, Pa, &Pde, sizeof(X64_PDE));
    if (Ret == FALSE)
    {
        goto error;
    }

    if (Pde.Entry.PageSize == TRUE)
    {
        PdeL.Data = Pde.Data;

        Pa.QuadPart = PdeL.Entry.PageFrameNumber * X64_LARGE_PAGE_SIZE;
        Pa.QuadPart += X64_GET_OFFSET_LARGE(Va);

        if (!PdeL.Entry.Present) goto error;
    }
    else
    {
        PTTIndex = X64_GET_PTTI(Va);

        Pa.QuadPart = Pde.Entry.PageFrameNumber * PAGE_SIZE;
        Pa.QuadPart += PTTIndex * sizeof(X64_PTE);

        if (!Pde.Entry.Present) goto error;

        Ret = MmReadPhysicalAddress(Handle, Pa, &Pte, sizeof(X64_PTE));
        if (Ret == FALSE)
        {
            goto error;
        }

        if (!Pte.Entry.Present) goto error;

        Pa.QuadPart = Pte.Entry.PageFrameNumber * PAGE_SIZE;
        Pa.QuadPart += X64_GET_OFFSET(Va);
    }

    return Pa;

error:
    Pa.QuadPart = 0;
    return Pa;
}
#endif

ULARGE_INTEGER
MmGetPhysicalAddress(
    HANDLE Handle,
    ULONGLONG PageDirectoryTable,
    ULONGLONG Va
)
{
ULARGE_INTEGER DirBase;
ULARGE_INTEGER Pa;


    if (PageDirectoryTable == 0)
    {
        DirBase.QuadPart = g_KiExcaliburData.DirectoryTableBase;
    }
    else
    {
        DirBase.QuadPart = PageDirectoryTable;
    }

    switch (g_KiExcaliburData.MachineType)
    {
#ifdef PRO_EDITION
        case MACHINE_X64:
            Pa = MmGetx64PhysicalAddress(Handle,
                                         DirBase,
                                         Va);
        break;
#endif
        case MACHINE_X86:
            if (g_KiExcaliburData.PaeEnabled == TRUE)
            {
                Pa = MmGetx86PaePhysicalAddress(Handle,
                                                DirBase,
                                                Va);
            }
            else
            {
                Pa = MmGetx86NoPaePhysicalAddress(Handle,
                                                  DirBase,
                                                  Va);
            }
        break;
        default:
            Pa.QuadPart = 0;
        break;
    }

    return Pa;
}