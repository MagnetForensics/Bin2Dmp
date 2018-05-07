/*++
    Copyright (C) 2010 Matthieu Suiche http://www.msuiche.net 
    Copyright (C) 2010 MoonSols. <http://www.moonsols.com>
    Copyright (c) 2017 - 2018, Comae Technologies DMCC
    All rights reserved.

Module Name:

    - pe.c

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
PeGetPdbName(
    HANDLE Handle,
    ULONGLONG Va,
    PUCHAR PdbName,
    ULONG SizeOfPdbName,
    PULONG SizeOfImage,
    PULONG ImageDebugDir
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
PIMAGE_DOS_HEADER DosHeader;
PIMAGE_NT_HEADERS32 NtHeader32;

PIMAGE_DEBUG_DIRECTORY DebugDir;
PCV_INFO_PDB70 CodeView;

ULONG DebugDirRva, DebugDirSize;
ULONGLONG VaToRead;
SIZE_T SizeToRead;

PUCHAR Buffer;

ULARGE_INTEGER Pa;

BOOL Ret;

    Ret = FALSE;

    // Buffer = LocalAlloc(LMEM_ZEROINIT, PAGE_SIZE);
    Buffer = (PUCHAR)malloc(PAGE_SIZE);
    if (Buffer == NULL) return FALSE;

    DosHeader = (PIMAGE_DOS_HEADER)Buffer;

    Ret = MmReadVirtualAddress(Handle,
                               0ULL,
                               Va,
                               Buffer,
                               PAGE_SIZE);

    if (Ret == FALSE) goto finish;

    NtHeader32 = (PIMAGE_NT_HEADERS32)&Buffer[DosHeader->e_lfanew];

    if (NtHeader32->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC)
    {
        PIMAGE_OPTIONAL_HEADER32 OptionalHeader32;

        OptionalHeader32 = (PIMAGE_OPTIONAL_HEADER32)&NtHeader32->OptionalHeader;
        *SizeOfImage = OptionalHeader32->SizeOfImage;

        DebugDirRva = OptionalHeader32->DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG].VirtualAddress;
        DebugDirSize = OptionalHeader32->DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG].Size;

        VaToRead = Va + DebugDirRva;

        Ret = MmReadVirtualAddress(Handle,
                                   0ULL,
                                   VaToRead,
                                   Buffer,
                                   PAGE_SIZE);

        if (Ret == FALSE) goto finish;
    }
    else if (NtHeader32->OptionalHeader.Magic  == IMAGE_NT_OPTIONAL_HDR64_MAGIC)
    {
        PIMAGE_NT_HEADERS64 NtHeader64;
        PIMAGE_OPTIONAL_HEADER64 OptionalHeader64;

        NtHeader64 = (PIMAGE_NT_HEADERS64)NtHeader32;

        OptionalHeader64 = (PIMAGE_OPTIONAL_HEADER64)&NtHeader32->OptionalHeader;
        *SizeOfImage = OptionalHeader64->SizeOfImage;

        DebugDirRva = OptionalHeader64->DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG].VirtualAddress;
        DebugDirSize = OptionalHeader64->DataDirectory[IMAGE_DIRECTORY_ENTRY_DEBUG].Size;

        VaToRead = Va + DebugDirRva;

        Ret = MmReadVirtualAddress(Handle,
                                   0ULL,
                                   VaToRead,
                                   Buffer,
                                   PAGE_SIZE);

        if (Ret == FALSE) goto finish;
    }
    else
    {
        Ret = FALSE;
        goto finish;
    }

    if ((DebugDirRva == 0) || (DebugDirSize == 0))
    {
        Ret = FALSE;
        goto finish;
    }

    DebugDir = (PIMAGE_DEBUG_DIRECTORY)Buffer;
    *ImageDebugDir = DebugDirRva;

    Pa = MmGetPhysicalAddress(Handle, 0ULL, Va);
    if (Pa.QuadPart == 0)
    {
        Ret = FALSE;
        goto finish;
    }
    if ((DebugDir->AddressOfRawData != 0) && (DebugDir->Type == IMAGE_DEBUG_TYPE_CODEVIEW))
    {
        VaToRead = Va + DebugDir->AddressOfRawData;
        SizeToRead = DebugDir->SizeOfData;
        if (SizeToRead > PAGE_SIZE)
        {
            SizeToRead = PAGE_SIZE;
        }

        Ret = MmReadVirtualAddress(Handle, 0ULL, VaToRead, Buffer, DebugDir->SizeOfData);
        if (Ret == FALSE) goto finish;

        CodeView = (PCV_INFO_PDB70)Buffer;

        Ret = FALSE;

        if (CodeView->Signature == CV_SIGNATURE_RSDS)
        {
#if DEBUG_ENABLED
            wprintf(L"pdbname: %S\n", CodeView->PdbFileName);
#endif
            if (strlen((PCHAR)CodeView->PdbFileName))
            {
                strcpy_s((PCHAR)PdbName, SizeOfPdbName, (PCHAR)CodeView->PdbFileName);
                Ret = TRUE;
            }
        }
    }

finish:
    // LocalFree(Buffer);
    if (Buffer) free(Buffer);

    return Ret;
}

ULONG64
PeGetProcAddress(
    HANDLE Handle,
    ULONG64 ModuleBase,
    PCHAR Name
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
PIMAGE_NT_HEADERS32 NtHeader32;
PIMAGE_DOS_HEADER DosHeader;

ULONG DirRva, DirSize;

PUCHAR Buffer;

BOOL Ret;

ULONG64 Va;

    Va = 0ULL;

    // Buffer = LocalAlloc(LMEM_ZEROINIT, PAGE_SIZE);
    Buffer = (PUCHAR)malloc(PAGE_SIZE);
    if (Buffer == NULL) return FALSE;

    DosHeader = (PIMAGE_DOS_HEADER)Buffer;

    Ret = MmReadVirtualAddress(Handle,
                               0ULL,
                               ModuleBase,
                               Buffer,
                               PAGE_SIZE);

    if (Ret == FALSE) goto finish;

    //
    // BUGBUG:
    // if (DosHeader->e_lfanew < 0x40)
    //
    NtHeader32 = (PIMAGE_NT_HEADERS32)&Buffer[DosHeader->e_lfanew];

    if (NtHeader32->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC)
    {
        PIMAGE_OPTIONAL_HEADER32 OptionalHeader32;
        PIMAGE_EXPORT_DIRECTORY ExportDir;
        ULONG SizeOfImage;
        ULONG NumberOfNames;

        PULONG AddressOfNames;
        PUSHORT AddressOfNameOrdinals;
        PULONG AddressOfFunctions;

        PUCHAR Image;

        ULONG i;

        OptionalHeader32 = (PIMAGE_OPTIONAL_HEADER32)&NtHeader32->OptionalHeader;

        SizeOfImage = OptionalHeader32->SizeOfImage;
        Image = (PUCHAR)malloc(SizeOfImage);
        if (Image == NULL) goto finish;

        Ret = MmReadVirtualAddress(Handle,
                           0ULL,
                           ModuleBase,
                           Image,
                           SizeOfImage);

        if (Ret == FALSE)
        {
            free(Image);
            goto finish;
        }

        DirRva = OptionalHeader32->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
        DirSize = OptionalHeader32->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;

        ExportDir = (PIMAGE_EXPORT_DIRECTORY)(Image + DirRva);

        NumberOfNames = ExportDir->NumberOfNames;

#if DEBUG_ENABLED
        wprintf(L"NumberOfNames: %x\n", ExportDir->NumberOfNames);
        wprintf(L"NumberOfFunctions: %x\n", ExportDir->NumberOfFunctions);
        wprintf(L"AddressOfFunctions: %x\n", ExportDir->AddressOfFunctions);
        wprintf(L"AddressOfNames: %x\n", ExportDir->AddressOfNames);
        wprintf(L"AddressOfNameOrdinals: %x\n", ExportDir->AddressOfNameOrdinals);
#endif

        AddressOfNames = (PULONG)(Image + (ULONG)ExportDir->AddressOfNames);
        AddressOfNameOrdinals = (PUSHORT)(Image + (ULONG)ExportDir->AddressOfNameOrdinals);
        AddressOfFunctions = (PULONG)(Image + (ULONG)ExportDir->AddressOfFunctions);


        for (i = 0; i < NumberOfNames; i += 1)
        {
            if (strcmp((PCHAR)(Image + AddressOfNames[i]), (PCHAR)Name) == 0)
            {
                //
                // We found it.
                //
                Va = AddressOfFunctions[AddressOfNameOrdinals[i]];
                Va += ModuleBase;

                break;
            }
        }

        free (Image);
    }
#ifdef PRO_EDITION
    else if (NtHeader32->OptionalHeader.Magic  == IMAGE_NT_OPTIONAL_HDR64_MAGIC)
    {
        PIMAGE_NT_HEADERS64 NtHeader64;
        PIMAGE_OPTIONAL_HEADER64 OptionalHeader64;
        PIMAGE_EXPORT_DIRECTORY ExportDir;

        ULONG SizeOfImage;
        ULONG NumberOfNames;

        PULONG AddressOfNames;
        PUSHORT AddressOfNameOrdinals;
        PULONG AddressOfFunctions;

        PUCHAR Image;

        ULONG i;

        NtHeader64 = (PIMAGE_NT_HEADERS64)NtHeader32;

        OptionalHeader64 = (PIMAGE_OPTIONAL_HEADER64)&NtHeader32->OptionalHeader;
        SizeOfImage = OptionalHeader64->SizeOfImage;

        Image = (PUCHAR)malloc(SizeOfImage);
        if (Image == NULL) goto finish;

        Ret = MmReadVirtualAddress(Handle,
                           0ULL,
                           ModuleBase,
                           Image,
                           SizeOfImage);

        if (Ret == FALSE)
        {
            free(Image);
            goto finish;
        }

        DirRva = OptionalHeader64->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
        DirSize = OptionalHeader64->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;

        ExportDir = (PIMAGE_EXPORT_DIRECTORY)(Image + DirRva);

        NumberOfNames = ExportDir->NumberOfNames;

#if DEBUG_ENABLED
        wprintf(L"NumberOfNames: %x\n", ExportDir->NumberOfNames);
        wprintf(L"NumberOfFunctions: %x\n", ExportDir->NumberOfFunctions);
        wprintf(L"AddressOfFunctions: %x\n", ExportDir->AddressOfFunctions);
        wprintf(L"AddressOfNames: %x\n", ExportDir->AddressOfNames);
        wprintf(L"AddressOfNameOrdinals: %x\n", ExportDir->AddressOfNameOrdinals);
#endif

        AddressOfNames = (PULONG)(Image + (ULONG)ExportDir->AddressOfNames);
        AddressOfNameOrdinals = (PUSHORT)(Image + (ULONG)ExportDir->AddressOfNameOrdinals);
        AddressOfFunctions = (PULONG)(Image + (ULONG)ExportDir->AddressOfFunctions);

        for (i = 0; i < NumberOfNames; i += 1)
        {
            if (strcmp((PCHAR)(Image + AddressOfNames[i]), (PCHAR)Name) == 0)
            {
                //
                // We found it.
                //
                Va = AddressOfFunctions[AddressOfNameOrdinals[i]];
                Va += ModuleBase;

                break;
            }
        }

        free (Image);
    }
#endif

finish:
    free(Buffer);

    return Va;
}

BOOL
PeGetSection(
    HANDLE Handle,
    ULONG64 ModuleBase,
    PUCHAR SectionName,
    PULONG OutSectionVa,
    PULONG OutSectionOffset,
    PULONG OutSectionSize
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
    PIMAGE_NT_HEADERS32 NtHeader32;
    PIMAGE_DOS_HEADER DosHeader;

    PUCHAR Buffer;

    BOOL Ret = FALSE;
    BOOL ReturnRet = FALSE;

    Buffer = (PUCHAR)malloc(PAGE_SIZE);
    if (Buffer == NULL) return FALSE;

    DosHeader = (PIMAGE_DOS_HEADER)Buffer;

    Ret = MmReadVirtualAddress(Handle,
                               0ULL,
                               ModuleBase,
                               Buffer,
                               PAGE_SIZE);

    if (Ret == FALSE) goto finish;

    //
    // BUGBUG:
    // if (DosHeader->e_lfanew < 0x40)
    //
    NtHeader32 = (PIMAGE_NT_HEADERS32)&Buffer[DosHeader->e_lfanew];

    if (NtHeader32->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC)
    {
        PIMAGE_OPTIONAL_HEADER32 OptionalHeader32;
        PIMAGE_SECTION_HEADER SectionHeader = NULL;
        ULONG SizeOfImage;
        ULONG NumberOfSections;

        ULONG i;

        OptionalHeader32 = (PIMAGE_OPTIONAL_HEADER32)&NtHeader32->OptionalHeader;

        SizeOfImage = OptionalHeader32->SizeOfImage;
        NumberOfSections = NtHeader32->FileHeader.NumberOfSections;

        SectionHeader = (PIMAGE_SECTION_HEADER)((PUCHAR)OptionalHeader32 + NtHeader32->FileHeader.SizeOfOptionalHeader);

        for (i = 0; i < NumberOfSections; i += 1)
        {
            if (strcmp((PCHAR)SectionHeader[i].Name, (PCHAR)SectionName) == 0)
            {
                *OutSectionVa = SectionHeader[i].VirtualAddress;
                *OutSectionOffset = SectionHeader[i].PointerToRawData;
                *OutSectionSize = SectionHeader[i].SizeOfRawData;
                break;
            }
        }

    }
    else if (NtHeader32->OptionalHeader.Magic  == IMAGE_NT_OPTIONAL_HDR64_MAGIC)
    {
        PIMAGE_NT_HEADERS64 NtHeader64 = NULL;
        PIMAGE_OPTIONAL_HEADER64 OptionalHeader64 = NULL;
        PIMAGE_SECTION_HEADER SectionHeader = NULL;

        ULONG SizeOfImage;
        ULONG NumberOfSections;

        ULONG i;

        NtHeader64 = (PIMAGE_NT_HEADERS64)NtHeader32;

        OptionalHeader64 = (PIMAGE_OPTIONAL_HEADER64)&NtHeader64->OptionalHeader;
        SizeOfImage = OptionalHeader64->SizeOfImage;
        NumberOfSections = NtHeader64->FileHeader.NumberOfSections;

        SectionHeader = (PIMAGE_SECTION_HEADER)((PUCHAR)OptionalHeader64 + NtHeader64->FileHeader.SizeOfOptionalHeader);

        for (i = 0; i < NumberOfSections; i += 1)
        {
            if (strcmp((PCHAR)SectionHeader[i].Name, (PCHAR)SectionName) == 0)
            {
                *OutSectionVa = SectionHeader[i].VirtualAddress;
                *OutSectionOffset = SectionHeader[i].PointerToRawData;
                *OutSectionSize = SectionHeader[i].SizeOfRawData;

                break;
            }
        }
    }

    ReturnRet = TRUE;

finish:
    free(Buffer);

    return ReturnRet;
}

VOID
PeDumpHexa(
    PVOID Buffer,
    ULONG BytesCount
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
PUCHAR p;
ULONG i;

    p = (PUCHAR)Buffer;

    for (i = 0; i < BytesCount; i += 1)
    {
        wprintf(L"%02X ", p[i]);
        if (((i + 1) % 0x10) == 0) wprintf(L"\n");
    }

}