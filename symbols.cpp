/*++
    Copyright (C) 2010 Matthieu Suiche http://www.msuiche.net 
    Copyright (C) 2010 MoonSols. <http://www.moonsols.com>
    All rights reserved.

Module Name:

    - symbols.c

Abstract:

    - 


Environment:

    - User mode

Revision History:

    - Matthieu Suiche (Jan-2010)

--*/

#include "stdafx.h"
#include "avalon.h"

#define SYMBOL_PATH "D:\\Symbols\\test"

#if LOAD_SYMBOLS
HANDLE g_hProcess = INVALID_HANDLE_VALUE;
BOOL g_SymInitialized = FALSE;

BOOL
SymInit(
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
ULONG SymOptions;

    g_hProcess = GetCurrentProcess();

    SymOptions = SymGetOptions();
    SymOptions = SYMOPT_UNDNAME;
    SymOptions |= SYMOPT_DEBUG;
    // SymOptions |= SYMOPT_DEFERRED_LOADS;
    SymOptions |= SYMOPT_PUBLICS_ONLY;
    SymSetOptions(SymOptions);

    g_SymInitialized = SymInitialize(g_hProcess,
                                     "srv*"SYMBOL_PATH"*http://msdl.microsoft.com/download/symbols",
                                     FALSE);

    return g_SymInitialized;
}

BOOL
SymLoadForImageBase(
    HANDLE Handle,
    ULONGLONG ImageBase,
    ULONG ImageSize
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
MODLOAD_DATA ModLoadData;

BYTE PdbFileName[MAX_PATH];
ULONG DebugDirRva;

PVOID Image;
PUCHAR FormatedName, p2;
ULONG SizeOfImage;

BOOL Ret;

    if (g_SymInitialized == FALSE) return FALSE;

    if ((ImageBase == 0) || (ImageSize == 0)) return FALSE;

    // Image = LocalAlloc(LMEM_ZEROINIT, ImageSize);
    Image = malloc(ImageSize);
    if (Image == NULL) return FALSE;

    Ret = MmReadVirtualAddress(Handle,
                               0ULL,
                               ImageBase,
                               Image,
                               ImageSize);

    if (Ret == FALSE) goto finish;

    Ret = PeGetPdbName(Handle,
                       ImageBase,
                       PdbFileName,
                       sizeof(PdbFileName),
                       &SizeOfImage,
                       &DebugDirRva);

    if (SizeOfImage > ImageSize)
    {
        Image = LocalReAlloc(Image, SizeOfImage, LMEM_ZEROINIT);
        if (Image == NULL) return FALSE;

        Ret = MmReadVirtualAddress(Handle,
                                   0ULL,
                                   ImageBase,
                                   Image,
                                   ImageSize);

        if (Ret == FALSE) goto finish;
    }
    else
    {
        SizeOfImage = ImageSize;
    }

    if (Ret == FALSE) goto finish;

    ModLoadData.ssize = sizeof(ModLoadData);
    ModLoadData.ssig = DBHHEADER_DEBUGDIRS;
    ModLoadData.data = (PUCHAR)Image + DebugDirRva;
    ModLoadData.size = sizeof(IMAGE_DEBUG_DIRECTORY);
    ModLoadData.flags = 0;

    FormatedName = strstr(PdbFileName, ".pdb");
    if (FormatedName) *FormatedName = '\0';

    for (FormatedName = PdbFileName;
         p2 = strstr(FormatedName, "\\");
         FormatedName = p2);

    if (FormatedName != PdbFileName) FormatedName += sizeof(UCHAR);

    if (SymLoadModuleEx(g_hProcess,
                        NULL,
                        FormatedName,
                        NULL,
                        (DWORD64)Image,
                        SizeOfImage,
                        &ModLoadData,
                        0))
    {
        IMAGEHLP_MODULE64 ModuleInfo = {0};

        ModuleInfo.SizeOfStruct = sizeof(ModuleInfo);
        SymGetModuleInfo64(g_hProcess, (DWORD64)Image, &ModuleInfo);
        wprintf(L"-> %S is loaded.\n", ModuleInfo.LoadedPdbName);

        Ret = TRUE;
    }
    else
    {
        Ret = FALSE;
        goto finish;
    }

finish:
    // LocalFree(Image);
    if (Image) free(Image);
    return Ret;
}

BOOL
SymDestroy(
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
    g_SymInitialized = FALSE;

    return SymCleanup(g_hProcess);
}

#endif