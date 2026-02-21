/*++
    Copyright (c) Comae Technologies DMCC. All rights reserved.

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
#include "HvlibSymbols.h"

#define SYMBOL_PATH "D:\\Symbols"

HANDLE g_hProcess = INVALID_HANDLE_VALUE;
BOOL g_SymInitialized = FALSE;

BOOL SymInit()
{
    ULONG SymOptions;
    CHAR szSymbolPath[MAX_PATH * 4] = { 0 };
    CHAR szEnvPath[MAX_PATH * 2] = { 0 };
    DWORD dwResult;

    g_hProcess = GetCurrentProcess();

    // Проверяем _NT_SYMBOL_PATH
    dwResult = GetEnvironmentVariableA("_NT_SYMBOL_PATH",
        szEnvPath,
        sizeof(szEnvPath));

    if (dwResult > 0 && dwResult < sizeof(szEnvPath))
    {
        // Используем путь из переменной окружения
        StringCchCopyA(szSymbolPath, sizeof(szSymbolPath), szEnvPath);
    }
    else
    {
        // Используем путь по умолчанию
        StringCchCopyA(szSymbolPath,
            sizeof(szSymbolPath),
            "srv*" SYMBOL_PATH "*https://msdl.microsoft.com/download/symbols");
    }

    SymOptions = SymGetOptions();
    SymOptions = SYMOPT_UNDNAME;
    SymOptions |= SYMOPT_DEBUG;
    // SymOptions |= SYMOPT_DEFERRED_LOADS;
    SymOptions |= SYMOPT_PUBLICS_ONLY;
    SymSetOptions(SymOptions);

    g_SymInitialized = SymInitialize(g_hProcess, szSymbolPath, FALSE);

    return g_SymInitialized;
}

ULONG64 GetSymbolOffset(HANDLE hProcess, DWORD64 baseAddress, const char* symbolName)
{
    SYMBOL_INFO* symbol;
    DWORD64 displacement = 0;
    ULONG64 Offset = 0;

    // Allocate memory for the symbol
    symbol = (SYMBOL_INFO*)malloc(sizeof(SYMBOL_INFO) + MAX_SYM_NAME);
    if (!symbol) {
        log_u(log_v2, L"hvlib:memory allocation failed\n");
        return 0;
    }

    symbol->SizeOfStruct = sizeof(SYMBOL_INFO);
    symbol->MaxNameLen = MAX_SYM_NAME;

    // Get the symbol details
    if (SymFromName(hProcess, symbolName, symbol))
    {
        Offset = symbol->Address - baseAddress;
        log_u(log_v2, L"hvlib:Symbol: %s | Address: 0x%llx | Offset: 0x%llx\n",
            symbol->Name,
            symbol->Address,
            symbol->Address - baseAddress);
    }
    else
    {
        log_u(log_v2, L"hvlib:Failed to retrieve symbol: %s. Error: %lu\n", symbolName, GetLastError());
    }

    MmSdkFree(symbol);

    return Offset;
}

SYMSRV_INDEX_INFO info = { 0 };
SYM_ENUM_TABLE g_SymTable = { 0 };

BOOL CALLBACK EnumSymbolsCallback(PSYMBOL_INFO pSymInfo, ULONG SymbolSize, PVOID UserContext) {
    UNREFERENCED_PARAMETER(SymbolSize);
    UNREFERENCED_PARAMETER(UserContext);

    if (!g_SymTable.SymTableAddress)
    {
        g_SymTable.SymTableAddress = malloc(sizeof(SYMBOL_INFO_PACKAGE));
    }
    else
    {
        PVOID ptrSymTable = g_SymTable.SymTableAddress;
        g_SymTable.SymTableAddress = realloc(ptrSymTable, g_SymTable.TableSize + sizeof(SYMBOL_INFO_PACKAGE));
    }

    RtlCopyMemory(&g_SymTable.SymTableAddress[g_SymTable.SymCount].si, pSymInfo, sizeof(SYMBOL_INFO_PACKAGE));
    g_SymTable.SymCount += 1;
    g_SymTable.TableSize += sizeof(SYMBOL_INFO_PACKAGE);

    //printf("0x%llX: %s\n", pSymInfo->Address, pSymInfo->Name);
    return TRUE;  // Continue enumeration
}

//
// https://github.com/MagnetForensics/Bin2Dmp/tree/master/Bin2Dmp
//

ULONG64
SymLoadForImageBase(
    PHVMM_ENUM_PARTITION PartitionEntry,
    ULONG64 ImageBase,
    ULONG ImageSize,
    const char* symbolName,
    MEMORY_ACCESS_TYPE MmAccess
)
{
    MODLOAD_DATA ModLoadData;

    BYTE PdbFileName[MAX_PATH] = { 0 };
    ULONG DebugDirRva;

    PVOID Image;
    PUCHAR FormatedName, p2;
    ULONG SizeOfImage;
    ULONG64 SymOffset = 0;
    ULONG64 SymAddress = 0;

    BOOL Ret;

    if (!g_SymInitialized)
        return FALSE;

    if ((ImageBase == 0) || (ImageSize == 0))
        return FALSE;

    Image = malloc(ImageSize);

    if (!Image)
        return FALSE;

    if (MmAccess == MmVirtualMemory)
    {
        Ret = MmReadVirtualAddress(PartitionEntry,
            ImageBase,
            ImageSize,
            Image,
            MmVirtualMemory
        );
    }
    else
    {
        ULARGE_INTEGER Pa;
        Pa.QuadPart = ImageBase;

        Ret = MmReadVirtualAddress(PartitionEntry, Pa.QuadPart, ImageSize, Image, MmPhysicalMemory);
    }

    if (!Ret)
        goto finish;

    Ret = PeGetPdbName(PartitionEntry,
        ImageBase,
        PdbFileName,
        sizeof(PdbFileName),
        &SizeOfImage,
        &DebugDirRva,
        MmVirtualMemory);

    if (SizeOfImage > ImageSize)
    {
        Image = realloc(Image, SizeOfImage);
        if (!Image)
            return FALSE;

        if (MmAccess == MmVirtualMemory)
        {
            Ret = MmReadVirtualAddress(PartitionEntry, ImageBase, ImageSize, Image, MmVirtualMemory);
        }
        else
        {
            ULARGE_INTEGER Pa;
            Pa.QuadPart = ImageBase;

            Ret = MmReadVirtualAddress(PartitionEntry, Pa.QuadPart, ImageSize, Image, MmPhysicalMemory);
        }

        if (!Ret)
            goto finish;
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

    ULONG64 BaseAddress = SymLoadModuleEx(g_hProcess,
        NULL,
        FormatedName,
        NULL,
        (DWORD64)Image,
        SizeOfImage,
        &ModLoadData,
        0);

    if (!SymEnumSymbols(g_hProcess, BaseAddress, "*", EnumSymbolsCallback, NULL)) {
        log_u(log_er, L"SymEnumSymbols failed. Error: %lu\n", GetLastError());
    }

    if (BaseAddress)
    {
        IMAGEHLP_MODULE64 ModuleInfo = { 0 };

        ModuleInfo.SizeOfStruct = sizeof(ModuleInfo);
        BOOLEAN bResult = SymGetModuleInfo64(g_hProcess, (DWORD64)Image, &ModuleInfo);

        if (!bResult)
        {
            log_u(log_er, L"-GetLastError() 0x%x\n", GetLastError());
        }

        log_u(log_er, L"-> %S is loaded.\n", ModuleInfo.LoadedPdbName);

        SymOffset = GetSymbolOffset(g_hProcess, BaseAddress, symbolName);
        SymAddress = SymOffset + ImageBase;

        Ret = TRUE;
    }
    else
    {
        Ret = FALSE;
        goto finish;
    }

finish:

    if (Image)
        MmSdkFree(Image);

    return SymAddress;
}

PSYM_ENUM_TABLE
SymInternalsGetAllymbolsInModule2(
    PHVMM_ENUM_PARTITION PartitionEntry,
    ULONG64 ImageBase,
    ULONG ImageSize,
    PWCHAR DriverName,
    MEMORY_ACCESS_TYPE MmAccess
)
{
    MODLOAD_DATA ModLoadData;

    BYTE PdbFileName[MAX_PATH] = { 0 };
    ULONG DebugDirRva;

    PVOID Image;
    PUCHAR FormatedName, p2 = NULL;
    ULONG SizeOfImage;
    ULONG64 SymOffset = 0;
    ULONG64 SymAddress = 0;

    BOOL Ret;

    if (g_SymTable.bInit)
    {
        PWCHAR drvName = (PWCHAR)&g_SymTable.DriverName;

        if (StrStrIW(drvName, DriverName))
            return &g_SymTable;
    }

    RtlZeroMemory(&g_SymTable, sizeof(SYM_ENUM_TABLE));

    if (!g_SymInitialized)
        return FALSE;

    if ((ImageBase == 0) || (ImageSize == 0))
        return FALSE;

    Image = malloc(ImageSize);

    if (!Image)
        return FALSE;

    if (MmAccess == MmVirtualMemory)
    {
        Ret = MmReadVirtualAddress(PartitionEntry,
            ImageBase,
            ImageSize,
            Image,
            MmVirtualMemory
        );
    }
    else
    {
        ULARGE_INTEGER Pa = { 0 };
        Pa.QuadPart = ImageBase;

        Ret = MmReadVirtualAddress(PartitionEntry, Pa.QuadPart, ImageSize, Image, MmPhysicalMemory);
    }

    if (!Ret)
        goto finish;

    Ret = PeGetPdbName(PartitionEntry,
        ImageBase,
        PdbFileName,
        sizeof(PdbFileName),
        &SizeOfImage,
        &DebugDirRva,
        MmVirtualMemory);

    if (SizeOfImage > ImageSize)
    {
        Image = realloc(Image, SizeOfImage);

        if (!Image)
            return FALSE;

        if (MmAccess == MmVirtualMemory)
        {
            Ret = MmReadVirtualAddress(PartitionEntry, ImageBase, ImageSize, Image, MmVirtualMemory);
        }
        else
        {
            ULARGE_INTEGER Pa;
            Pa.QuadPart = ImageBase;

            Ret = MmReadVirtualAddress(PartitionEntry, Pa.QuadPart, ImageSize, Image, MmPhysicalMemory);
        }

        if (!Ret)
            goto finish;
    }
    else
    {
        SizeOfImage = ImageSize;
    }

    if (!Ret)
        goto finish;

    ModLoadData.ssize = sizeof(ModLoadData);
    ModLoadData.ssig = DBHHEADER_DEBUGDIRS;
    ModLoadData.data = (PUCHAR)Image + DebugDirRva;
    ModLoadData.size = sizeof(IMAGE_DEBUG_DIRECTORY);
    ModLoadData.flags = 0;

    FormatedName = strstr(PdbFileName, ".pdb");

    if (FormatedName)
        *FormatedName = '\0';

    FormatedName = PdbFileName;
    p2 = FormatedName;
    const char* result = NULL;

    while ((p2 = strstr(p2, "\\")) != NULL)
    {
        p2++;           // Save the latest match  
        result = p2;    // Move forward to check for more
        //result++;
    }

    if (result)
        FormatedName = result;
    else
        FormatedName = PdbFileName;

    ULONG64 BaseAddress = SymLoadModuleEx(g_hProcess,
        NULL,
        FormatedName,
        NULL,
        (DWORD64)Image,
        SizeOfImage,
        &ModLoadData,
        0);

    if (!SymEnumSymbols(g_hProcess, BaseAddress, "*", EnumSymbolsCallback, NULL)) {
        log_u(log_er, L"SymEnumSymbols failed. Error: %lu\n", GetLastError());
        return NULL;
    }

    IMAGEHLP_MODULE64 ModuleInfo = { 0 };

    ModuleInfo.SizeOfStruct = sizeof(ModuleInfo);
    BOOLEAN bResult = SymGetModuleInfo64(g_hProcess, (DWORD64)Image, &ModuleInfo);

    if (!bResult)
    {
        log_u(log_er, L"-GetLastError() 0x%x\n", GetLastError());
    }

    //
    // const char* sym = "WinHvpDllLoadSuccessful";
    //

    for (ULONG i = 0; i < g_SymTable.SymCount; i++)
    {
        //
        // Retrieve symbol offset
        //

        SymOffset = GetSymbolOffset(g_hProcess, BaseAddress, g_SymTable.SymTableAddress[i].si.Name);
        if (!SymOffset)
        {
            log_u(log_er, L"%d, name 0x%x\n", i, GetLastError());
        }
        else
        {
            SymAddress = SymOffset + ImageBase;
            g_SymTable.SymTableAddress[i].si.Address = SymAddress;
        }
    }

    g_SymTable.bInit = TRUE;

finish:

    if (Image)
        MmSdkFree(Image);

    return &g_SymTable;
}

BOOLEAN
SymDestroy()
{
    g_SymInitialized = FALSE;
    return SymCleanup(g_hProcess);
}

ULONG64 SymInternalsGetAllModuleSymbolsTableLength
(
    PHVMM_ENUM_PARTITION PartitionEntry,
    ULONG64 ImageBase,
    ULONG ImageSize,
    PWCHAR DriverName,
    MEMORY_ACCESS_TYPE MmAccess
)
{
    if (!SymInit())
    {
        log_u(log_v2, L"hvlib:SymInit false\n");
        return 0;
    }

    PSYM_ENUM_TABLE SymbolAddress = SymInternalsGetAllymbolsInModule2(PartitionEntry, ImageBase, ImageSize, DriverName, MmAccess);

    if (!SymDestroy())
    {
        log_u(log_v2, L"hvlib:SymDestroy failed, but execution is continues\n");
        return 0;
    }

    if (!SymbolAddress)
    {
        log_u(log_v2, L"hvlib:SymbolAddress from SymInternalsGetAllymbolsInModule2 is NULL\n");
        return 0;
    }

    if (SymbolAddress->bInit) {
        RtlCopyMemory(&g_SymTable.DriverName, DriverName, wcslen(DriverName) * 2);
        return SymbolAddress->SymCount;
    }

    return 0;
}

PSYM_ENUM_TABLE SymInternalsGetAllModuleSymbols
(
    PHVMM_ENUM_PARTITION PartitionEntry,
    ULONG64 ImageBase,
    ULONG ImageSize,
    PWCHAR DriverName,
    MEMORY_ACCESS_TYPE MmAccess
)
{
    if (!SymInit())
        return NULL;

    PSYM_ENUM_TABLE SymbolAddress = SymInternalsGetAllymbolsInModule2(PartitionEntry, ImageBase, ImageSize, DriverName, MmAccess);
    SymDestroy();
    return SymbolAddress;
}

ULONG64
SymInternalsGetSymbolAddress
(
    PHVMM_ENUM_PARTITION PartitionEntry,
    ULONG64 ImageBase,
    ULONG ImageSize,
    const char* symbolName,
    MEMORY_ACCESS_TYPE MmAccess
)
{
    if (!SymInit())
        return 0;

    ULONG64 SymbolAddress = SymLoadForImageBase(PartitionEntry, ImageBase, ImageSize, symbolName, MmAccess);
    SymDestroy();
    return SymbolAddress;
}