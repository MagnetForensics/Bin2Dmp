/*++
    Copyright (C) 2010 Matthieu Suiche http://www.msuiche.net 
    Copyright (C) 2010 MoonSols. <http://www.moonsols.com>
    Copyright (c) 2017 - 2018, Comae Technologies DMCC
    All rights reserved.

Module Name:

    - hibr2bin.c

Abstract:

    - Convert raw memory dump images into Microsoft crash dump files.


Environment:

    - User mode

Revision History:

    - Matthieu Suiche (Mar-2010)

--*/

#include "stdafx.h"
#include "avalon.h"

#ifndef COMAE_TOOLKIT_VERSION
#define COMAE_TOOLKIT_VERSION "3.0.0.undefined"
#endif

VOID
Help()
{
    wprintf(L"Usage: Bin2Dmp <input file> <output file>\n\n");

    wprintf(L"Description:\n"
            L"  Converts raw memory dump images into Microsoft crash dump files.\n\n");

    wprintf(L"Options:\n"
            L"  <input file>      Source path of the raw memory dump file.\n"
            L"  <output file>     Destination path of the Microsoft crash dump file.\n");
}

int wmain(UINT argc, LPCWSTR argv[])
{
    HANDLE BinFile, CrashDumpFile;
    BOOL Ret;   
    ULONG StartTime, EndTime;

    wprintf(L"\n"
            L"  Bin2Dmp %S\n"
            L"  Copyright (C) 2007 - 2017, Matthieu Suiche <http://www.msuiche.net>\n"
            L"  Copyright (C) 2012 - 2014, MoonSols Limited <http://www.moonsols.com>\n"
            L"  Copyright (C) 2015 - 2017, Comae Technologies FZE <http://www.comae.io>\n",
            L"  Copyright (C) 2017 - 2018, Comae Technologies DMCC <http://www.comae.io>\n\n",
            COMAE_TOOLKIT_VERSION);

    if (argc < 3)
    {
        Help();
        return FALSE;
    }

    if (OpenBinFile(argv[1], &BinFile) == FALSE)
    {
        Red(L"Cannot open file. Please check if the file is not being used.\n");
        return FALSE;
    }

    CrashDumpFile = CreateFile(argv[2],
                        GENERIC_WRITE,
                        0,
                        NULL,
                        CREATE_ALWAYS,
                        FILE_ATTRIBUTE_NORMAL,
                        NULL);

    if (CrashDumpFile != INVALID_HANDLE_VALUE)
    {
        White(L"Loading file... ");
        Green(L"Done.\n");

        StartTime = GetTickCount();
        Ret = ConvertToDmp(BinFile, CrashDumpFile);
        EndTime = GetTickCount();

        EndTime = (EndTime - StartTime) / 1000;

        if (Ret == TRUE)
        {
            White(L"\nTotal time for the conversion: ");
            Green(L"%d minutes %d seconds.\n", EndTime / 60, EndTime % 60);
        }
        else
        {
            White(L"Conversion... ");
            Red(L"Failed.");
        }

        CloseHandle(CrashDumpFile);
    }
    else
    {
        White(L"Loading file... ");
        Red(L"Failed.\n");
    }

    CloseXFile(BinFile);

    return TRUE;
}

