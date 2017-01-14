/*++
    Copyright (C) 2010 Matthieu Suiche http://www.msuiche.net 
    Copyright (C) 2010 MoonSols. <http://www.moonsols.com>
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

#define APPLICATION_NAME L"bin2dmp"
#define APPLICATION_DESC L"Convert raw memory dump images into Microsoft crash dump files."

#ifdef PRO_EDITION
#define APPLICATION_EDITION L"Professional Edition"
#define LICENSE_TYPE L" - Single User Licence"
#else
#define APPLICATION_EDITION L"Community Edition"
#define LICENSE_TYPE L""
#endif

VOID
Help()
{
    wprintf(L"Usage: " APPLICATION_NAME L" <input file> <output file>\n"
            L"\n"
            L"  - <input file>      Source path of the raw memory dump file.\n"
            L"  - <output file>     Destination path of the Microsoft crash dump file.\n\n");

#ifdef COMMUNITY_EDITION
    Red(L"Note:\n"
            L"   Community Edition only supports 32-bits Microsoft hibernation file of\n"
            L"   Windows XP, 2003, 2008 and Vista.\n\n");
#endif

    Green(L"   Professional Edition supports x86 and x64 raw memory files from Windows XP to 7.\n");

#ifdef COMMUNITY_EDITION
    White(L"   More information available on http://www.moonsols.com\n");
#endif
}

int wmain(UINT argc, LPCWSTR argv[])
{
HANDLE BinFile, CrashDumpFile;
BOOL Ret;   

ULONG StartTime, EndTime;

    White(L"\n"
            L"  " APPLICATION_NAME L" - " LIBRARY_VERSION L"\n"
            L"  " APPLICATION_DESC L"\n"
            L"  Copyright (C) 2007 - 2014, Matthieu Suiche <http://www.msuiche.net>\n"
            L"  Copyright (C) 2012 - 2014, MoonSols Limited <http://www.moonsols.com>\n"
//            L"  User " USER_NAME L", " COMPANY_NAME L" (" COUNTRY_CODE L")\n"
            L"\n");

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

