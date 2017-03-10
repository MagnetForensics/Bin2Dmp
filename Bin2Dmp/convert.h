/*++
    Copyright (C) 2010 Matthieu Suiche http://www.msuiche.net 
    Copyright (C) 2010 MoonSols. <http://www.moonsols.com>
    All rights reserved.

Module Name:

    - convert.h

Abstract:

    - 


Environment:

    - User mode

Revision History:

    - Matthieu Suiche (Mar-2010)

--*/

#define WRITE_CACHE_SIZE (1024 * 1024)

BOOL
ConvertToDmp(
    HANDLE Input,
    HANDLE CrashDumpFile
);

BOOL
ConvertToDmp32(
    HANDLE Input,
    HANDLE CrashDumpFile
);

#ifdef PRO_EDITION
BOOL
ConvertToDmp64(
    HANDLE Input,
    HANDLE CrashDumpFile
);
#endif

BOOL
ConvertToBin(
    HANDLE Input,
    HANDLE BinFile
);