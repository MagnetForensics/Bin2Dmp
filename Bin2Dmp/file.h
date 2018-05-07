/*++
    Copyright (C) 2010 Matthieu Suiche http://www.msuiche.net 
    Copyright (C) 2010 MoonSols. <http://www.moonsols.com>
    Copyright (c) 2017 - 2018, Comae Technologies DMCC
    All rights reserved.

Module Name:

    - file.h

Abstract:

    - 


Environment:

    - User mode

Revision History:

    - Matthieu Suiche (Jan-2010)

--*/

BOOL
OpenXFile(
    LPCWSTR FileName,
    PHANDLE Handle
);

BOOL
OpenBinFile(
    LPCWSTR FileName,
    PHANDLE Handle
);

BOOL
OpenDmpFile(
    LPCWSTR FileName,
    PHANDLE Handle
);

BOOL
OpenHiberFile(
    LPCWSTR FileName,
    PHANDLE Handle,
    BOOLEAN InitializeKdData
);

BOOL
ReadFileAsynchronous(
    HANDLE Handle,
    ULARGE_INTEGER Offset,
    PVOID Dest,
    ULONG Size
);

BOOL
WriteFileSynchronous(
    HANDLE Handle,
    PVOID Buffer,
    DWORD NbOfBytesToWrite
);

BOOL
CloseXFile(
    HANDLE Handle
);