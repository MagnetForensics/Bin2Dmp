/*++
    Copyright (C) 2010 Matthieu Suiche http://www.msuiche.net 
    Copyright (C) 2010 MoonSols. <http://www.moonsols.com>
    Copyright (c) 2017 - 2018, Comae Technologies DMCC
    All rights reserved.

Module Name:

    - file.c

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
ReadFileAsynchronous(
    HANDLE Handle,
    ULARGE_INTEGER Offset,
    PVOID Dest,
    ULONG Size
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
OVERLAPPED Overlapped = {0};
ULONG NbOfBytes;

BOOL Ret;

    Overlapped.Offset = Offset.LowPart;
    Overlapped.OffsetHigh = Offset.HighPart;

    NbOfBytes = 0;
    Ret = ReadFile(Handle, Dest, Size, &NbOfBytes, &Overlapped);
    // Asynchronous  I/O
    if (Ret == FALSE)
    {
        if (GetLastError() != ERROR_IO_PENDING)
        {
            return Ret;
        }
        else
        {
            Ret = GetOverlappedResult(Handle,
                                      &Overlapped,
                                      &NbOfBytes,
                                      TRUE);
        }
    }

    return Ret;
}

BOOL
WriteFileSynchronous(
    HANDLE Handle,
    PVOID Buffer,
    DWORD NbOfBytesToWrite
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
    DWORD WrittenBytes;
    BOOL Ret;

    WrittenBytes = 0;
    Ret = FALSE;

    Ret = WriteFile(Handle, Buffer, NbOfBytesToWrite, &WrittenBytes, NULL);
    if ((Ret == FALSE) && (GetLastError() == ERROR_IO_PENDING))
    {
        do
        {
            Ret = WaitForSingleObjectEx(Handle, INFINITE, TRUE);
        } while (Ret == WAIT_IO_COMPLETION);
    }

    if (WrittenBytes == NbOfBytesToWrite)
    {
        Ret = TRUE;
    }

    return Ret;
}

BOOL
OpenXFile(
    LPCWSTR FileName,
    PHANDLE Handle
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

    if (Handle == NULL) return FALSE;

    *Handle = CreateFile(FileName,
                         GENERIC_READ,
                         FILE_SHARE_READ, // If user already opened file in an editor.
                         NULL,
                         OPEN_EXISTING,
                         FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OVERLAPPED,
                         NULL);

    if (GetLastError() == ERROR_SHARING_VIOLATION)
    {
        *Handle = CreateFile(FileName,
                             GENERIC_READ,
                             FILE_SHARE_READ | FILE_SHARE_WRITE, // If user already opened file in an editor.
                             NULL,
                             OPEN_EXISTING,
                             FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OVERLAPPED,
                             NULL);
    }

    if (*Handle == INVALID_HANDLE_VALUE) return FALSE;

    if (Ret = MmInitializeMdl(*Handle, TypeDmp))
    {
#if DEBUG_ENABLED
        wprintf(L"TypeDmp\n");
#endif

        Ret = MmSortMdl();
        if (Ret == TRUE) Ret = KeInitializeData(*Handle, TypeDmp);
    }
    else if ((InternalErrorCode == FALSE) && (Ret = MmInitializeMdl(*Handle, TypeHibr)))
    {
#if DEBUG_ENABLED
        wprintf(L"TypeHibr\n");
#endif

        Ret = MmSortMdl();
        if (Ret == TRUE) Ret = KeInitializeData(*Handle, TypeHibr);
    }
    else if ((InternalErrorCode == FALSE) && (Ret = MmInitializeMdl(*Handle, TypeRaw)))
    {
#if DEBUG_ENABLED
        wprintf(L"TypeRaw\n");
#endif

        Ret = MmSortMdl();
        if (Ret == TRUE) Ret = KeInitializeData(*Handle, TypeRaw);
    }

    return Ret;
}

BOOL
OpenBinFile(
    LPCWSTR FileName,
    PHANDLE Handle
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

    if (Handle == NULL) return FALSE;

    *Handle = CreateFile(FileName,
                         GENERIC_READ,
                         FILE_SHARE_READ, // If user already opened file in an editor.
                         NULL,
                         OPEN_EXISTING,
                         FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OVERLAPPED,
                         NULL);

#ifdef PRO_EDITION
    if (GetLastError() == ERROR_SHARING_VIOLATION)
    {
        *Handle = CreateFile(FileName,
                             GENERIC_READ,
                             FILE_SHARE_READ | FILE_SHARE_WRITE, // If user already opened file in an editor.
                             NULL,
                             OPEN_EXISTING,
                             FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OVERLAPPED,
                             NULL);
    }
#endif

    if (*Handle == INVALID_HANDLE_VALUE) return FALSE;
    // ERROR_SHARING_VIOLATION

    if ((Ret = MmInitializeMdl(*Handle, TypeRaw)))
    {
#if DEBUG_ENABLED
        wprintf(L"TypeRaw\n");
#endif

        Ret = MmSortMdl();
        if (Ret == TRUE) Ret = KeInitializeData(*Handle, TypeRaw);
    }

    return Ret;
}

BOOL
OpenDmpFile(
    LPCWSTR FileName,
    PHANDLE Handle
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

    if (Handle == NULL) return FALSE;

    *Handle = CreateFile(FileName,
                         GENERIC_READ,
                         FILE_SHARE_READ, // If user already opened file in an editor.
                         NULL,
                         OPEN_EXISTING,
                         FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OVERLAPPED,
                         NULL);

#ifdef PRO_EDITION
    if (GetLastError() == ERROR_SHARING_VIOLATION)
    {
        *Handle = CreateFile(FileName,
                             GENERIC_READ,
                             FILE_SHARE_READ | FILE_SHARE_WRITE, // If user already opened file in an editor.
                             NULL,
                             OPEN_EXISTING,
                             FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OVERLAPPED,
                             NULL);
    }
#endif

    if (*Handle == INVALID_HANDLE_VALUE) return FALSE;

    if (Ret = MmInitializeMdl(*Handle, TypeDmp))
    {
#if DEBUG_ENABLED
        wprintf(L"TypeDmp\n");
#endif

        Ret = MmSortMdl();
        if (Ret == TRUE) Ret = KeInitializeData(*Handle, TypeDmp);
    }

    return Ret;
}

BOOL
OpenHiberFile(
    LPCWSTR FileName,
    PHANDLE Handle,
    BOOLEAN InitializeKdData
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

    if (Handle == NULL) return FALSE;

    *Handle = CreateFile(FileName,
                         GENERIC_READ,
                         FILE_SHARE_READ, // If user already opened file in an editor.
                         NULL,
                         OPEN_EXISTING,
                         FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OVERLAPPED,
                         NULL);

#ifdef PRO_EDITION
    if (GetLastError() == ERROR_SHARING_VIOLATION)
    {
        *Handle = CreateFile(FileName,
                             GENERIC_READ,
                             FILE_SHARE_READ | FILE_SHARE_WRITE, // If user already opened file in an editor.
                             NULL,
                             OPEN_EXISTING,
                             FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OVERLAPPED,
                             NULL);
    }
#endif

    if (*Handle == INVALID_HANDLE_VALUE) return FALSE;

    if ((Ret = MmInitializeMdl(*Handle, TypeHibr)))
    {
#if DEBUG_ENABLED
        wprintf(L"TypeHibr\n");
#endif

        Ret = MmSortMdl();
        if (InitializeKdData)
        {
            if (Ret == TRUE) Ret = KeInitializeData(*Handle, TypeHibr);
        }
    }

    return Ret;
}

BOOL
CloseXFile(
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

    Ret = FALSE;

    if (Handle && (Handle != INVALID_HANDLE_VALUE))
    {
        CloseHandle(Handle);
        Ret = TRUE;
    }

    if (g_KiExcaliburData.DbgData) free(g_KiExcaliburData.DbgData);
    if (g_KiExcaliburData.ContextData) free(g_KiExcaliburData.ContextData);
    if (g_KiExcaliburData.SpecialRegsData) free(g_KiExcaliburData.SpecialRegsData);

    MmDestroyMdl();

    return Ret;
}
