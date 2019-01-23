/*++
    Copyright (c) Comae Technologies DMCC. All rights reserved.

Module Name:

    - read.c

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
MmReadVirtualAddress(
    HANDLE Handle,
    ULONGLONG PageDirectoryTable,
    ULONGLONG Va,
    PVOID Buffer,
    SIZE_T SizeOfBuffer
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
SIZE_T BytesReaded, BytesToRead;

BOOL Ret;

    if (Buffer == NULL) return FALSE;

#if DEBUG_ENABLED
    // wprintf(L"a");
#endif
    RtlZeroMemory(Buffer, SizeOfBuffer);

    for (BytesReaded = 0;
         BytesReaded < SizeOfBuffer;
         BytesReaded += PAGE_SIZE)
    {
#if DEBUG_ENABLED
        // wprintf(L"b");
#endif
        Pa = MmGetPhysicalAddress(Handle,
                                  PageDirectoryTable,
                                  Va + BytesReaded);

        if (Pa.QuadPart == 0) continue;

#if DEBUG_ENABLED
        // wprintf(L"c");
#endif
        BytesToRead = ((SizeOfBuffer - BytesReaded) >= PAGE_SIZE) ?
                        PAGE_SIZE : (SizeOfBuffer % PAGE_SIZE);

        Ret = MmReadPhysicalAddress(Handle,
                                    Pa,
                                    (PUCHAR)Buffer + BytesReaded,
                                    (ULONG)BytesToRead);

#if DEBUG_ENABLED
        // wprintf(L"d");
#endif
        if (Ret == FALSE) continue;
    }

    return TRUE;
}