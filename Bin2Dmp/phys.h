/*++
    Copyright (C) 2010 Matthieu Suiche http://www.msuiche.net 
    Copyright (C) 2010 MoonSols. <http://www.moonsols.com>
    All rights reserved.

Module Name:

    - phys.h

Abstract:

    - 


Environment:

    - User mode

Revision History:

    - Matthieu Suiche (Jan-2010)

--*/

ULARGE_INTEGER
MmComputePhysicalAddress(
    HANDLE Handle,
    ULARGE_INTEGER Pa
);

BOOL
MmReadPageAtPhysicalAddress(
    HANDLE Handle,
    ULARGE_INTEGER Pa,
    PVOID Buffer,
    ULONG SizeOfBuffer
);

BOOL
MmReadPhysicalAddress(
    HANDLE Handle,
    ULARGE_INTEGER Pa,
    PVOID Buffer,
    ULONG SizeOfBuffer
);

BOOL
MmValidatex86PaePageDirectoryPointerTable(
    HANDLE Handle,
    ULARGE_INTEGER Pa
);

BOOL
MmValidatex86NoPaePageDirectoryTable(
    HANDLE Handle,
    ULARGE_INTEGER Pa
);

BOOL
MmValidatex64PageMapLevel4Table(
    HANDLE Handle,
    ULARGE_INTEGER Pa
);

BOOL
MmReadXpressBlock(
    IN HANDLE Handle,
    OPTIONAL IN PULARGE_INTEGER Pa,
    OPTIONAL IN ULONG XpressIndex,
    IN ULARGE_INTEGER XpressHeader,
    OUT PVOID Buffer,
    IN ULONG SizeOfBuffer,
    OPTIONAL IN ULONG InCompressedSize, // Win8
    OPTIONAL OUT PULONG OutBufferSize
);