/*++
    Copyright (C) 2010 Matthieu Suiche http://www.msuiche.net 
    Copyright (C) 2010 MoonSols. <http://www.moonsols.com>
    Copyright (c) 2017 - 2018, Comae Technologies DMCC
    All rights reserved.

Module Name:

    - pe.h

Abstract:

    - 


Environment:

    - User mode

Revision History:

    - Matthieu Suiche (Jan-2010)

--*/

#define CV_SIGNATURE_NB10   '01BN'
#define CV_SIGNATURE_RSDS   'SDSR'

typedef struct _CV_INFO_PDB70 
{
    DWORD Signature; 
    GUID Guid; // unique identifier 
    DWORD Age; // an always-incrementing value 
    BYTE PdbFileName[1]; // zero terminated string with the name of the PDB file 
} CV_INFO_PDB70, *PCV_INFO_PDB70;

BOOL
PeGetPdbName(
    HANDLE Handle,
    ULONGLONG Va,
    PUCHAR PdbName,
    ULONG SizeOfPdbName,
    PULONG SizeOfImage,
    PULONG ImageDebugDir
);

VOID
PeDumpHexa(
    PVOID Buffer,
    ULONG BytesCount
);

ULONG64
PeGetProcAddress(
    HANDLE Handle,
    ULONG64 ModuleBase,
    PCHAR Name
);

BOOL
PeGetSection(
    HANDLE Handle,
    ULONG64 ModuleBase,
    PUCHAR SectionName,
    PULONG OutSectionVa,
    PULONG OutSectionOffset,
    PULONG OutSectionSize
);