/*++
    Copyright (C) 2010 Matthieu Suiche http://www.msuiche.net 
    Copyright (C) 2010 MoonSols. <http://www.moonsols.com>
    Copyright (c) 2017 - 2018, Comae Technologies DMCC
    All rights reserved.

Module Name:

    - cache.h

Abstract:

    - 


Environment:

    - User mode

Revision History:

    - Matthieu Suiche (Mar-2010)

--*/

BOOL
MmAddToCache(
    ULARGE_INTEGER Pa,
    PVOID Va
);

BOOL
MmIsCached(
    ULARGE_INTEGER Pa,
    PVOID Va,
    SIZE_T Size
);
