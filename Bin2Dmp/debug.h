/*++
    Copyright (C) 2010 Matthieu Suiche http://www.msuiche.net 
    Copyright (C) 2010 MoonSols. <http://www.moonsols.com>
    All rights reserved.

Module Name:

    - debug.h

Abstract:

    - 


Environment:

    - User mode

Revision History:

    - Matthieu Suiche (Jan-2010)

--*/

#if DEBUG_ENABLED
VOID
DumpExcalibur(
    HANDLE Handle
);

VOID
DumpCache(
);

VOID
DumpMdl(
);
#endif