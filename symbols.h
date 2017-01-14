/*++
    Copyright (C) 2010 Matthieu Suiche http://www.msuiche.net 
    Copyright (C) 2010 MoonSols. <http://www.moonsols.com>
    All rights reserved.

Module Name:

    - symbols.h

Abstract:

    - 


Environment:

    - User mode

Revision History:

    - Matthieu Suiche (Jan-2010)

--*/

#if LOAD_SYMBOLS
BOOL
SymInit(
);

BOOL
SymLoadForImageBase(
    HANDLE Handle,
    ULONGLONG ImageBase,
    ULONG ImageSize
);

BOOL
SymDestroy(
);
#endif