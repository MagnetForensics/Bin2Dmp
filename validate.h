/*++
    Copyright (C) 2010 Matthieu Suiche http://www.msuiche.net 
    Copyright (C) 2010 MoonSols. <http://www.moonsols.com>
    All rights reserved.

Module Name:

    - validate.h

Abstract:

    - 


Environment:

    - User mode

Revision History:

    - Matthieu Suiche (Jan-2010)

--*/

BOOL
MmValidatex86KPCR(
    HANDLE Handle,
    PVOID Page
);

BOOL
MmValidationx86KProcState(
    HANDLE Handle,
    PVOID Page
);

BOOL
MmValidatex64KPCR(
    PVOID Page
);

BOOL
MmValidationx64KProcState(
    PVOID Page
);