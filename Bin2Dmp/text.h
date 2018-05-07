/*++
    Copyright (C) 2010 Matthieu Suiche http://www.msuiche.net 
    Copyright (C) 2010 MoonSols. <http://www.moonsols.com>
    Copyright (c) 2017 - 2018, Comae Technologies DMCC
    All rights reserved.

Module Name:

    - text.h

Abstract:

    - 


Environment:

    - User mode

Revision History:

    - Matthieu Suiche (Jan-2010)

--*/


USHORT
GetConsoleTextAttribute(
    HANDLE hConsole
);

VOID
Red(
    LPCWSTR Format,
    ...
);

VOID
White(
    LPCWSTR Format,
    ...
);

VOID
Green(
    LPCWSTR Format,
    ...
);

VOID
GetCursorPosition(
    HANDLE hConsole,
    PCOORD Coord
);

UCHAR
InteractiveQuestion(
    LPCWSTR QuestionToAsk,
    LPCWSTR Choices,
    LPCWSTR Command
);