/*++
    Copyright (C) 2010 Matthieu Suiche http://www.msuiche.net 
    Copyright (C) 2010 MoonSols. <http://www.moonsols.com>
    Copyright (c) 2017 - 2018, Comae Technologies DMCC
    All rights reserved.

Module Name:

    - text.cpp

Abstract:

    - 


Environment:

    - User mode

Revision History:

    - Matthieu Suiche (Mar-2010)

--*/


#include "stdafx.h"
#include "avalon.h"

#include <conio.h>

USHORT
GetConsoleTextAttribute(HANDLE hConsole)
{
CONSOLE_SCREEN_BUFFER_INFO csbi;

    GetConsoleScreenBufferInfo(hConsole, &csbi);
    return(csbi.wAttributes);
}

VOID
Red(LPCWSTR Format, ...)
{
HANDLE Handle;
USHORT Color;
va_list va;

    Handle = GetStdHandle(STD_OUTPUT_HANDLE);

    Color = GetConsoleTextAttribute(Handle);

    SetConsoleTextAttribute(Handle, FOREGROUND_RED | FOREGROUND_INTENSITY);
    va_start(va, Format);
    vwprintf(Format, va);
    va_end(va); 

    SetConsoleTextAttribute(Handle, Color);
}

VOID
White(LPCWSTR Format, ...)
{
HANDLE Handle;
USHORT Color;
va_list va;

    Handle = GetStdHandle(STD_OUTPUT_HANDLE);

    Color = GetConsoleTextAttribute(Handle);

    SetConsoleTextAttribute(Handle, 0xF);
    va_start(va, Format);
    vwprintf(Format, va);
    va_end(va); 

    SetConsoleTextAttribute(Handle, Color);
}


VOID
Green(LPCWSTR Format, ...)
{
HANDLE Handle;
USHORT Color;
va_list va;

    Handle = GetStdHandle(STD_OUTPUT_HANDLE);

    Color = GetConsoleTextAttribute(Handle);

    SetConsoleTextAttribute(Handle, FOREGROUND_GREEN | FOREGROUND_INTENSITY);
    va_start(va, Format);
    vwprintf(Format, va);
    va_end(va); 

    SetConsoleTextAttribute(Handle, Color);
}

VOID
GetCursorPosition(HANDLE hConsole, PCOORD Coord)
{
CONSOLE_SCREEN_BUFFER_INFO csbi;

    GetConsoleScreenBufferInfo(hConsole, &csbi);

    *Coord = csbi.dwCursorPosition;
}

UCHAR
InteractiveQuestion(LPCWSTR QuestionToAsk,
                    LPCWSTR Choices,
                    LPCWSTR Command)
{
UCHAR c;

    White(L"\r\n%s", QuestionToAsk);
    wprintf(L"%s", Choices);
    White(L"%s", Command);
    c = (UCHAR)_getch();

    //
    // We donnot print caca text.
    //
    if (((c >= '0') && (c <= '9')) ||
        ((c >= 'A') && (c <= 'Z')) ||
        ((c >= 'a') && (c <= 'z')))
    {
        Green(L"%c", c);
    }
    wprintf(L"\r\n");

    return tolower(c);
}