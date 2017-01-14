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