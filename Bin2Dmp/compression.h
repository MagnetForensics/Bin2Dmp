/*++
    Copyright (C) 2010 Matthieu Suiche http://www.msuiche.net 
    Copyright (C) 2010 MoonSols. <http://www.moonsols.com>
    Copyright (c) 2017 - 2018, Comae Technologies DMCC
    All rights reserved.

Module Name:

    - compression.h

Abstract:

    - 


Environment:

    - User mode

Revision History:

    - Matthieu Suiche (Jan-2010)

--*/

#define XPRESS_ENCODE_MAGIC 0x19880922

#define XPRESS_MAGIC "\x81\x81xpress"
#define XPRESS_MAGIC_SIZE (sizeof(XPRESS_MAGIC) - 1)

#define XPRESS_HEADER_SIZE 0x20

#define XPRESS_ALIGNMENT 8

ULONG
Xpress_Decompress(
    PUCHAR InputBuffer,
    ULONG InputSize,
    PUCHAR OutputBuffer,
    ULONG OutputSize
);