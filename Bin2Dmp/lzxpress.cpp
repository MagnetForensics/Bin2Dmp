/*++
    Copyright (C) 2010 Matthieu Suiche http://www.msuiche.net 
    Copyright (C) 2010 MoonSols. <http://www.moonsols.com>
    All rights reserved.

Module Name:

    - lzxpress.c

Abstract:

    - 


Environment:

    - User mode

Revision History:

    - Matthieu Suiche (Jan-2010)

--*/

#include "stdafx.h"
#include "avalon.h"

BOOL
XpressHuffTable()
{
    /*
    CurrentTableEntry = 0
    For BitLength = 1 to 15
    For Symbol = 0 to 511
    If the encoded bit length of Symbol equals BitLength
    EntryCount = (1 << (15 – BitLength))
    Repeat EntryCount times
    If CurrentTableEntry >= 2^15
    The compressed data is not valid. Return with error.
    DecodingTable[CurrentTableEntry] = Symbol
    CurrentTableEntry = CurrentTableEntry + 1
    If CurrentTableEntry does not equal 2^15
    The compressed data is not valid. Return with error.
    */
    return FALSE;
}

ULONG
Xpress_Decompress(
    PUCHAR InputBuffer,
    ULONG InputSize,
    PUCHAR OutputBuffer,
    ULONG OutputSize
)
/*++

Routine Description:

    Desc.

Arguments:

    Arg1 - Desc.

    Arg2 - Desc.

    Arg3 - Desc.

Return Value:

    Ret1 - Desc.

    Ret2 - Desc.

--*/
{
    ULONG OutputIndex, InputIndex;
    ULONG Indicator, IndicatorBit;
    ULONG Length;
    ULONG Offset;
    ULONG NibbleIndex;
    ULONG NibbleIndicator;

    Indicator = 0;
    IndicatorBit = 0;
    Length = 0;
    Offset = 0;
    NibbleIndex = 0;

    NibbleIndicator = XPRESS_ENCODE_MAGIC;

    for (OutputIndex = 0, InputIndex = 0;
         (OutputIndex < OutputSize) && (InputIndex < InputSize);
         )
    {

        if (IndicatorBit == 0)
        {
            Indicator = (InputBuffer[InputIndex + 3] << 24);
            Indicator |= (InputBuffer[InputIndex + 2] << 16);
            Indicator |= (InputBuffer[InputIndex + 1] << 8);
            Indicator |= InputBuffer[InputIndex];

            InputIndex += sizeof(ULONG);

            IndicatorBit = 32; 
        }

        IndicatorBit--;

        //
        // Check whether the bit specified by IndicatorBit is set or not 
        // set in Indicator. For example, if IndicatorBit has value 4 
        // check whether the 4th bit of the value in Indicator is set.
        //

        if (((Indicator >> IndicatorBit) & 1) == 0)
        {
            if (InputIndex >= InputSize) break;
            OutputBuffer[OutputIndex] = InputBuffer[InputIndex];

            InputIndex += sizeof(UCHAR);
            OutputIndex += sizeof(UCHAR);
        }
        else 
        {
            if ((InputIndex + 1) >= InputSize) break;
            Length = (InputBuffer[InputIndex + 1] << 8);
            Length |= InputBuffer[InputIndex];

            InputIndex += sizeof(USHORT);

            Offset = Length / 8;
            Length = Length % 8;

            if (Length == 7)
            {
                if (NibbleIndex == 0)
                {
                    NibbleIndex = InputIndex;

                    if (InputIndex >= InputSize) break;
                    Length = InputBuffer[InputIndex] % 16; 

                    InputIndex += sizeof(UCHAR);
                }
                else 
                {
                    if (NibbleIndex >= InputSize) break;
                    Length = InputBuffer[NibbleIndex] / 16;
                    NibbleIndex = 0;
                }

                if (Length == 15)
                {
                    if (InputIndex >= InputSize) break;
                    Length = InputBuffer[InputIndex];

                    InputIndex += sizeof(UCHAR);

                    if (Length == 255)
                    {
                        if ((InputIndex + 1) >= InputSize) break;
                        Length = (InputBuffer[InputIndex + 1] << 8);
                        Length |= InputBuffer[InputIndex];

                        InputIndex += sizeof(USHORT);

                        Length -= (15 + 7);
                    }
                    Length += 15; 
                }
                Length += 7;
            }

            Length += 3;

            while (Length != 0)
            {
                if ((OutputIndex >= OutputSize) || ((Offset + 1) > OutputIndex)) break;

                OutputBuffer[OutputIndex] = OutputBuffer[OutputIndex - Offset - 1];

                OutputIndex += sizeof(UCHAR);
                Length -= sizeof(UCHAR);
            }
        }
    }

    return OutputIndex;
}