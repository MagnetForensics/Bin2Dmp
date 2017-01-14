/*++
    Copyright (C) 2010 Matthieu Suiche http://www.msuiche.net 
    Copyright (C) 2010 MoonSols. <http://www.moonsols.com>
    All rights reserved.

Module Name:

    - cache.h

Abstract:

    - Caches 16 pages in memory to gain performance. Very useful with
      hibernation file.


Environment:

    - User mode

Revision History:

    - Matthieu Suiche (Mar-2010)

--*/

#include "stdafx.h"
#include "avalon.h"

#if CACHE_ENABLED
BOOL
MmAddToCache(
    ULARGE_INTEGER Pa,
    PVOID Va
)
{
ULONG CacheIndex;
ULONG LowestPriorityCacheIndex;
ULONGLONG LowestPriority;

ULARGE_INTEGER MaskedPa;

    //
    // Align physical address;
    //
    MaskedPa = Pa;
    MaskedPa.QuadPart &= ~(PAGE_SIZE - 1);

    LowestPriorityCacheIndex = 0;
    LowestPriority = 0xFFFFFFFFFFFFFFFFULL;

    for (CacheIndex = 0; CacheIndex < MAX_CACHED_PAGES; CacheIndex += 1)
    {
        if ((MmCachedPages[CacheIndex].Pa.QuadPart == 0) && (MmCachedPages[CacheIndex].Priority == 0))
        {
            //
            // Empty entry.
            //
            LowestPriorityCacheIndex = CacheIndex;
            goto AddEntry;
        }
        else
        {
            if (MmCachedPages[CacheIndex].Pa.QuadPart == MaskedPa.QuadPart)
            {
                //
                // Already exists. But we should never reach this condition.
                //
                MmCachedPages[CacheIndex].Priority += 1;
                goto Finish;
            }
            else if (MmCachedPages[CacheIndex].Priority < LowestPriority)
            {
                //
                // Computer the less accessed entry.
                //
                LowestPriorityCacheIndex = CacheIndex;
                LowestPriority = MmCachedPages[CacheIndex].Priority;
            }
        }
    }

AddEntry:
    // wprintf(L"=> (Add) Pa: %I64X in Index %d\n", MaskedPa.QuadPart, CacheIndex);

    MmCachedPages[LowestPriorityCacheIndex].Priority = 1;
    MmCachedPages[LowestPriorityCacheIndex].Pa = MaskedPa;

    //
    // BUG: The input source buffer is not always aligned.
    // Especially with heap allocation so we do not need to align it.
    //
    // (SIZE_T)Va &= ~(PAGE_SIZE - 1);
    //

    memcpy_s(MmCachedPages[LowestPriorityCacheIndex].Page,
             PAGE_SIZE,
             Va,
             PAGE_SIZE);

Finish:
    return TRUE;
}

BOOL
MmIsCached(
    ULARGE_INTEGER Pa,
    PVOID Va,
    SIZE_T Size
)
{
ULONG CacheIndex;
BOOL IsCached;

ULARGE_INTEGER MaskedPa;

    MaskedPa = Pa;
    MaskedPa.QuadPart &= ~(PAGE_SIZE - 1);

    IsCached = FALSE;

    for (CacheIndex = 0; CacheIndex < MAX_CACHED_PAGES; CacheIndex += 1)
    {
        if (MmCachedPages[CacheIndex].Priority == 0)
        {
            goto Finish;
        }
        else if (MmCachedPages[CacheIndex].Pa.QuadPart == MaskedPa.QuadPart)
        {
            ULONG Offset;

            MmCachedPages[CacheIndex].Priority += 1;

            // wprintf(L"=> (Read) Pa: %I64X in Index %d\n", MaskedPa.QuadPart, CacheIndex);

            Offset = (Pa.LowPart & (PAGE_SIZE - 1));

            IsCached = TRUE;

            memcpy_s(Va,
                     Size,
                     MmCachedPages[CacheIndex].Page + Offset,
                     Size);
            goto Finish;
        }
    }

Finish:
    return IsCached;
}
#endif