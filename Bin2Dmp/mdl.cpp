/*++
    Copyright (c) Comae Technologies DMCC. All rights reserved.

Module Name:

    - mdl.c

Abstract:

    - Never use PHYSICAL_ADDRESS (signed). Use ULARGE_INTEGER instead.


Environment:

    - User mode

Revision History:

    - Matthieu Suiche (Jan-2010)

--*/

#include "stdafx.h"
#include "avalon.h"

//
// Globals
//
PMEMORY_DESCRIPTOR_LIST MmMdlAvailable = NULL;
ULARGE_INTEGER MmMaximumPhysicalAddress = {0};
ULONG MmMaximumPhysicalPage = 0;

ULARGE_INTEGER g_LastValidXpressBlock = {0};

#if CACHE_ENABLED
PMEMORY_CACHE_ENTRY MmCachedPages = NULL;
#endif

SIZE_T MmMdlCount = 0;
SIZE_T MmMdlAllocatedCount = 0;

BOOL InternalErrorCode = FALSE;

BOOL
NextXpressBlock(
    HANDLE Handle,
    PULARGE_INTEGER XpressHdr
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
    ULONG CompressedSize, NumberOfUncompressedPages;
    ULONG Info;

    UCHAR xprs[XPRESS_HEADER_SIZE];

    BOOL Ret;

    Ret = TRUE;

    if (ReadFileAsynchronous(Handle, *XpressHdr, xprs, XPRESS_HEADER_SIZE) == FALSE)
    {
        Ret = FALSE;
        goto finish;
    }

    if (memcmp(xprs, XPRESS_MAGIC, XPRESS_MAGIC_SIZE) != 0)
    {
        Ret = FALSE;
        goto finish;
    }

    Info = xprs[XPRESS_MAGIC_SIZE + 0];
    Info |= (xprs[XPRESS_MAGIC_SIZE + 1]) << 8;
    Info |= (xprs[XPRESS_MAGIC_SIZE + 2]) << 16;
    Info |= (xprs[XPRESS_MAGIC_SIZE + 3]) << 24;

    CompressedSize = ((Info >> 10) + 1);
    NumberOfUncompressedPages = ((Info & 0x3ff) + 1);

    if (CompressedSize == (NumberOfUncompressedPages * PAGE_SIZE))
    {
#if DEBUG_ENABLED
        wprintf(L"[?] Buffer is not compressed at 0x%08X%08X. (%d)\n",
            XpressHdr->HighPart, XpressHdr->LowPart, CompressedSize);
#endif
    }

    CompressedSize = (CompressedSize + (XPRESS_ALIGNMENT - 1)) & ~(XPRESS_ALIGNMENT - 1);
    XpressHdr->QuadPart += (CompressedSize + XPRESS_HEADER_SIZE);

    if (ReadFileAsynchronous(Handle, *XpressHdr, xprs, XPRESS_HEADER_SIZE) == FALSE)
    {
        Ret = FALSE;
        goto finish;
    }

    if (memcmp(xprs, XPRESS_MAGIC, XPRESS_MAGIC_SIZE) != 0)
    {
        Ret = FALSE;
        goto finish;
    }

    g_LastValidXpressBlock = *XpressHdr;
    Ret = TRUE;

finish:
    return Ret;
}

BOOL
MmExtractSlackBlocks(
    HANDLE hHandle,
    LPWSTR OutputDir,
    PULONG SlackBlockCount
    )
{
    BOOL Ret = FALSE;
    ULARGE_INTEGER Offset = g_LastValidXpressBlock;
    ULARGE_INTEGER FileSize = {0};
    UCHAR xprs[XPRESS_HEADER_SIZE] = {0};

    PVOID Buffer = NULL;
    ULONG BufferSize = 0x10 * PAGE_SIZE;

    ULONG SlackBlocks = 0;

    WCHAR DstPath[MAX_PATH + 1];

    HANDLE hOutput = NULL;

    if (Offset.QuadPart == 0)
    {
        wprintf (L" -> No slack blocks detected.\n");
        return FALSE;
    }

    FileSize.LowPart = GetFileSize(hHandle, &FileSize.HighPart) ;

    Buffer = malloc(BufferSize);
    if (Buffer == NULL) goto CleanUp;

    for (Offset.QuadPart = (g_LastValidXpressBlock.QuadPart + XPRESS_HEADER_SIZE);
         Offset.QuadPart < FileSize.QuadPart;
         Offset.QuadPart += XPRESS_HEADER_SIZE)
    {
        if ((Ret = ReadFileAsynchronous(hHandle, Offset, xprs, XPRESS_HEADER_SIZE)) == FALSE)
        {
            Ret = FALSE;
            goto CleanUp;
        }

        if (memcmp(xprs, XPRESS_MAGIC, XPRESS_MAGIC_SIZE) != 0)
        {
            Ret = FALSE;
            InternalErrorCode = TRUE;

            continue;
        }

        SlackBlocks += 1;

        Ret = MmReadXpressBlock(hHandle, NULL, 0, Offset, Buffer, BufferSize, 0, NULL);
        if (Ret == FALSE) goto CleanUp;

        swprintf_s(DstPath,
                   sizeof(DstPath) / sizeof(DstPath[0]),
                   L"%s\\%x%x.bin", OutputDir, Offset.HighPart, Offset.LowPart);
        White(L"    -> Writing %x%x.bin\n", Offset.HighPart, Offset.LowPart);

        hOutput = CreateFile(DstPath,
                            GENERIC_WRITE,
                            0,
                            NULL,
                            CREATE_ALWAYS,
                            FILE_ATTRIBUTE_NORMAL,
                            NULL);
        if (hOutput == INVALID_HANDLE_VALUE)
        {
            Red(L"  -> Error: Can't create destination file (%s).\n", DstPath);
            goto CleanUp;
        }

        Ret = WriteFileSynchronous(hOutput, Buffer, BufferSize);
        if (Ret == FALSE) goto CleanUp;

        CloseHandle(hOutput);
    }

    if (SlackBlocks) Ret = TRUE;
    *SlackBlockCount = SlackBlocks;

CleanUp:
    if (hOutput) CloseHandle(hOutput);
    if (Buffer) free(Buffer);

    return Ret;
}

BOOL
MmInitializeMdl(
    HANDLE Handle,
    FILE_TYPE Type
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
BOOL Ret;

    Ret = FALSE;

    MmMdlAvailable = (PMEMORY_DESCRIPTOR_LIST)malloc(MDL_COUNT * sizeof(MEMORY_DESCRIPTOR_LIST));
    if (MmMdlAvailable == NULL)
    {
        return FALSE;
    }

#if CACHE_ENABLED
    // MmCachedPages = LocalAlloc(LPTR, MAX_CACHED_PAGES * sizeof(MEMORY_CACHE_ENTRY));
    MmCachedPages = (PMEMORY_CACHE_ENTRY)malloc(MAX_CACHED_PAGES * sizeof(MEMORY_CACHE_ENTRY));
    RtlZeroMemory(MmCachedPages, MAX_CACHED_PAGES * sizeof(MEMORY_CACHE_ENTRY));

    if (MmCachedPages == NULL)
    {
        Ret = FALSE;
    }
#endif

    MmMdlAllocatedCount = MDL_COUNT;

    White(L"Initializing memory descriptors... ");
    switch (Type)
    {
        case TypeRaw:
            Ret = MmRawInitializeMdl(Handle);
        break;
        case TypeDmp:
            Ret = MmDmpInitializeMdl(Handle);
        break;
        case TypeHibr:
            Ret = MmHibrInitializeMdl(Handle);
        break;
        default:
            wprintf(L"");
        break;
    }

    if (Ret == TRUE)
    {
        Green(L"Done.\n");
    }
    else
    {
        Red(L"Failed.\n");
    }

    if (Ret == FALSE)
    {
        MmDestroyMdl();
    }

    return Ret;
}

BOOL
MmAddMdlEntry(
    ULARGE_INTEGER Min,
    ULARGE_INTEGER Max,
    ULARGE_INTEGER Base,
    ULONG XpressIndex,
    ULONG CompressedSize,
    BOOL IsCompressed
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
PMEMORY_DESCRIPTOR_LIST Mdl;

BOOL Status;

    Status = FALSE;

    if ((MmMdlCount + 1) >= MmMdlAllocatedCount)
    {
        ULONG MdlSizeToAlloc;

        if (!SUCCEEDED(ULongAdd((ULONG)MmMdlAllocatedCount, MDL_COUNT, (PULONG)&MmMdlAllocatedCount)))
        {
            wprintf(L"Really ? \n");
            Status = FALSE;
            goto finish;
        }

        if (!SUCCEEDED(ULongMult((ULONG)MmMdlAllocatedCount, sizeof(MEMORY_DESCRIPTOR_LIST), (PULONG)&MdlSizeToAlloc)))
        {
            wprintf(L"Really ? \n");
            Status = FALSE;
            goto finish;
        }

        if ((Mdl = (PMEMORY_DESCRIPTOR_LIST)malloc(MdlSizeToAlloc)) == NULL)
        {
#if DEBUG_ENABLED
            wprintf(L"Failed to realloc. %p Err=%d\n",
                MmMdlAvailable,
                GetLastError());
#endif

            Status = FALSE;
            goto finish;
        }

        memcpy_s(Mdl,
                 MmMdlAllocatedCount * sizeof(MEMORY_DESCRIPTOR_LIST),
                 MmMdlAvailable,
                 MmMdlCount * sizeof(MEMORY_DESCRIPTOR_LIST));

        // LocalFree(MmMdlAvailable);
        free(MmMdlAvailable);
        MmMdlAvailable = Mdl;
        Mdl = NULL;
    }

    Mdl = &MmMdlAvailable[MmMdlCount];

    Mdl->MemoryDescriptor.IsCompressed = IsCompressed;

    if (IsCompressed == FALSE)
    {
        Mdl->MemoryDescriptor.Uncompressed.BaseOffset = Base;
    }
    else
    {
        if (CompressedSize)
        {
            Mdl->MemoryDescriptor.NoHeader = TRUE;
            Mdl->MemoryDescriptor.CompressedSize = CompressedSize;
        }

        Mdl->MemoryDescriptor.Compressed.XpressHeader = Base;
        Mdl->MemoryDescriptor.Compressed.XpressIndex = (XpressIndex % 0x10);
    }

    Mdl->MemoryDescriptor.Range.Maximum = Max;
    Mdl->MemoryDescriptor.Range.Minimum = Min;
    Mdl->MemoryDescriptor.PageCount = (ULONG)((Max.QuadPart - Min.QuadPart) / PAGE_SIZE);

    if (Mdl->MemoryDescriptor.Range.Maximum.QuadPart > MmMaximumPhysicalAddress.QuadPart)
    {
        MmMaximumPhysicalAddress = Mdl->MemoryDescriptor.Range.Maximum;
        MmMaximumPhysicalPage = (ULONG)(MmMaximumPhysicalAddress.QuadPart / PAGE_SIZE);
    }

#if MM_GENERIC
    //
    // Goto last Mdl
    //
    for (Mdl = MmMdlAvailable;
         Mdl->Entry.Flink;
         Mdl = (PMEMORY_DESCRIPTOR_LIST)Mdl->Entry.Flink)
    {
#if 0
        wprintf(L"[%p-0x%I64X] ",
            Mdl, Mdl->MemoryDescriptor.Range.Minimum.QuadPart);
#endif
    }

    if (MmMdlCount == 0)
    {
        Mdl->Entry.Flink = NULL;
        Mdl->Entry.Blink = NULL;
    }
    else
    {
        if ((MmMdlCount + 1) >= MmMdlAllocatedCount)
        {
            Status = FALSE;
            goto finish;

            //
            // We now initialize 0x100000 MDLs which is around 24Mb.
            // FIXME.
            //

            //
            // BUG: Int overflow. Should not be reached, because hibernation file is only 4GB max.
            // But anyway. FIXME.
            //
            wprintf(L"Count %x\n", MmMdlAllocatedCount);
            if (!SUCCEEDED(ULongAdd(MmMdlAllocatedCount, MDL_COUNT, &MmMdlAllocatedCount)))
            {
                wprintf(L"Really ? \n");
                Status = FALSE;
                goto finish;
            }
            wprintf(L"Count %x\n", MmMdlAllocatedCount);
            wprintf(L"Before LocalRealloc MmMdlAvailable at %p\n", MmMdlAvailable);
#if 0
            //
            // BUGBUG: Re-write homemade LocalReAlloc to fix offsets of FLink and BLink
            //
            if ((MmMdlAvailable = LocalReAlloc(MmMdlAvailable,
                                               MmMdlAllocatedCount * sizeof(MEMORY_DESCRIPTOR_LIST),
                                               LHND)) == NULL)
#endif
#if 1
            if ((MmMdlAvailable = HeapReAlloc(GetProcessHeap(),
                                              HEAP_ZERO_MEMORY | HEAP_REALLOC_IN_PLACE_ONLY,
                                              MmMdlAvailable,
                                              MmMdlAllocatedCount * sizeof(MEMORY_DESCRIPTOR_LIST))) == NULL)
#endif
            {
                wprintf(L"Failed to realloc. %p Err=%d\n",
                    MmMdlAvailable,
                    GetLastError());

                Status = FALSE;
                goto finish;
            }

            wprintf(L"LocalRealloc(0x%x) new offset of MmMdlAvailable at %p\n", MmMdlAllocatedCount, MmMdlAvailable);
        }

        Mdl->Entry.Flink = (PLIST_ENTRY)(Mdl + 1);
        PrevMdl = Mdl;
        Mdl = (PMEMORY_DESCRIPTOR_LIST)Mdl->Entry.Flink;

        if (Mdl == NULL)
        {
            Status = FALSE;
            goto finish;
        }

        Mdl->Entry.Blink = (PLIST_ENTRY)PrevMdl;
        Mdl->Entry.Flink = NULL;
    }

    Mdl->MemoryDescriptor.IsCompressed = IsCompressed;

    if (IsCompressed == FALSE)
    {
        Mdl->MemoryDescriptor.Uncompressed.BaseOffset = Base;
    }
    else
    {
        if (CompressedSize)
        {
            Mdl->MemoryDescriptor.NoHeader = TRUE;
            Mdl->MemoryDescriptor.CompressedSize = CompressedSize;
        }

        Mdl->MemoryDescriptor.Compressed.XpressHeader = Base;
        Mdl->MemoryDescriptor.Compressed.XpressIndex = (XpressIndex % 0x10);
    }

    Mdl->MemoryDescriptor.Range.Maximum = Max;
    Mdl->MemoryDescriptor.Range.Minimum = Min;
    Mdl->MemoryDescriptor.PageCount = (ULONG)((Max.QuadPart - Min.QuadPart) / PAGE_SIZE);
#if MM_GENERIC
    Mdl->Head = (PLIST_ENTRY)MmMdlAvailable;
#endif
    if (Mdl->MemoryDescriptor.Range.Maximum.QuadPart > MmMaximumPhysicalAddress.QuadPart)
    {
        MmMaximumPhysicalAddress = Mdl->MemoryDescriptor.Range.Maximum;
        MmMaximumPhysicalPage = (ULONG)(MmMaximumPhysicalAddress.QuadPart / PAGE_SIZE);
    }

#endif 

    MmMdlCount += 1;

    Status = TRUE;

finish:
    return Status;
}

BOOL
MmRawInitializeMdl(
    HANDLE Handle
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
ULARGE_INTEGER Min, Max, Base;
BOOL Ret;

    Base.QuadPart = 0;
    Min.QuadPart = 0;
    Max.LowPart = GetFileSize(Handle, &Max.HighPart);

    if (GetLastError() != NO_ERROR)
    {
        if (GetLastError() != ERROR_IO_PENDING)
        {
#if DEBUG_ENABLED
            wprintf(L"Cannot get file size. (err=%d)\n", GetLastError());
#endif
            InternalErrorCode = TRUE;
            return FALSE;
        }
        else
        {
            OVERLAPPED Overlapped = {0};
            ULONG NbOfBytes = 0;

            Ret = GetOverlappedResult(Handle,
                                      &Overlapped,
                                      &NbOfBytes,
                                      TRUE);
        }

        if (Ret == FALSE) return Ret;
    }

    return MmAddMdlEntry(Min, Max, Base, 0UL, 0, FALSE);
}

BOOL
MmMemoryRangeArrayv1_x86(
    HANDLE Handle,
    ULARGE_INTEGER XpressHeaderAddr,
    PVOID pRangeArray
)
{
    ULONGLONG NextTable;
    ULONG i;

    UCHAR xprs[XPRESS_HEADER_SIZE];
    ULARGE_INTEGER Addr, XpressHeader;
    BOOL Ret = FALSE;

    PUCHAR m = NULL;

    PPO_MEMORY_RANGE_ARRAY32 RangeArray = (PPO_MEMORY_RANGE_ARRAY32)pRangeArray;

    if ((m = (PUCHAR)malloc(PAGE_SIZE + (PAGE_SIZE * 0x10))) == NULL)
    {
        InternalErrorCode = TRUE;
        goto finish;
    }

    XpressHeader = XpressHeaderAddr;
    NextTable = RangeArray->Link.NextTable;

    while (TRUE)
    {
        ULONG XpressIndex = 0;

#if DEBUG_ENABLED
        wprintf(L"++ Count: %d\n", RangeArray->Link.EntryCount);
#endif

        for (i = 0; i < RangeArray->Link.EntryCount; i += 1)
        {
            PPO_MEMORY_RANGE_ARRAY_RANGE32 Range;
            ULONG PagesCount, PageIndex;

            Range = &RangeArray->Range[i];
            PagesCount = Range->EndPage - Range->StartPage;

            for (PageIndex = 0; PageIndex < PagesCount; PageIndex += 1)
            {
                ULARGE_INTEGER Min, Max;

                if (XpressIndex && ((XpressIndex % 0x10) == 0))
                {
                    if ((Ret = NextXpressBlock(Handle, &XpressHeader)) == FALSE)
                    {
                        InternalErrorCode = TRUE;
#if DEBUG_ENABLED
                        wprintf(L"[%d:%d] PageIndex: %d vs PagesCount: %d\n",
                                i, RangeArray->Link.EntryCount,
                                PageIndex, PagesCount);
#endif
                        goto finish;
                    }
                }

                Min.QuadPart = ((ULONGLONG)Range->StartPage + PageIndex) * PAGE_SIZE;
                Max.QuadPart = ((ULONGLONG)Range->StartPage + PageIndex + 1) * PAGE_SIZE;

                if ((Ret = MmAddMdlEntry(Min, Max, XpressHeader, XpressIndex, 0, TRUE)) == FALSE)
                {
                    InternalErrorCode = TRUE;
                    goto finish;
                }

                XpressIndex += 1;
            }
        }

        if (NextTable == 0) break;
        //
        // In case NextTable has an invalid value, we check if the table hasn't max up the nb of entries.
        //
        // if (RangeArray->Link.EntryCount != 0xff) break;

        Addr.QuadPart = NextTable * PAGE_SIZE;
        if ((Ret = ReadFileAsynchronous(Handle, Addr, m, PAGE_SIZE)) == FALSE)
        {
            InternalErrorCode = TRUE;
            goto finish;
        }
        RangeArray = (PPO_MEMORY_RANGE_ARRAY32)m;

        //
        // Next Xpress Block
        //
        XpressHeader.QuadPart = ((ULONGLONG)NextTable + 1) * PAGE_SIZE;
        if ((Ret = ReadFileAsynchronous(Handle, XpressHeader, xprs, XPRESS_HEADER_SIZE)) == FALSE)
        {
            InternalErrorCode = TRUE;
#if DEBUG_ENABLED
            wprintf(L"ReadFileAsynchronous(Xpress) = FALSE;\n");
#endif
            goto finish;
        }

        if (memcmp(xprs, XPRESS_MAGIC, XPRESS_MAGIC_SIZE) != 0)
        {
            Ret = FALSE;
            InternalErrorCode = TRUE;

#if DEBUG_ENABLED
            wprintf(L"(Xpress magic code = FALSE %I64X;\n", XpressHeader.QuadPart);
#endif
            break; // goto finish;
        }

        XpressIndex = 0;
        NextTable = RangeArray->Link.NextTable;
    }

    Ret = TRUE;

finish:
    if (m) free(m);
    return Ret;
}

BOOL
MmMemoryRangeArrayv1_x64(
    HANDLE Handle,
    ULARGE_INTEGER XpressHeaderAddr,
    PVOID pRangeArray
)
{
    ULONGLONG NextTable;
    ULONG i;

    PUCHAR m = NULL;

    UCHAR xprs[XPRESS_HEADER_SIZE];
    ULARGE_INTEGER Addr, XpressHeader;
    BOOL Ret = FALSE;

    PPO_MEMORY_RANGE_ARRAY64_NT52 RangeArray64 = (PPO_MEMORY_RANGE_ARRAY64_NT52)pRangeArray;

    if ((m = (PUCHAR)malloc(PAGE_SIZE + (PAGE_SIZE * 0x10))) == NULL)
    {
        InternalErrorCode = TRUE;
        goto finish;
    }

#if DEBUG_ENABLED
    wprintf(L"NT 52 x64\n");
#endif

    XpressHeader = XpressHeaderAddr;
    NextTable = RangeArray64->Link.NextTable;

    while (TRUE)
    {
        ULONG XpressIndex = 0;

#if DEBUG_ENABLED
        wprintf(L"++ Count: %d\n", RangeArray64->Link.EntryCount);
#endif

        for (i = 0; i < RangeArray64->Link.EntryCount; i += 1)
        {
            PPO_MEMORY_RANGE_ARRAY_RANGE64_NT52 Range;
            ULONGLONG PagesCount, PageIndex;

            Range = &RangeArray64->Range[i];
            PagesCount = Range->EndPage - Range->StartPage;

            for (PageIndex = 0; PageIndex < PagesCount; PageIndex += 1)
            {
                ULARGE_INTEGER Min, Max;

                if (XpressIndex && ((XpressIndex % 0x10) == 0))
                {
                    if ((Ret = NextXpressBlock(Handle, &XpressHeader)) == FALSE)
                    {
                        InternalErrorCode = TRUE;
#if DEBUG_ENABLED
                        wprintf(L"[%d:%d] PageIndex: %I64X vs PagesCount: %I64X\n",
                                i, RangeArray64->Link.EntryCount,
                                PageIndex, PagesCount);
#endif
                        goto finish;
                    }
                }

                Min.QuadPart = ((ULONGLONG)Range->StartPage + PageIndex) * PAGE_SIZE;
                Max.QuadPart = ((ULONGLONG)Range->StartPage + PageIndex + 1) * PAGE_SIZE;

                if ((Ret = MmAddMdlEntry(Min, Max, XpressHeader, XpressIndex, 0, TRUE)) == FALSE)
                {
                    InternalErrorCode = TRUE;
                    goto finish;
                }

                XpressIndex += 1;
            }
        }

        if (NextTable == 0) break;
        // if (RangeArray64->Link.EntryCount != 0x7F) break;

        Addr.QuadPart = NextTable * PAGE_SIZE;

        if ((Ret = ReadFileAsynchronous(Handle, Addr, m, PAGE_SIZE)) == FALSE)
        {
            InternalErrorCode = TRUE;
            goto finish;
        }

        RangeArray64 = (PPO_MEMORY_RANGE_ARRAY64_NT52)m;

        //
        // Next Xpress Block
        //
        XpressHeader.QuadPart = ((ULONGLONG)NextTable + 1) * PAGE_SIZE;
        if ((Ret = ReadFileAsynchronous(Handle, XpressHeader, xprs, XPRESS_HEADER_SIZE)) == FALSE)
        {
            InternalErrorCode = TRUE;
#if DEBUG_ENABLED
            wprintf(L"ReadFileAsynchronous(Xpress) = FALSE;\n");
#endif
            goto finish;
        }

        if (memcmp(xprs, XPRESS_MAGIC, XPRESS_MAGIC_SIZE) != 0)
        {
            Ret = FALSE;
            InternalErrorCode = TRUE;
#if DEBUG_ENABLED
            wprintf(L"(Xpress magic code = FALSE %I64X;\n", XpressHeader.QuadPart);
#endif
            break; // goto finish;
        }

        NextTable = RangeArray64->Link.NextTable;
    }

    Ret = TRUE;

finish:
    if (m) free(m);
    return Ret;
}

BOOL
MmMemoryRangeArrayv2_x64(
    HANDLE Handle,
    ULARGE_INTEGER XpressHeaderAddr,
    PVOID pRangeArray
)
{
    ULONGLONG NextTable;
    ULONG i;

    PUCHAR m = NULL;

    UCHAR xprs[XPRESS_HEADER_SIZE];
    ULARGE_INTEGER Addr, XpressHeader;
    BOOL Ret = FALSE;
    PPO_MEMORY_RANGE_ARRAY64 RangeArray64 = (PPO_MEMORY_RANGE_ARRAY64)pRangeArray;

#if DEBUG_ENABLED
    wprintf(L"NT 60 x64\n");
#endif

    if ((m = (PUCHAR)malloc(PAGE_SIZE + (PAGE_SIZE * 0x10))) == NULL)
    {
        InternalErrorCode = TRUE;
        goto finish;
    }

    XpressHeader = XpressHeaderAddr;
    NextTable = RangeArray64->Link.NextTable;

    while (TRUE)
    {
        ULONG XpressIndex = 0;
#if DEBUG_ENABLED
        wprintf(L"++ Count: %d\n", RangeArray64->Link.EntryCount);
#endif

        for (i = 0; i < RangeArray64->Link.EntryCount; i += 1)
        {
            PPO_MEMORY_RANGE_ARRAY_RANGE64 Range;
            ULONGLONG PagesCount, PageIndex;

            Range = &RangeArray64->Range[i];
            PagesCount = Range->EndPage - Range->StartPage;

            for (PageIndex = 0; PageIndex < PagesCount; PageIndex += 1)
            {
                ULARGE_INTEGER Min, Max;

                if (XpressIndex && ((XpressIndex % 0x10) == 0))
                {
                    if (NextXpressBlock(Handle, &XpressHeader) == FALSE)
                    {
                        Ret = FALSE;
                        InternalErrorCode = TRUE;
#if DEBUG_ENABLED
                        wprintf(L"[%d:%d] PageIndex: %d vs PagesCount: %d\n",
                                i, RangeArray64->Link.EntryCount,
                                PageIndex, PagesCount);
#endif
                        goto finish;
                    }
                }

                Min.QuadPart = ((ULONGLONG)Range->StartPage + PageIndex) * PAGE_SIZE;
                Max.QuadPart = ((ULONGLONG)Range->StartPage + PageIndex + 1) * PAGE_SIZE;

                if ((Ret = MmAddMdlEntry(Min, Max, XpressHeader, XpressIndex, 0, TRUE)) == FALSE)
                {
                    InternalErrorCode = TRUE;
                    goto finish;
                }

                XpressIndex += 1;
            }
        }

        if (NextTable == 0) break;
        // if (RangeArray64->Link.EntryCount != 0xFE) break;

        Addr.QuadPart = NextTable * PAGE_SIZE;

        if ((Ret = ReadFileAsynchronous(Handle, Addr, m, PAGE_SIZE)) == FALSE)
        {
            InternalErrorCode = TRUE;
            goto finish;
        }

        RangeArray64 = (PPO_MEMORY_RANGE_ARRAY64)m;

        //
        // Next Xpress Block
        //
        XpressHeader.QuadPart = ((ULONGLONG)NextTable + 1) * PAGE_SIZE;
        if ((Ret = ReadFileAsynchronous(Handle, XpressHeader, xprs, XPRESS_HEADER_SIZE)) == FALSE)
        {
            InternalErrorCode = TRUE;
#if DEBUG_ENABLED
            wprintf(L"ReadFileAsynchronous(Xpress) = FALSE;\n");
#endif
            goto finish;
        }

        if (memcmp(xprs, XPRESS_MAGIC, XPRESS_MAGIC_SIZE) != 0)
        {
            Ret = FALSE;
            InternalErrorCode = TRUE;
#if DEBUG_ENABLED
            wprintf(L"(Xpress magic code = FALSE %I64X;\n", XpressHeader.QuadPart);
#endif
            break; // goto finish;
        }

        NextTable = RangeArray64->Link.NextTable;
    }
    Ret = TRUE;

finish:
    if (m) free(m);
    return Ret;
}

BOOL
MmMemoryRangeArrayv2_x86(
    HANDLE Handle,
    ULARGE_INTEGER XpressHeaderAddr,
    PVOID pRangeArray
)
{
    ULONGLONG NextTable;
    ULONG i;

    PUCHAR m = NULL;

    UCHAR xprs[XPRESS_HEADER_SIZE];
    ULARGE_INTEGER Addr, XpressHeader;
    BOOL Ret = FALSE;
    PPO_MEMORY_RANGE_ARRAY32_NT61 RangeArrayWin7 = (PPO_MEMORY_RANGE_ARRAY32_NT61)pRangeArray;

    if ((m = (PUCHAR)malloc(PAGE_SIZE + (PAGE_SIZE * 0x10))) == NULL)
    {
        InternalErrorCode = TRUE;
        goto finish;
    }

    XpressHeader = XpressHeaderAddr;
    NextTable = RangeArrayWin7->Link.NextTable;

    while (TRUE)
    {
        ULONG XpressIndex = 0;

#if DEBUG_ENABLED
        wprintf(L"++ Count: %d\n", RangeArrayWin7->Link.EntryCount);
#endif

        for (i = 0; i < RangeArrayWin7->Link.EntryCount; i += 1)
        {
            PPO_MEMORY_RANGE_ARRAY_RANGE32_NT61 Range;
            ULONG PagesCount, PageIndex;

            Range = &RangeArrayWin7->Range[i];
            PagesCount = Range->EndPage - Range->StartPage;

            for (PageIndex = 0; PageIndex < PagesCount; PageIndex += 1)
            {
                ULARGE_INTEGER Min, Max;

                if (XpressIndex && ((XpressIndex % 0x10) == 0))
                {
                    if ((Ret = NextXpressBlock(Handle, &XpressHeader)) == FALSE)
                    {
                        InternalErrorCode = TRUE;

#if DEBUG_ENABLED
                        wprintf(L"[%d:%d] PageIndex: %d vs PagesCount: %d\n",
                                i, RangeArrayWin7->Link.EntryCount,
                                PageIndex, PagesCount);
#endif
                        goto finish;
                    }
                }

                Min.QuadPart = ((ULONGLONG)Range->StartPage + PageIndex) * PAGE_SIZE;
                Max.QuadPart = ((ULONGLONG)Range->StartPage + PageIndex + 1) * PAGE_SIZE;

                if ((Ret = MmAddMdlEntry(Min, Max, XpressHeader, XpressIndex, 0, TRUE)) == FALSE)
                {
                    InternalErrorCode = TRUE;
                    goto finish;
                }

                XpressIndex += 1;
            }
        }

        if (NextTable == 0) break;
        // if (RangeArrayWin7->Link.EntryCount != 0x1FF) break;

        Addr.QuadPart = NextTable * PAGE_SIZE;
        if ((Ret = ReadFileAsynchronous(Handle, Addr, m, PAGE_SIZE)) == FALSE)
        {
            InternalErrorCode = TRUE;
            goto finish;
        }

        RangeArrayWin7 = (PPO_MEMORY_RANGE_ARRAY32_NT61)m;

        //
        // Next Xpress Block
        //
        XpressHeader.QuadPart = ((ULONGLONG)NextTable + 1) * PAGE_SIZE;
        if ((Ret = ReadFileAsynchronous(Handle, XpressHeader, xprs, XPRESS_HEADER_SIZE)) == FALSE)
        {
            InternalErrorCode = TRUE;
#if DEBUG_ENABLED
            wprintf(L"ReadFileAsynchronous(Xpress) = FALSE;\n");
#endif
            goto finish;
        }

        if (memcmp(xprs, XPRESS_MAGIC, XPRESS_MAGIC_SIZE) != 0)
        {
            Ret = FALSE;
            InternalErrorCode = TRUE;
#if DEBUG_ENABLED
            wprintf(L"(Xpress magic code = FALSE %I64X;\n", XpressHeader.QuadPart);
#endif
            break;
            // goto finish;
        }

        NextTable = RangeArrayWin7->Link.NextTable;
    }

    Ret = TRUE;

finish:
    if (m) free(m);
    return Ret;
}

BOOL
MmMemoryRangeArrayv3_x64(
    HANDLE Handle,
    ULARGE_INTEGER XpressHeaderAddr,
    PVOID pRangeArray
)
{
    ULONGLONG NextTable;
    ULONG i;

    PUCHAR m = NULL;

    UCHAR xprs[XPRESS_HEADER_SIZE];
    ULARGE_INTEGER Addr, XpressHeader;
    BOOL Ret = FALSE;
    PPO_MEMORY_RANGE_ARRAY64_NT61 RangeArray64Win7 = (PPO_MEMORY_RANGE_ARRAY64_NT61)pRangeArray;

    if ((m = (PUCHAR)malloc(PAGE_SIZE + (PAGE_SIZE * 0x10))) == NULL)
    {
        InternalErrorCode = TRUE;
        goto finish;
    }

    XpressHeader = XpressHeaderAddr;
    NextTable = RangeArray64Win7->Link.NextTable;

#if DEBUG_ENABLED
    wprintf(L"NT 6.1 x64\n");
#endif

    while (TRUE)
    {
        ULONG XpressIndex = 0;

#if DEBUG_ENABLED
        wprintf(L"++ Count: %d\n", RangeArray64Win7->Link.EntryCount);
#endif

        for (i = 0; i < RangeArray64Win7->Link.EntryCount; i += 1)
        {
            PPO_MEMORY_RANGE_ARRAY_RANGE64_NT61 Range;
            ULONGLONG PagesCount, PageIndex;

            Range = &RangeArray64Win7->Range[i];
            PagesCount = Range->EndPage - Range->StartPage;

            for (PageIndex = 0; PageIndex < PagesCount; PageIndex += 1)
            {
                ULARGE_INTEGER Min, Max;

                if (XpressIndex && ((XpressIndex % 0x10) == 0))
                {
                    if ((Ret = NextXpressBlock(Handle, &XpressHeader)) == FALSE)
                    {
                        InternalErrorCode = TRUE;

#if DEBUG_ENABLED
                        wprintf(L"[%d:%d] PageIndex: %d vs PagesCount: %d\n",
                                i, RangeArray64Win7->Link.EntryCount,
                                PageIndex, PagesCount);
#endif
                        goto finish;
                    }
                }

                Min.QuadPart = ((ULONGLONG)Range->StartPage + PageIndex) * PAGE_SIZE;
                Max.QuadPart = ((ULONGLONG)Range->StartPage + PageIndex + 1) * PAGE_SIZE;

                if ((Ret = MmAddMdlEntry(Min, Max, XpressHeader, XpressIndex, 0, TRUE)) == FALSE)
                {
                    InternalErrorCode = TRUE;
                    goto finish;
                }

                XpressIndex += 1;
            }
        }

        if (NextTable == 0) break;

        Addr.QuadPart = NextTable * PAGE_SIZE;
        if ((Ret = ReadFileAsynchronous(Handle, Addr, m, PAGE_SIZE)) == FALSE)
        {
            InternalErrorCode = TRUE;
            goto finish;
        }

        RangeArray64Win7 = (PPO_MEMORY_RANGE_ARRAY64_NT61)m;

        //
        // Next Xpress Block
        //
        XpressHeader.QuadPart = ((ULONGLONG)NextTable + 1) * PAGE_SIZE;
        if ((Ret = ReadFileAsynchronous(Handle, XpressHeader, xprs, XPRESS_HEADER_SIZE)) == FALSE)
        {
            InternalErrorCode = TRUE;
#if DEBUG_ENABLED
            wprintf(L"ReadFileAsynchronous(Xpress) = FALSE;\n");
#endif
            goto finish;
        }

        if (memcmp(xprs, XPRESS_MAGIC, XPRESS_MAGIC_SIZE) != 0)
        {
            Ret = FALSE;
            InternalErrorCode = TRUE;

#if DEBUG_ENABLED
            wprintf(L"(Xpress magic code = FALSE %I64X;\n", XpressHeader.QuadPart);
#endif
            break; // goto finish;
        }

        NextTable = RangeArray64Win7->Link.NextTable;
    }

    Ret = TRUE;

finish:
    if (m) free(m);
    return Ret;
}

BOOL
MmMemoryRangeArrayv3_x86(
    HANDLE Handle,
    ULARGE_INTEGER XpressHeaderAddr,
    PVOID pRangeArray
)
{
    ULONGLONG NextTable;
    ULONG RangeIndex;

    PUCHAR m = NULL;

    ULARGE_INTEGER Addr, XpressHeader;
    BOOL Ret = FALSE;
    PPO_MEMORY_RANGE_TABLE32_NT62 RangeArray32Win8 = (PPO_MEMORY_RANGE_TABLE32_NT62)pRangeArray;

    if ((m = (PUCHAR)malloc(PAGE_SIZE + (PAGE_SIZE * 0x10))) == NULL)
    {
        InternalErrorCode = TRUE;
        goto finish;
    }

    XpressHeader = XpressHeaderAddr;
#if DEBUG_ENABLED
    wprintf(L"NT 6.2 x86\n");
#endif
    // hardcoded
    NextTable = 0x7 * PAGE_SIZE; //RangeArray32Win8;
    // NextTable += sizeof(PO_MEMORY_RANGE_TABLE32_NT62);
    // NextTable += ((RangeArray32Win8->RangeCount - 1) * sizeof(PO_MEMORY_RANGE32_NT62));
    // NextTable += RangeArray32Win8->CompressedSize;

    while (TRUE)
    {
        ULONG XpressIndex = 0;

#if DEBUG_ENABLED
        wprintf(L"++ Count: %d\n", RangeArray32Win8->RangeCount);
#endif

        if ((RangeArray32Win8->RangeCount > 0x10) || (RangeArray32Win8->RangeCount == 0)) break;

        XpressIndex = 0;

        for (RangeIndex = 0; RangeIndex < RangeArray32Win8->RangeCount; RangeIndex += 1)
        {
            PPO_MEMORY_RANGE32_NT62 Range;
            ULONGLONG PagesCount, PageIndex;

            Range = &RangeArray32Win8->Range[RangeIndex];

            PagesCount = Range->PageCount;
            PagesCount += 1;

            if (PagesCount > 0x10)
            {
                NextTable = 0;
                break;
            }

            XpressHeader.QuadPart = NextTable;
            XpressHeader.QuadPart += sizeof(PO_MEMORY_RANGE_TABLE32_NT62);
            XpressHeader.QuadPart += ((RangeArray32Win8->RangeCount - 1) * sizeof(PO_MEMORY_RANGE32_NT62));

#if DEBUG_ENABLED
            wprintf(L"RangeArray32Win8->CompressedSize %X PageCount %d XpressHeader: %08X%08X\n",
                    RangeArray32Win8->CompressedSize, RangeArray32Win8->RangeCount,
                    XpressHeader.HighPart, XpressHeader.LowPart);
#endif

            for (PageIndex = 0; PageIndex < PagesCount; PageIndex += 1)
            {
                ULARGE_INTEGER Min, Max;
                BOOL IsCompressed;

                Min.QuadPart = ((ULONGLONG)Range->StartPage + PageIndex) * PAGE_SIZE;
                Max.QuadPart = ((ULONGLONG)Range->StartPage + PageIndex + 1) * PAGE_SIZE;

                IsCompressed = (RangeArray32Win8->CompressedSize != (0x10 * PAGE_SIZE));

                if (RangeArray32Win8->CompressMethod != XpressFast)
                {
#if DEBUG_ENABLED
                    wprintf(L"Using something else than XpressFast (%d)\n", RangeArray32Win8->CompressMethod);
#endif
                }

                if (RangeArray32Win8->CompressedSize > 0x10000)
                {
#if DEBUG_ENABLED
                    wprintf(L"RangeArray32Win8->CompressedSize = %X\n", RangeArray32Win8->CompressedSize);
#endif
                    NextTable = 0;
                    break;
                }

                if ((Ret = MmAddMdlEntry(Min, Max, XpressHeader, XpressIndex, RangeArray32Win8->CompressedSize, IsCompressed)) == FALSE)
                {
                    InternalErrorCode = TRUE;
                    goto finish;
                }

                XpressIndex += 1;
            }
        }

        if (NextTable == 0) break;

        NextTable += sizeof(PO_MEMORY_RANGE_TABLE32_NT62);
        NextTable += ((RangeArray32Win8->RangeCount - 1) * sizeof(PO_MEMORY_RANGE32_NT62));
        NextTable += RangeArray32Win8->CompressedSize;

        Addr.QuadPart = NextTable;
        if ((Ret = ReadFileAsynchronous(Handle, Addr, m, PAGE_SIZE + (PAGE_SIZE * 0x10))) == FALSE)
        {
            InternalErrorCode = TRUE;
            goto finish;
        }

        RangeArray32Win8 = (PPO_MEMORY_RANGE_TABLE32_NT62)m;
    }

#if DEBUG_ENABLED
    wprintf(L"Setting the O.S. variables to NT 6.2 x86\n");
#endif

    Ret = TRUE;

finish:
    if (m) free(m);
    return Ret;
}

BOOL
MmMemoryRangeArrayv4_x64(
    HANDLE Handle,
    ULARGE_INTEGER XpressHeaderAddr,
    PVOID pRangeArray
)
{
    ULONGLONG NextTable;
    ULONG RangeIndex;

    PUCHAR m = NULL;

    ULARGE_INTEGER Addr, XpressHeader;
    BOOL Ret = FALSE;
    PPO_MEMORY_RANGE_TABLE64_NT62 RangeArrayWin8 = (PPO_MEMORY_RANGE_TABLE64_NT62)pRangeArray;

    if ((m = (PUCHAR)malloc(PAGE_SIZE + (PAGE_SIZE * 0x10))) == NULL)
    {
        InternalErrorCode = TRUE;
        goto finish;
    }

    XpressHeader = XpressHeaderAddr;
#if DEBUG_ENABLED
    wprintf(L"NT 6.2 x64\n");
#endif
    // hardcoded
    NextTable = 0x7 * PAGE_SIZE; //RangeArray32Win8;
    // NextTable += sizeof(PO_MEMORY_RANGE_TABLE32_NT62_X64);
    // NextTable += ((RangeArrayWin8->RangeCount - 1) * sizeof(PO_MEMORY_RANGE_TABLE32_NT62_X64));
    // NextTable += RangeArrayWin8->CompressedSize;

    while (TRUE)
    {
        ULONG XpressIndex = 0;

#if DEBUG_ENABLED
        wprintf(L"++ Count: %d\n", RangeArrayWin8->RangeCount);
#endif

        if ((RangeArrayWin8->RangeCount > 0x10) || (RangeArrayWin8->RangeCount == 0)) break;

        XpressIndex = 0;

        for (RangeIndex = 0; RangeIndex < RangeArrayWin8->RangeCount; RangeIndex += 1)
        {
            PPO_MEMORY_RANGE64_NT62 Range;
            ULONGLONG PagesCount, PageIndex;

            Range = &RangeArrayWin8->Range[RangeIndex];

            PagesCount = Range->PageCount;
            PagesCount += 1;

            if (PagesCount > 0x10)
            {
                NextTable = 0;
                break;
            }

            XpressHeader.QuadPart = NextTable;
            XpressHeader.QuadPart += sizeof(PO_MEMORY_RANGE_TABLE64_NT62);
            XpressHeader.QuadPart += ((RangeArrayWin8->RangeCount - 1) * sizeof(PO_MEMORY_RANGE64_NT62));

#if DEBUG_ENABLED
            wprintf(L"RangeArray64Win8->CompressedSize %X PageCount %d XpressHeader: %08X%08X\n",
                    RangeArrayWin8->CompressedSize, RangeArrayWin8->RangeCount,
                    XpressHeader.HighPart, XpressHeader.LowPart);
#endif

            for (PageIndex = 0; PageIndex < PagesCount; PageIndex += 1)
            {
                ULARGE_INTEGER Min, Max;
                BOOL IsCompressed;

                Min.QuadPart = ((ULONGLONG)Range->StartPage + PageIndex) * PAGE_SIZE;
                Max.QuadPart = ((ULONGLONG)Range->StartPage + PageIndex + 1) * PAGE_SIZE;

                IsCompressed = (RangeArrayWin8->CompressedSize != (0x10 * PAGE_SIZE));

                if (RangeArrayWin8->CompressMethod != XpressFast)
                {
                    wprintf(L"Using something else than XpressFast (%d)\n", RangeArrayWin8->CompressMethod);
                }

                if (RangeArrayWin8->CompressedSize > 0x10000)
                {
                    wprintf(L"RangeArray32Win8->CompressedSize = %X\n", RangeArrayWin8->CompressedSize);
                    NextTable = 0;
                    break;
                }

                if ((Ret = MmAddMdlEntry(Min, Max, XpressHeader, XpressIndex, RangeArrayWin8->CompressedSize, IsCompressed)) == FALSE)
                {
                    InternalErrorCode = TRUE;
                    goto finish;
                }

                XpressIndex += 1;
            }
        }

        if (NextTable == 0) break;

        NextTable += sizeof(PO_MEMORY_RANGE_TABLE64_NT62);
        NextTable += ((RangeArrayWin8->RangeCount - 1) * sizeof(PO_MEMORY_RANGE64_NT62));
        NextTable += RangeArrayWin8->CompressedSize;

        Addr.QuadPart = NextTable;
        // wprintf(L"Reading at offset 0x%x%x\n", Addr.HighPart, Addr.LowPart);
        Ret = ReadFileAsynchronous(Handle, Addr, m, PAGE_SIZE + (PAGE_SIZE * 0x10));
        if (Ret == FALSE)
        {
            wprintf(L"Error: ReadFileAsynchronous = %x (Offset: 0x%X%x)\n", GetLastError(), Addr.HighPart, Addr.LowPart);
            InternalErrorCode = TRUE;
            goto finish;
        }

        RangeArrayWin8 = (PPO_MEMORY_RANGE_TABLE64_NT62)m;
    }

#if DEBUG_ENABLED
    wprintf(L"Setting the O.S. variables to NT 6.2 x64\n");
#endif

    Ret = TRUE;

finish:
    if (m) free(m);
    return Ret;
}

BOOL
MmHibrInitializeMdl(
    HANDLE Handle
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
ULARGE_INTEGER XpressHeader, Addr;

PPO_MEMORY_RANGE_ARRAY32 RangeArray;

ULONGLONG NextTable;

PUCHAR p;
BOOL Ret;
ULONG i;

BOOL HasXpressTag = FALSE;

    Ret = TRUE;

    if ((p = (PUCHAR)malloc(PAGE_SIZE * 0x10)) == NULL)
    {
        InternalErrorCode = TRUE;
        return FALSE;
    }

    Addr.QuadPart = 0;
    if ((Ret = ReadFileAsynchronous(Handle, Addr, p, PAGE_SIZE * 0x10)) == FALSE)
    {
        InternalErrorCode = TRUE;
        goto finish;
    }

    for (i = 0;
         i < 0x10;
         i += 1)
    {
        if (memcmp(p + (i * PAGE_SIZE), XPRESS_MAGIC, XPRESS_MAGIC_SIZE) == 0)
        {
            HasXpressTag = TRUE;
            break;
        }
    }

#if DEBUG_ENABLED
    wprintf(L"Xpress  : %x\n", i * PAGE_SIZE);
#endif

#if 0
    if (i == 0x10)
    {
        UCHAR Answer;
        Answer = InteractiveQuestion(L"  #1 The version of the hibernation file can't be identified. Do you want to try Windows 8 ?\r\n",
                                     L"      - n No (default)\r\n"
                                     L"      - y Yes\r\n",
                                     L"     [y/n] (default: No) ");
        if (Answer != 'y')
        {
            Ret = FALSE;
            goto finish;
        }

        i = 7;
        NextTable = (i - 1) * PAGE_SIZE;
    }
#endif

    XpressHeader.QuadPart = (i * PAGE_SIZE);
    RangeArray = (PPO_MEMORY_RANGE_ARRAY32)(p + ((i - 1) * PAGE_SIZE));

    if (HasXpressTag)
    {
#if DEBUG_ENABLED
        wprintf(L"Has xpress tag\n");
#endif
        if (RangeArray->Link.EntryCount == 0xff)
        {
            //
            // NT 5.0, 5.1, 5.2, 6.0 x86
            //
#if DEBUG_ENABLED
        wprintf(L"NT 5.1, 5.2, 6.0 x86\n");
#endif

            Ret = MmMemoryRangeArrayv1_x86(Handle, XpressHeader, RangeArray);
            if (!Ret) goto finish;

            g_KiExcaliburData.MachineType = MACHINE_X86;
            g_KiExcaliburData.MajorVersion = 5;
            g_KiExcaliburData.MinorVersion = 1;
        }
        else if (((PPO_MEMORY_RANGE_ARRAY64_NT52)RangeArray)->Link.EntryCount == 0x7F)
        {
            //
            // NT 52 x64
            //
#if DEBUG_ENABLED
        wprintf(L"NT 52 x64\n");
#endif
            Ret = MmMemoryRangeArrayv1_x64(Handle, XpressHeader, RangeArray);
            if (!Ret) goto finish;

            g_KiExcaliburData.MachineType = MACHINE_AMD64;
            g_KiExcaliburData.PaeEnabled = TRUE;
            g_KiExcaliburData.MajorVersion = 5;
            g_KiExcaliburData.MinorVersion = 2;
        }
        else if (((PPO_MEMORY_RANGE_ARRAY64)RangeArray)->Link.EntryCount == 0xFE)
        {
            //
            // NT 6.0 x64
            //
            Ret = MmMemoryRangeArrayv2_x64(Handle, XpressHeader, RangeArray);
            if (!Ret) goto finish;

            g_KiExcaliburData.MachineType = MACHINE_AMD64;
            g_KiExcaliburData.PaeEnabled = TRUE;
            g_KiExcaliburData.MajorVersion = 6;
            g_KiExcaliburData.MinorVersion = 0;
        }
        else if (((PPO_MEMORY_RANGE_ARRAY32_NT61)RangeArray)->Link.EntryCount == 0x1FF)
        {
            //
            // NT 6.1 x86
            //
#if DEBUG_ENABLED
        wprintf(L"NT 6.1 x86\n");
#endif

            Ret = MmMemoryRangeArrayv2_x86(Handle, XpressHeader, RangeArray);
            if (!Ret) goto finish;

            g_KiExcaliburData.MachineType = MACHINE_X86;
            g_KiExcaliburData.MajorVersion = 6;
            g_KiExcaliburData.MinorVersion = 1;
        }
        else if (((PPO_MEMORY_RANGE_ARRAY64_NT61)RangeArray)->Link.EntryCount == 0xFF)
        {
#if DEBUG_ENABLED
        wprintf(L"NT 6.1 x64\n");
#endif
            //
            // NT 6.1 x64
            //
            Ret = MmMemoryRangeArrayv3_x64(Handle, XpressHeader, RangeArray);
            if (!Ret) goto finish;

            g_KiExcaliburData.MachineType = MACHINE_AMD64;
            g_KiExcaliburData.PaeEnabled = TRUE;
            g_KiExcaliburData.MajorVersion = 6;
            g_KiExcaliburData.MinorVersion = 1;
        }
    }
    else
    {
        //
        // Try x64 win8
        //
        i = 8;
        NextTable = (i - 1) * PAGE_SIZE;
        XpressHeader.QuadPart = (i * PAGE_SIZE);
        RangeArray = (PPO_MEMORY_RANGE_ARRAY32)(p + ((i - 1) * PAGE_SIZE));

        //
        // KPROCESSOR_DATA is at the 0x1000 offset. So we check it first.
        //
        if (MmValidationx64KProcState(p + (1 * PAGE_SIZE)))
        {
            if ((((PPO_MEMORY_RANGE_TABLE64_NT62)RangeArray)->RangeCount < 0x10) &&
                (((PPO_MEMORY_RANGE_TABLE64_NT62)RangeArray)->CompressedSize < (PAGE_SIZE * 0x10)) &&
                (((PPO_MEMORY_RANGE_TABLE64_NT62)RangeArray)->CompressMethod == XpressFast))
            {
#if DEBUG_ENABLED
                wprintf(L"MmMemoryRangeArrayv4_x64()\n");
#endif
                Ret = MmMemoryRangeArrayv4_x64(Handle, XpressHeader, RangeArray);
                if (!Ret) goto finish;

                g_KiExcaliburData.MachineType = MACHINE_X64;
                g_KiExcaliburData.MajorVersion = 6;
                g_KiExcaliburData.MinorVersion = 2;
                goto finish;
            }
        }
        else if (MmValidationx86KProcState(Handle, p + (1 * PAGE_SIZE)))
        {
            i = 8;
            NextTable = (i - 1) * PAGE_SIZE;
            XpressHeader.QuadPart = (i * PAGE_SIZE);
            RangeArray = (PPO_MEMORY_RANGE_ARRAY32)(p + ((i - 1) * PAGE_SIZE));

            // wprintf(L"No Xpress header\n");

            //
            // Try x86 win8
            //

            if ((((PPO_MEMORY_RANGE_TABLE32_NT62)RangeArray)->RangeCount < 0x10) &&
                (((PPO_MEMORY_RANGE_TABLE32_NT62)RangeArray)->CompressedSize < (PAGE_SIZE * 0x10)) &&
                (((PPO_MEMORY_RANGE_TABLE32_NT62)RangeArray)->CompressMethod == XpressFast))
            {
#if DEBUG_ENABLED
                wprintf(L"MmMemoryRangeArrayv3_x86()\n");
#endif
                Ret = MmMemoryRangeArrayv3_x86(Handle, XpressHeader, RangeArray);
                if (!Ret) goto finish;

                g_KiExcaliburData.MachineType = MACHINE_X86;
                g_KiExcaliburData.MajorVersion = 6;
                g_KiExcaliburData.MinorVersion = 2;
                goto finish;
            }
        }
    }

#if DEBUG_ENABLED
    wprintf(L"MmMaximumPhysicalAddress: %I64X\n", MmMaximumPhysicalAddress.QuadPart);
#endif

finish:
    if (p) free(p);

    return Ret;
}

BOOL
MmDmpInitializeMdl(
    HANDLE Handle
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
#ifdef PRO_EDITION
PDUMP_HEADER64 Header64;
#endif
PDUMP_HEADER32 Header32;

ULARGE_INTEGER Base;

ULONG Index;

BOOL Ret;

    Ret = FALSE;

    // Header32 = (PDUMP_HEADER32)LocalAlloc(LPTR, sizeof(DUMP_HEADER64));
    Header32 = (PDUMP_HEADER32)malloc(sizeof(DUMP_HEADER64));

    if (Header32 == NULL) return FALSE;

    Base.QuadPart = 0;
    if (ReadFileAsynchronous(Handle, Base, Header32, sizeof(DUMP_HEADER64)) == FALSE)
    {
        goto finish;
    }

    if (Header32->Signature != DUMP_SIGNATURE) goto finish;

    if (Header32->ValidDump == DUMP_VALID_DUMP)
    {
        if ((Header32->DumpType != DUMP_TYPE_FULL) && (Header32->MachineImageType != IMAGE_FILE_MACHINE_I386))
        {
            InternalErrorCode = TRUE;
            goto finish;
        }

        Base.QuadPart = sizeof(DUMP_HEADER32);

        for (Index = 0;
             Index < Header32->PhysicalMemoryBlock.NumberOfRuns;
             Index += 1)
        {
            ULARGE_INTEGER Min, Max;

            Min.QuadPart = Header32->PhysicalMemoryBlock.Run[Index].BasePage;
            Min.QuadPart *= PAGE_SIZE;

            Max.QuadPart = Header32->PhysicalMemoryBlock.Run[Index].PageCount;
            Max.QuadPart *= PAGE_SIZE;
            Max.QuadPart += Min.QuadPart;

            if (MmAddMdlEntry(Min, Max, Base, 0UL, 0, FALSE) == FALSE)
            {
                InternalErrorCode = TRUE;
                goto finish;
            }

            Base.QuadPart += (((ULONGLONG)Header32->PhysicalMemoryBlock.Run[Index].PageCount) * PAGE_SIZE);
        }

        Ret = TRUE;
    }
    else if (Header32->ValidDump == DUMP_VALID_DUMP64)
    {
#ifdef PRO_EDITION

        Base.QuadPart = sizeof(DUMP_HEADER64);
        Header64 = (PDUMP_HEADER64)Header32;

        if ((Header64->DumpType != DUMP_TYPE_FULL) && (Header64->MachineImageType != IMAGE_FILE_MACHINE_AMD64))
        {
            InternalErrorCode = TRUE;
            goto finish;
        }

        for (Index = 0;
             Index < Header64->PhysicalMemoryBlock.NumberOfRuns;
             Index += 1)
        {
            ULARGE_INTEGER Min, Max;

            Min.QuadPart = Header64->PhysicalMemoryBlock.Run[Index].BasePage;
            Min.QuadPart *= PAGE_SIZE;

            Max.QuadPart = Header64->PhysicalMemoryBlock.Run[Index].PageCount;
            Max.QuadPart *= PAGE_SIZE;
            Max.QuadPart += Min.QuadPart;

            if (MmAddMdlEntry(Min, Max, Base, 0UL, 0, FALSE) == FALSE)
            {
                InternalErrorCode = TRUE;
                goto finish;
            }

            Base.QuadPart += (((ULONGLONG)Header64->PhysicalMemoryBlock.Run[Index].PageCount) * PAGE_SIZE);
        }

        Ret = TRUE;
#else
        Red(L"Error: This file format is not supported in this product version.\n"
            L"       Don't wait any longer ! Upgrade to Professional Edition ! \n");
        White(L"       More information on http://www.moonsols.com\n\n");
#endif
    }

finish:
    // LocalFree(Header32);
    free(Header32);

    return Ret;
}

BOOL
MmSortMdl(
    VOID
)
/*++

Routine Description:

    Desc.

Arguments:

    -

Return Value:

    Ret1 - Desc.

--*/
{
ULONG MdlXIndex, MdlYIndex, MdlLowest;

PMEMORY_DESCRIPTOR_LIST Mdl;
ULARGE_INTEGER LowestAddr;

ULONG MdlSizeToAlloc;

BOOL Ret;

ULONG Start, End;

    Ret = FALSE;

    if (MmMdlCount == 1)
    {
        Ret = TRUE;
        goto finish;
    }

    if (!SUCCEEDED(ULongMult((ULONG)MmMdlAllocatedCount, sizeof(MEMORY_DESCRIPTOR_LIST), &MdlSizeToAlloc)))
    {
        goto finish;
    }

    Mdl = (PMEMORY_DESCRIPTOR_LIST)malloc(MdlSizeToAlloc);
    if (Mdl == NULL) goto finish;

    RtlZeroMemory(Mdl, MdlSizeToAlloc);

    Start = GetTickCount();
    White(L"Sorting %d entries... ", MmMdlCount);

    //
    // FIXED 6 Nov 2010 (MdlYIndex = 0; in MdlYIndex = 1;)
    // FIXED 9 Dec 2010 (MdlYIndex == 0) case
    //
    for (MdlYIndex = 0; MdlYIndex < MmMdlCount; MdlYIndex += 1)
    {
        LowestAddr.QuadPart = 0xFFFFFFFFFFFFFFFFULL;

        for (MdlXIndex = 0; MdlXIndex < MmMdlCount; MdlXIndex += 1)
        {
            if ((MmMdlAvailable[MdlXIndex].MemoryDescriptor.Range.Minimum.QuadPart <
                LowestAddr.QuadPart))
            {
                BOOL Ok;

                if ((MdlYIndex >= 1) && 
                    (Mdl[MdlYIndex - 1].MemoryDescriptor.Range.Minimum.QuadPart
                    >= MmMdlAvailable[MdlXIndex].MemoryDescriptor.Range.Minimum.QuadPart))
                {
                    continue;
                }

                //
                // Check if the potential entry is already in the sorted Mdl list.
                //
                Ok = FALSE;

                if (MdlYIndex >= 1)
                {
                    if (Mdl[MdlYIndex - 1].MemoryDescriptor.Range.Minimum.QuadPart < 
                        MmMdlAvailable[MdlXIndex].MemoryDescriptor.Range.Minimum.QuadPart)
                    {
                        Ok = TRUE;
                    }
                }
                else
                {
                    Ok = TRUE;
                }

                //
                // Only if this is a new entry.
                //
                if (Ok == TRUE)
                {
                    MdlLowest = MdlXIndex;
                    LowestAddr = MmMdlAvailable[MdlXIndex].MemoryDescriptor.Range.Minimum;
                }
            }
        }

        Mdl[MdlYIndex] = MmMdlAvailable[MdlLowest];

        if ((MdlLowest + 1) < MmMdlCount)
        {
            while ((MmMdlAvailable[MdlLowest].MemoryDescriptor.Range.Minimum.QuadPart + PAGE_SIZE) ==
                   (MmMdlAvailable[MdlLowest + 1].MemoryDescriptor.Range.Minimum.QuadPart))
            {
                if ((MdlLowest + 1) >= MmMdlCount) break;
                if ((MdlYIndex + 1) >= MmMdlCount) break;

                MdlYIndex += 1;
                MdlLowest += 1;
                Mdl[MdlYIndex] = MmMdlAvailable[MdlLowest];
            }
        }
    }

    //
    // Replace
    //
    free(MmMdlAvailable);

    MmMdlAvailable = Mdl;

    End = GetTickCount();
    Green(L"%d seconds.\n", (End - Start) / 1000);

    Ret = TRUE;

finish:
    return Ret;
}

BOOL
MmDestroyMdl(
    VOID
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

#if DEBUG_ENABLED
    wprintf(L"Destroy MmMdlAvailable ...\n");
#endif

    if (MmMdlAvailable)
    {
        free(MmMdlAvailable);
        MmMdlAvailable = NULL;
    }

#if CACHE_ENABLED
    if (MmCachedPages)
    {
#if DEBUG_ENABLED
        wprintf(L"Destroy MmCachedPages..");
#endif
        free(MmCachedPages); // LocalFree(MmCachedPages);
        MmCachedPages = NULL;
    }
#endif

    return TRUE;
}