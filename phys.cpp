/*++
    Copyright (C) 2010 Matthieu Suiche http://www.msuiche.net 
    Copyright (C) 2010 MoonSols. <http://www.moonsols.com>
    All rights reserved.

Module Name:

    - phys.c

Abstract:

    - 


Environment:

    - User mode

Revision History:

    - Matthieu Suiche (Jan-2010)

--*/

#include "stdafx.h"
#include "avalon.h"

// DECOMPRESSOR_HANDLE Decompressor = NULL;


typedef DWORD (WINAPIV *PXPRESSDECOMPRESS)(PVOID, DWORD, PVOID, DWORD);

PXPRESSDECOMPRESS xpress_decompress = NULL;

BOOL
MmReadXpressBlock(
    IN HANDLE Handle,
    OPTIONAL IN PULARGE_INTEGER Pa,
    OPTIONAL IN ULONG XpressIndex,
    IN ULARGE_INTEGER XpressHeader,
    OUT PVOID Buffer,
    IN ULONG SizeOfBuffer,
    OPTIONAL IN ULONG InCompressedSize, // Win8
    OPTIONAL OUT PULONG OutBufferSize
)
{
    ULONG NumberOfUncompressedPages, UncompressedBytes;
    ULONG CompressedSize, UncompressedSize;

    UCHAR xprs[XPRESS_HEADER_SIZE];
    PUCHAR Uncompressed, Compressed;
    ULONG Info;
    ULONG Offset = 0;

    BOOLEAN UseXpressHeader = FALSE;

    BOOL Ret = FALSE;

    Ret = ReadFileAsynchronous(Handle, XpressHeader, xprs, XPRESS_HEADER_SIZE);
    if (Ret == FALSE)
    {
        goto CleanUp;
    }

    if (memcmp(xprs, XPRESS_MAGIC, XPRESS_MAGIC_SIZE) == 0)
    {
        Info = *((PULONG)(&xprs[XPRESS_MAGIC_SIZE]));

        CompressedSize = ((Info >> 10) + 1);
        CompressedSize = (CompressedSize + (XPRESS_ALIGNMENT - 1)) & ~(XPRESS_ALIGNMENT - 1);

        NumberOfUncompressedPages = ((Info & 0x3ff) + 1);
        UncompressedSize = (NumberOfUncompressedPages * PAGE_SIZE);

        UseXpressHeader = TRUE;

        XpressHeader.QuadPart += XPRESS_HEADER_SIZE;
    }
    else
    {
        // Windows 8 does not use the old xpress header tags.
        CompressedSize = InCompressedSize;
        NumberOfUncompressedPages = 0x10;
        UncompressedSize = NumberOfUncompressedPages * PAGE_SIZE;

        UseXpressHeader = FALSE;
    }

    if ((UncompressedSize == 0) || (CompressedSize == 0))
    {
        Ret = FALSE;
        goto CleanUp;
    }

    if ((SizeOfBuffer < UncompressedSize) && Pa)
    {
        if (OutBufferSize) *OutBufferSize = UncompressedSize;
        goto CleanUp;
    }

    Uncompressed = (PUCHAR)malloc(UncompressedSize);
    if (Uncompressed == NULL)
    {
        Ret = FALSE;
        goto CleanUp;
    }

    Compressed = (PUCHAR)malloc(CompressedSize);
    if (Compressed == NULL)
    {
        Ret = FALSE;
        goto CleanUp;
    }
    RtlZeroMemory(Compressed, CompressedSize);

    Ret = ReadFileAsynchronous(Handle, XpressHeader, Compressed, CompressedSize);
    if (Ret == FALSE) goto CleanUp;

    if (CompressedSize != UncompressedSize)
    {
        // wprintf(L"XData: 0x%08X%08X Size: 0x%X\n", XpressHeader.HighPart, XpressHeader.LowPart, CompressedSize);

        UncompressedBytes = Xpress_Decompress(Compressed,
                                                CompressedSize,
                                                Uncompressed,
                                                UncompressedSize);

        // wprintf(L"CompressedSize 0x%x -> UncompressedBytes: 0x%08x UncompressedSize 0x%x\n", CompressedSize, UncompressedBytes, UncompressedSize);

        if (UseXpressHeader && (UncompressedBytes != UncompressedSize))
        {
            Ret = FALSE;
            goto CleanUp;
        }
    }
    else
    {
        RtlCopyMemory(Uncompressed, Compressed, UncompressedSize);
    }

    if (Pa) Offset = Pa->LowPart & (PAGE_SIZE - 1);

    RtlCopyMemory(Buffer,
                  &Uncompressed[(XpressIndex * PAGE_SIZE)] + Offset,
                  min(UncompressedSize, SizeOfBuffer));
#if CACHE_ENABLED
    //
    // Optimization: We cache the page
    //
    if (Pa)
    {
        MmAddToCache(*Pa, &Uncompressed[(XpressIndex * PAGE_SIZE)]);
    }
#endif

    Ret = TRUE;

CleanUp:
    if (Uncompressed) free(Uncompressed);
    if (Compressed) free(Compressed);

    return Ret;
}

BOOL
MmReadPageAtPhysicalAddress(
    HANDLE Handle,
    ULARGE_INTEGER Pa,
    PVOID Buffer,
    ULONG SizeOfBuffer
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

    ULARGE_INTEGER Address;

    ULONG MdlIndex;
    ULONG BytesToCopy;
    BOOL Ret;

    Ret = FALSE;

    if (Buffer == NULL) goto Finish;

#if CACHE_ENABLED
    //
    // Optimization: Check if page is already cached.
    //

    Ret = MmIsCached(Pa, Buffer, SizeOfBuffer);
    if (Ret == TRUE) goto Finish;
#endif

    if (Pa.QuadPart >= MmMaximumPhysicalAddress.QuadPart) goto Finish;

    for (Mdl = MmMdlAvailable, MdlIndex = 0;
         MdlIndex < MmMdlCount;
         Mdl += 1, MdlIndex += 1)
    {
        if ((Pa.QuadPart >= Mdl->MemoryDescriptor.Range.Minimum.QuadPart) &&
            (Pa.QuadPart < Mdl->MemoryDescriptor.Range.Maximum.QuadPart))
        {
            goto MdlFound; // break;
        }
    }

    if (MdlIndex == MmMdlCount) goto Finish;

MdlFound:

    if (Mdl->MemoryDescriptor.IsCompressed == FALSE)
    {
#if CACHE_ENABLED
        PUCHAR Page;
        ULONG Delta;
#endif

        Address.QuadPart = Pa.QuadPart;
        Address.QuadPart += Mdl->MemoryDescriptor.Uncompressed.BaseOffset.QuadPart;
        Address.QuadPart -= Mdl->MemoryDescriptor.Range.Minimum.QuadPart;

#if 1
        Page = (PUCHAR)malloc(PAGE_SIZE);
        if (Page == NULL)
        {
            Ret = FALSE;
            goto Finish;
        }

        Delta = (Address.LowPart & (PAGE_SIZE - 1));
        Address.LowPart &= ~(PAGE_SIZE - 1);

        Ret = ReadFileAsynchronous(Handle, Address, Page, PAGE_SIZE);
        if (Ret == FALSE)
        {
            free(Page);
            goto Finish;
        }

        //
        // Optimization: We cache the page
        //
        Ret = MmAddToCache(Pa, Page);
        if (Ret == FALSE)
        {
            free(Page);
            goto Finish;
        }

        BytesToCopy = ((PAGE_SIZE - Delta) > SizeOfBuffer) ? SizeOfBuffer : (PAGE_SIZE - Delta);
        memcpy_s(Buffer, SizeOfBuffer, Page + Delta, BytesToCopy);

        free(Page);
#endif

#if 0
        Ret = ReadFileAsynchronous(Handle, Address, Buffer, SizeOfBuffer);
        if (Ret == FALSE) goto Finish;
#endif
    }
    else
    {
        ULONG NumberOfUncompressedPages, UncompressedBytes;
        ULONG CompressedSize, UncompressedSize;

        UCHAR xprs[XPRESS_HEADER_SIZE];
        ULARGE_INTEGER XpressHeader;
        PUCHAR Uncompressed, Compressed;
        ULONG Info;

        BOOLEAN UseXpressHeader = FALSE;

        XpressHeader = Mdl->MemoryDescriptor.Compressed.XpressHeader;

        if ((Ret = ReadFileAsynchronous(Handle, XpressHeader, xprs, XPRESS_HEADER_SIZE)) == FALSE)
        {
            goto Finish;
        }

        if (memcmp(xprs, XPRESS_MAGIC, XPRESS_MAGIC_SIZE) == 0)
        {
            Info = *((PULONG)(&xprs[XPRESS_MAGIC_SIZE]));

            CompressedSize = ((Info >> 10) + 1);
            CompressedSize = (CompressedSize + (XPRESS_ALIGNMENT - 1)) & ~(XPRESS_ALIGNMENT - 1);

            NumberOfUncompressedPages = ((Info & 0x3ff) + 1);
            UncompressedSize = (NumberOfUncompressedPages * PAGE_SIZE);

            UseXpressHeader = TRUE;

            XpressHeader.QuadPart += XPRESS_HEADER_SIZE;
        }
        else
        {
            // Windows 8 does not use the old xpress header tags.
            CompressedSize = Mdl->MemoryDescriptor.CompressedSize;
            NumberOfUncompressedPages = 0x10;
            UncompressedSize = NumberOfUncompressedPages * PAGE_SIZE;

            UseXpressHeader = FALSE;
        }

        if ((UncompressedSize == 0) || (CompressedSize == 0))
        {
            Ret = FALSE;
            goto Finish;
        }

        // Uncompressed = LocalAlloc(LPTR, UncompressedSize);
        Uncompressed = (PUCHAR)malloc(UncompressedSize);
        if (Uncompressed == NULL)
        {
            Ret = FALSE;
            goto Finish;
        }

        // Compressed = LocalAlloc(LPTR, CompressedSize);
        Compressed = (PUCHAR)malloc(CompressedSize);
        if (Compressed == NULL)
        {
            Ret = FALSE;

            // LocalFree(Uncompressed);
            free(Uncompressed);
            goto Finish;
        }
        RtlZeroMemory(Compressed, CompressedSize);

        if ((Ret = ReadFileAsynchronous(Handle, XpressHeader, Compressed, CompressedSize)) == FALSE)
        {
            // LocalFree(Uncompressed);
            // LocalFree(Compressed);
            free(Uncompressed);
            free(Compressed);
            goto Finish;
        }

        if (CompressedSize != UncompressedSize)
        {
            // wprintf(L"XData: 0x%08X%08X Size: 0x%X\n", XpressHeader.HighPart, XpressHeader.LowPart, CompressedSize);

            UncompressedBytes = Xpress_Decompress(Compressed,
                                                  CompressedSize,
                                                  Uncompressed,
                                                  UncompressedSize);

            // wprintf(L"CompressedSize 0x%x -> UncompressedBytes: 0x%08x UncompressedSize 0x%x\n", CompressedSize, UncompressedBytes, UncompressedSize);

            if (UseXpressHeader && (UncompressedBytes != UncompressedSize))
            {
                Ret = FALSE;

                // LocalFree(Uncompressed);
                // LocalFree(Compressed);
                free(Uncompressed);
                free(Compressed);
                goto Finish;
            }
        }
        else
        {
            RtlCopyMemory(Uncompressed, Compressed, UncompressedSize);
        }

        RtlCopyMemory(Buffer,
                     &Uncompressed[(Mdl->MemoryDescriptor.Compressed.XpressIndex * PAGE_SIZE)]
                        + (Pa.LowPart & (PAGE_SIZE - 1)),
                     SizeOfBuffer);

#if CACHE_ENABLED
        //
        // Optimization: We cache the page
        //
        MmAddToCache(Pa, &Uncompressed[(Mdl->MemoryDescriptor.Compressed.XpressIndex * PAGE_SIZE)]);
#endif

        // LocalFree(Uncompressed);
        // LocalFree(Compressed);
        free(Uncompressed);
        free(Compressed);
    }

    Ret = TRUE;

Finish:
    return Ret;
}

BOOL
MmReadPhysicalAddress(
    HANDLE Handle,
    ULARGE_INTEGER Pa,
    PVOID Buffer,
    ULONG SizeOfBuffer
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
    ULARGE_INTEGER PaBis;
    ULONG SizeToRead;

    ULONG BytesReaded;
    BOOL Ret;

    if (Buffer == NULL) return FALSE;

    RtlZeroMemory(Buffer, SizeOfBuffer);

    for (BytesReaded = 0; BytesReaded < SizeOfBuffer; BytesReaded += PAGE_SIZE)
    {
        SizeToRead = ((SizeOfBuffer - BytesReaded) >= PAGE_SIZE) ?
                        PAGE_SIZE : (SizeOfBuffer % PAGE_SIZE);

        PaBis = Pa;
        PaBis.QuadPart += BytesReaded;

        Ret = MmReadPageAtPhysicalAddress(Handle,
                                          PaBis,
                                          ((PUCHAR)Buffer) + BytesReaded,
                                          SizeToRead);

        if (Ret == FALSE) break;

        Ret = TRUE;
    }

    return Ret;
}