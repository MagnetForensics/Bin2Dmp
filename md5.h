/*++
    Windows Memory Dumper - Win32dd/Win64dd
    Copyright (C) 2008-2009 Matthieu Suiche http://www.msuiche.net 
    Copyright (C) 2009 MoonSols. All rights reserved.
*/

//
// Data structure for MD5 (Message Digest) computation 
//
typedef struct _MD5_CONTEXT {
    ULONG i[2]; /* number of _bits_ handled mod 2^64 */
    ULONG Buffer[4]; /* scratch Bufferfer */
    UCHAR In[64]; /* Input Bufferfer */
    UCHAR Digest[16]; /* actual Digest after MD5FInal call */
} MD5_CONTEXT, *PMD5_CONTEXT;

VOID
MD5Init(
    MD5_CONTEXT *Md5Context
);

VOID
MD5Update(
    MD5_CONTEXT *Md5Context,
    PUCHAR InBuf,
    ULONG InLen
);

VOID
MD5Final(
    MD5_CONTEXT *Md5Context
);
