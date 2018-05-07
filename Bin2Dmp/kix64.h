/*++
    Copyright (C) 2010 Matthieu Suiche http://www.msuiche.net 
    Copyright (C) 2010 MoonSols. <http://www.moonsols.com>
    Copyright (c) 2017 - 2018, Comae Technologies DMCC
    All rights reserved.

Module Name:

    - kix64.h

Abstract:

    - 


Environment:

    - User mode

Revision History:

    - Matthieu Suiche (Jan-2010)

--*/

#define X64_KPRCB_OFFSET                0x180
#define X64_KPROCESSOR_STATE_OFFSET     0x040
#define X64_KSPECIAL_REGISTERS_OFFSET   0x000
#define X64_CONTEXT_OFFSET              0x0E0

#define KGDT64_NULL         (0 * 16)
#define KGDT64_R0_CODE      (1 * 16)
#define KGDT64_R0_DATA      ((1 * 16) + 8)
#define KGDT64_R3_CMCODE    (2 * 16)
#define KGDT64_R3_DATA      ((2 * 16) + 8)
#define KGDT64_R3_CODE      (3 * 16)
#define KGDT64_SYS_TSS      (4 * 16)
#define KGDT64_R3_CMTEB     (5 * 16)
#define KGDT64_LAST         (6 * 16)

#define X64_KUSER_SHARED_DATA_VA 0xFFFFF78000000000ULL
#define X64_USER_SHARED_DATA_VA 0x7FFE00000000ULL

#if 0
typedef struct _M128A {
/*0x000*/     UINT64       Low;
/*0x008*/     INT64        High;
} M128A, *PM128A;
#endif

typedef struct _X64_KDESCRIPTOR {
/*0x000*/     UINT16       Pad[3];
/*0x006*/     UINT16       Limit;
/*0x008*/     ULONGLONG    Base;
} X64_KDESCRIPTOR, *PX64_KDESCRIPTOR;

typedef struct _X64_KSPECIAL_REGISTERS {
/*0x000*/     UINT64       Cr0;
/*0x008*/     UINT64       Cr2;
/*0x010*/     UINT64       Cr3;
/*0x018*/     UINT64       Cr4;
/*0x020*/     UINT64       KernelDr0;
/*0x028*/     UINT64       KernelDr1;
/*0x030*/     UINT64       KernelDr2;
/*0x038*/     UINT64       KernelDr3;
/*0x040*/     UINT64       KernelDr6;
/*0x048*/     UINT64       KernelDr7;
/*0x050*/     struct _X64_KDESCRIPTOR Gdtr;
/*0x060*/     struct _X64_KDESCRIPTOR Idtr;
/*0x070*/     UINT16       Tr;
/*0x072*/     UINT16       Ldtr;
/*0x074*/     ULONG32      MxCsr;
/*0x078*/     UINT64       DebugControl;
/*0x080*/     UINT64       LastBranchToRip;
/*0x088*/     UINT64       LastBranchFromRip;
/*0x090*/     UINT64       LastExceptionToRip;
/*0x098*/     UINT64       LastExceptionFromRip;
/*0x0A0*/     UINT64       Cr8;
/*0x0A8*/     UINT64       MsrGsBase;
/*0x0B0*/     UINT64       MsrGsSwap;
/*0x0B8*/     UINT64       MsrStar;
/*0x0C0*/     UINT64       MsrLStar;
/*0x0C8*/     UINT64       MsrCStar;
/*0x0D0*/     UINT64       MsrSyscallMask;
} X64_KSPECIAL_REGISTERS, *PX64_KSPECIAL_REGISTERS;

typedef struct _X64_CONTEXT {
/*0x000*/     UINT64       P1Home;
/*0x008*/     UINT64       P2Home;
/*0x010*/     UINT64       P3Home;
/*0x018*/     UINT64       P4Home;
/*0x020*/     UINT64       P5Home;
/*0x028*/     UINT64       P6Home;
/*0x030*/     ULONG32      ContextFlags;
/*0x034*/     ULONG32      MxCsr;
/*0x038*/     UINT16       SegCs;
/*0x03A*/     UINT16       SegDs;
/*0x03C*/     UINT16       SegEs;
/*0x03E*/     UINT16       SegFs;
/*0x040*/     UINT16       SegGs;
/*0x042*/     UINT16       SegSs;
/*0x044*/     ULONG32      EFlags;
/*0x048*/     UINT64       Dr0;
/*0x050*/     UINT64       Dr1;
/*0x058*/     UINT64       Dr2;
/*0x060*/     UINT64       Dr3;
/*0x068*/     UINT64       Dr6;
/*0x070*/     UINT64       Dr7;
/*0x078*/     UINT64       Rax;
/*0x080*/     UINT64       Rcx;
/*0x088*/     UINT64       Rdx;
/*0x090*/     UINT64       Rbx;
/*0x098*/     UINT64       Rsp;
/*0x0A0*/     UINT64       Rbp;
/*0x0A8*/     UINT64       Rsi;
/*0x0B0*/     UINT64       Rdi;
/*0x0B8*/     UINT64       R8;
/*0x0C0*/     UINT64       R9;
/*0x0C8*/     UINT64       R10;
/*0x0D0*/     UINT64       R11;
/*0x0D8*/     UINT64       R12;
/*0x0E0*/     UINT64       R13;
/*0x0E8*/     UINT64       R14;
/*0x0F0*/     UINT64       R15;
/*0x0F8*/     UINT64       Rip;
    struct
    {
        /*0x100*/ struct _M128A Header[2];
        /*0x120*/ struct _M128A Legacy[8];
        /*0x1A0*/ struct _M128A Xmm0;
        /*0x1B0*/ struct _M128A Xmm1;
        /*0x1C0*/ struct _M128A Xmm2;
        /*0x1D0*/ struct _M128A Xmm3;
        /*0x1E0*/ struct _M128A Xmm4;
        /*0x1F0*/ struct _M128A Xmm5;
        /*0x200*/ struct _M128A Xmm6;
        /*0x210*/ struct _M128A Xmm7;
        /*0x220*/ struct _M128A Xmm8;
        /*0x230*/ struct _M128A Xmm9;
        /*0x240*/ struct _M128A Xmm10;
        /*0x250*/ struct _M128A Xmm11;
        /*0x260*/ struct _M128A Xmm12;
        /*0x270*/ struct _M128A Xmm13;
        /*0x280*/ struct _M128A Xmm14;
        /*0x290*/ struct _M128A Xmm15;
        /*0x2A0*/ UINT8 _PADDING0_[0x60];
    };
/*0x300*/     struct       _M128A VectorRegister[26];
/*0x4A0*/     UINT64       VectorControl;
/*0x4A8*/     UINT64       DebugControl;
/*0x4B0*/     UINT64       LastBranchToRip;
/*0x4B8*/     UINT64       LastBranchFromRip;
/*0x4C0*/     UINT64       LastExceptionToRip;
/*0x4C8*/     UINT64       LastExceptionFromRip;
} X64_CONTEXT, *PX64_CONTEXT;
