/*++
    Copyright (C) 2010 Matthieu Suiche http://www.msuiche.net 
    Copyright (C) 2010 MoonSols. <http://www.moonsols.com>
    All rights reserved.

Module Name:

    - kix86.h

Abstract:

    - 


Environment:

    - User mode

Revision History:

    - Matthieu Suiche (Jan-2010)

--*/

#define X86_KPRCB_SIZE            0x120
#define X86_KPROCESSOR_STATE_SIZE 0x1C
#define X86_CONTEXT_SIZE          0x2CC

#define X86_KPRCB_OFFSET              0x120
#define X86_KPROCESSOR_STATE_OFFSET   0x01C
#define X86_CONTEXT_OFFSET            0x000
#define X86_KSPECIAL_REGISTERS_OFFSET 0x2CC

//
// If Win7 and above.
//
#define X86_NT61_KPROCESSOR_STATE_OFFSET 0x18

#define KDBG_TAG 'GBDK'

#define RPL_MASK            0x0003
#define MODE_MASK           0x0001

#define KGDT_NULL           (0x00)
#define KGDT_R0_CODE        (0x8)
#define KGDT_R0_DATA        (0x10)
#define KGDT_R3_CODE        (0x18)
#define KGDT_R3_DATA        (0x20)
#define KGDT_TSS            (0x28)
#define KGDT_R0_PCR         (0x30)
#define KGDT_R3_TEB         (0x38)
#define KGDT_LDT            (0x48)
#define KGDT_DF_TSS         (0x50)
#define KGDT_NMI_TSS        (0x58)

#define X86_KUSER_SHARED_DATA_VA 0xFFDF0000ULL
#define X86_USER_SHARED_DATA_VA 0x7FFE0000ULL

typedef struct _X86_CONTEXT {
    /*0x000*/     ULONG32      ContextFlags;
    /*0x004*/     ULONG32      Dr0;
    /*0x008*/     ULONG32      Dr1;
    /*0x00C*/     ULONG32      Dr2;
    /*0x010*/     ULONG32      Dr3;
    /*0x014*/     ULONG32      Dr6;
    /*0x018*/     ULONG32      Dr7;
    /*0x01C*/     UCHAR        FloatSave[0x70];
    /*0x08C*/     ULONG32      SegGs;
    /*0x090*/     ULONG32      SegFs;
    /*0x094*/     ULONG32      SegEs;
    /*0x098*/     ULONG32      SegDs;
    /*0x09C*/     ULONG32      Edi;
    /*0x0A0*/     ULONG32      Esi;
    /*0x0A4*/     ULONG32      Ebx;
    /*0x0A8*/     ULONG32      Edx;
    /*0x0AC*/     ULONG32      Ecx;
    /*0x0B0*/     ULONG32      Eax;
    /*0x0B4*/     ULONG32      Ebp;
    /*0x0B8*/     ULONG32      Eip;
    /*0x0BC*/     ULONG32      SegCs;
    /*0x0C0*/     ULONG32      EFlags;
    /*0x0C4*/     ULONG32      Esp;
    /*0x0C8*/     ULONG32      SegSs;
    /*0x0CC*/     UINT8        ExtendedRegisters[512];
} X86_CONTEXT, *PX86_CONTEXT;

typedef struct _X86_DESCRIPTOR {
/*0x000*/     UINT16       Pad;
/*0x002*/     UINT16       Limit;
/*0x004*/     ULONG32      Base;
} X86_DESCRIPTOR, *PX86_DESCRIPTOR;

typedef struct _X86_KSPECIAL_REGISTERS {
/*0x000*/     ULONG32      Cr0;
/*0x004*/     ULONG32      Cr2;
/*0x008*/     ULONG32      Cr3;
/*0x00C*/     ULONG32      Cr4;
/*0x010*/     ULONG32      KernelDr0;
/*0x014*/     ULONG32      KernelDr1;
/*0x018*/     ULONG32      KernelDr2;
/*0x01C*/     ULONG32      KernelDr3;
/*0x020*/     ULONG32      KernelDr6;
/*0x024*/     ULONG32      KernelDr7;
/*0x028*/     X86_DESCRIPTOR   Gdtr;
/*0x030*/     X86_DESCRIPTOR   Idtr;
/*0x038*/     UINT16       Tr;
/*0x03A*/     UINT16       Ldtr;
/*0x03C*/     ULONG32      Reserved[6];
} X86_KSPECIAL_REGISTERS, *PX86_KSPECIAL_REGISTERS;
