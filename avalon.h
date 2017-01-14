/*++
    Copyright (C) 2010 Matthieu Suiche http://www.msuiche.net 
    Copyright (C) 2010 MoonSols. <http://www.moonsols.com>
    All rights reserved.

Module Name:

    - avalon.h

Abstract:

    - 


Environment:

    - User mode

Revision History:

    - Matthieu Suiche (Jan-2010)

--*/

#include <windows.h>

#include <stdlib.h>
#include <stdio.h>

#include <intsafe.h>

#include <dbghelp.h>
#include <wdbgexts.h>

#include <compressapi.h>

//
// Global definition
//
#define CACHE_ENABLED 1

#define PRO_EDITION


#define FORCE_DEBUG_MODE 0

#if defined(PRO_EDITION)
#define DEBUG_ENABLED FORCE_DEBUG_MODE
#elif defined(COMMUNITY_EDITION)
#define DEBUG_ENABLED 0
#else
#define DEBUG_ENABLED 1
#endif


#define LOAD_SYMBOLS 0

#define MM_GENERIC 0

#include "file.h"
#include "mdl.h"
#include "kernel.h"

#include "validate.h"
#include "phys.h"

#include "kix86.h"
#include "kix64.h"

#include "mm.h"

#include "pe.h"

#include "symbols.h"

#include "dmp.h"

#include "compression.h"

#include "hiber.h"

// Optimization
#include "cache.h"

// DEBUG
#include "debug.h"

// Features
#include "convert.h"

//
// High Level
//
#include "text.h"
#include "md5.h"

#define LIBRARY_VERSION L"v2.1.1.20140523"

#pragma comment(lib, "dbghelp.lib" )

// #pragma comment(lib, "Cabinet.lib" )

#define SIGN_EXTEND(_x_) (ULONG64)(LONG)(_x_)