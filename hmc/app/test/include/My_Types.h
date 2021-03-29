


#ifndef _MY_TYPES_H_INCLUDED_

#include <stdint.h> //for uint32_t

typedef void *Handle_t;

typedef void (*Void_CB_t)(void);
typedef int (*Simple_CB_t)(void);
typedef int (*Common_CB_t)(Handle_t handle);
typedef int (*Common_CB2_t)(Handle_t cbHdl, Handle_t cbPrivate);

#ifndef null
#define null NULL
#endif

//For argument
#ifndef IN
#define IN
#endif

#ifndef OUT
#define OUT
#endif

#ifndef IO
#define IO
#endif

#ifndef uchar
typedef unsigned char uchar;
#endif
#ifndef ushort
typedef unsigned short ushort;
#endif
#ifndef uint
typedef unsigned int uint;
#endif
#ifndef ulong
typedef unsigned long ulong;
#endif

#ifndef u8
typedef uint8_t u8;
#endif
#ifndef u16
typedef uint16_t u16;
#endif
#ifndef u32
typedef uint32_t u32;
#endif
#ifndef u64
typedef uint64_t u64;
#endif

#ifndef s8
typedef int8_t s8;
#endif
#ifndef s16
typedef int16_t s16;
#endif
#ifndef s32
typedef int32_t s32;
#endif
#ifndef s64
typedef int64_t s64;
#endif

//Return Code define:
#define EC_EXIT_SUCCESS (0)
#define EC_EXIT_FAILURE (1)

//Generic Return Code:
//0x00010000: Memory issue
#define RC_MEMORY_ALLOCATE_FAILED (0x00010000)
#define RC_BUFFER_FULL            (0x00011000)
#define RC_BUFFER_OVERFLOW        (0x00011001)
#define RC_BUFFER_TOO_SMALL       (0x00011002)
//0x00020000: File issue
#define RC_FILE_REACH_EOF         (0x00020000)
#define RC_FILE_OPEN_ERROR        (0x00020001)
#define RC_FILE_CLOSE_ERROR       (0x00020002)
#define RC_FILE_SCAN_ERROR        (0x00020003)
#define RC_FILE_PRINT_ERROR       (0x00020004)

#define DO_ENDIAN_SWAP (true)
#define NO_ENDIAN_SWAP (false)

typedef enum {
    LITTLE_END,
    BIG_END,
} endian_t;

typedef enum {
    TO_LITTLE_END,
    TO_BIG_END,
} endian_to_t;

typedef enum {
    FROM_LITTLE_END,
    FROM_BIG_END,
} endian_from_t;

#define INDENT01 "    "
#define INDENT02 "        "
#define INDENT03 "            "
#define INDENT04 "                "
#define INDENT05 "                    "
#define INDENT06 "                        "

#define INDENTS1 "  "
#define INDENTS2 "    "
#define INDENTS3 "      "
#define INDENTS4 "        "
#define INDENTS5 "          "
#define INDENTS6 "            "

#define INDENTSS1 " "
#define INDENTSS2 "  "
#define INDENTSS3 "   "
#define INDENTSS4 "    "
#define INDENTSS5 "     "
#define INDENTSS6 "      "

#define INDENTT1 "\t"
#define INDENTT2 "\t\t"
#define INDENTT3 "\t\t\t"
#define INDENTT4 "\t\t\t\t"
#define INDENTT5 "\t\t\t\t\t"
#define INDENTT6 "\t\t\t\t\t\t"

#define PRINT01(...) printf(INDENT01 __VA_ARGS__)
#define PRINT02(...) printf(INDENT02 __VA_ARGS__)
#define PRINT03(...) printf(INDENT03 __VA_ARGS__)
#define PRINT04(...) printf(INDENT04 __VA_ARGS__)
#define PRINT05(...) printf(INDENT05 __VA_ARGS__)
#define PRINT06(...) printf(INDENT06 __VA_ARGS__)





#if 0
//Copy from here
#if 0
#define MY_INDENT01 INDENT01
#define MY_INDENT02 INDENT02
#define MY_INDENT03 INDENT03
#define MY_INDENT04 INDENT04
#define MY_INDENT05 INDENT05
#define MY_INDENT06 INDENT06
#else
#define MY_INDENT01 INDENTS1
#define MY_INDENT02 INDENTS2
#define MY_INDENT03 INDENTS3
#define MY_INDENT04 INDENTS4
#define MY_INDENT05 INDENTS5
#define MY_INDENT06 INDENTS6
#endif
//Copy till here
#endif

#define _MY_TYPES_H_INCLUDED_
#endif//_MY_TYPES_H_INCLUDED_


