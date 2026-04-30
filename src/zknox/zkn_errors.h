// copyright, zknox, 2025
#ifndef _ZKN_ERRORS_H
#define _ZKN_ERRORS_H

typedef int zkn_error_t;
typedef int zkn_flag_t;

#define ZKN_NOTIMPLEMENTED  0x8B99
#define ZKN_NOT_INITIALIZED 0x8B45
#define ZKN_FILE_FULL       0x8BFF
/* MACROS DEFINITIONS */
#define ZKN_UNUSED(x) x

#define ZKN_ERROR_INIT() zkn_error_t error = 0

/* label for the ZKN_CHECK goto */
#define ZKN_ERROR_CLOSE() \
    do {                  \
    end:                  \
        return error;     \
    } while (0)

/* label for the ZKN_CHECK goto */
#define ZKN_ERROR_CLOSE_SEND()                            \
    do {                                                  \
    end:                                                  \
        if (error) return io_send_sw(SWO_INCORRECT_DATA); \
        return 0;                                         \
    } while (0)

/* test return function and go to label end if not ok*/
#define ZKN_CHECK(call) \
    do {                \
        error = call;   \
        if (error) {    \
            goto end;   \
        }               \
    } while (0)

#endif