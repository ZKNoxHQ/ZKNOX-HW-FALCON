/*****************************************************************************
 *   Ledger App — Falcon family dispatcher (v0.4.0 with masked Falcon-512 flash)
 *
 *     0x30 / 0x31 / 0x33 / 0x34   Falcon-1024 streaming
 *     0x40 / 0x41 / 0x43 / 0x44   Falcon-512  streaming
 *     0x60 / 0x61 / 0x62 / 0x63   Falcon-512  flash (unprotected sampler)
 *     0x64 / 0x65                 flash GET_SIG / DUMP_NVM (Falcon-512)
 *     0x66                        Falcon-512  flash SIGN with SCA-protected
 *                                 sampler (Lin et al. PKC 2025) — NEW
 *     0x70 / 0x71 / 0x72 / 0x73   Falcon-1024 flash
 *     0x74 / 0x75                 flash GET_SIG / DUMP_NVM (Falcon-1024)
 *****************************************************************************/

#include <stdint.h>
#include <stdbool.h>

#include "buffer.h"
#include "io.h"
#include "ledger_assert.h"

#include "dispatcher.h"
#include "constants.h"
#include "globals.h"
#include "types.h"
#include "sw.h"
#include "get_version.h"
#include "get_app_name.h"
#include "get_public_key.h"
#include "sign_tx.h"
#include "provide_token_info.h"

#include "handler_falcon.h"
#include "handler_falcon_sign.h"
#include "handler_falcon_keygen_expand.h"

#include "handler_falcon512.h"
#include "handler_falcon512_sign.h"
#include "handler_falcon512_keygen_expand.h"

#include "handler_falcon512_flash.h"
#include "handler_falcon512_flash_sign_protect.h"

#include "handler_falcon1024_flash.h"

int apdu_dispatcher(const command_t *cmd) {
    LEDGER_ASSERT(cmd != NULL, "NULL cmd");

    if (cmd->cla != CLA) {
        return io_send_sw(SWO_INVALID_CLA);
    }

    buffer_t buf = {0};

    switch (cmd->ins) {
        case GET_VERSION:
            if (cmd->p1 != 0 || cmd->p2 != 0) return io_send_sw(SWO_INCORRECT_P1_P2);
            return handler_get_version();

        case GET_APP_NAME:
            if (cmd->p1 != 0 || cmd->p2 != 0) return io_send_sw(SWO_INCORRECT_P1_P2);
            return handler_get_app_name();

        case GET_PUBLIC_KEY:
            if (cmd->p1 > 1 || cmd->p2 > 0) return io_send_sw(SWO_INCORRECT_P1_P2);
            if (!cmd->data) return io_send_sw(SWO_WRONG_DATA_LENGTH);
            buf.ptr = cmd->data; buf.size = cmd->lc; buf.offset = 0;
            return handler_get_public_key(&buf, (bool) cmd->p1);

        case SIGN_TX:
            if ((cmd->p1 == P1_START && cmd->p2 != P2_MORE) ||
                cmd->p1 > P1_MAX ||
                (cmd->p2 != P2_LAST && cmd->p2 != P2_MORE))
                return io_send_sw(SWO_INCORRECT_P1_P2);
            if (!cmd->data) return io_send_sw(SWO_WRONG_DATA_LENGTH);
            buf.ptr = cmd->data; buf.size = cmd->lc; buf.offset = 0;
            return handler_sign_tx(&buf, cmd->p1, (bool) (cmd->p2 & P2_MORE), false);

        case SIGN_TOKEN_TX:
            if ((cmd->p1 == P1_START && cmd->p2 != P2_MORE) ||
                cmd->p1 > P1_MAX ||
                (cmd->p2 != P2_LAST && cmd->p2 != P2_MORE))
                return io_send_sw(SWO_INCORRECT_P1_P2);
            if (!cmd->data) return io_send_sw(SWO_WRONG_DATA_LENGTH);
            buf.ptr = cmd->data; buf.size = cmd->lc; buf.offset = 0;
            return handler_sign_tx(&buf, cmd->p1, (bool) (cmd->p2 & P2_MORE), true);

        case PROVIDE_TOKEN_INFO:
            buf.ptr = cmd->data; buf.size = cmd->lc; buf.offset = 0;
            return handler_provide_token_info(&buf);

        /* ---- Falcon-1024 streaming ---- */
        case FALCON_KEYGEN:
            if (cmd->p1 != 0 || cmd->p2 != 0) return io_send_sw(SWO_INCORRECT_P1_P2);
            if (cmd->lc != 0) return io_send_sw(SWO_WRONG_DATA_LENGTH);
            buf.ptr = cmd->data; buf.size = cmd->lc; buf.offset = 0;
            return handler_falcon_keygen(&buf);

        case FALCON_GET_PK:
            buf.ptr = cmd->data; buf.size = cmd->lc; buf.offset = 0;
            return handler_falcon_get_pk(&buf, cmd->p1, cmd->p2);

        case FALCON_SIGN:
            buf.ptr = cmd->data; buf.size = cmd->lc; buf.offset = 0;
            return handler_falcon_sign(&buf, cmd->p1, cmd->p2);

        case FALCON_KEYGEN_EXPAND:
            if (cmd->lc != 0) return io_send_sw(SWO_WRONG_DATA_LENGTH);
            buf.ptr = cmd->data; buf.size = cmd->lc; buf.offset = 0;
            return handler_falcon_keygen_expand(&buf, cmd->p1, cmd->p2);

        /* ---- Falcon-512 streaming ---- */
        case FALCON512_KEYGEN:
            if (cmd->p1 != 0 || cmd->p2 != 0) return io_send_sw(SWO_INCORRECT_P1_P2);
            if (cmd->lc != 0) return io_send_sw(SWO_WRONG_DATA_LENGTH);
            buf.ptr = cmd->data; buf.size = cmd->lc; buf.offset = 0;
            return handler_falcon512_keygen(&buf);

        case FALCON512_GET_PK:
            buf.ptr = cmd->data; buf.size = cmd->lc; buf.offset = 0;
            return handler_falcon512_get_pk(&buf, cmd->p1, cmd->p2);

        case FALCON512_SIGN:
            buf.ptr = cmd->data; buf.size = cmd->lc; buf.offset = 0;
            return handler_falcon512_sign(&buf, cmd->p1, cmd->p2);

        case FALCON512_KEYGEN_EXPAND:
            if (cmd->lc != 0) return io_send_sw(SWO_WRONG_DATA_LENGTH);
            buf.ptr = cmd->data; buf.size = cmd->lc; buf.offset = 0;
            return handler_falcon512_keygen_expand(&buf, cmd->p1, cmd->p2);

        /* ---- Falcon-512 flash variant ---- */
        case FALCON512_FLASH_KEYGEN:
            if (cmd->p1 != 0 || cmd->p2 != 0) return io_send_sw(SWO_INCORRECT_P1_P2);
            if (cmd->lc != 0) return io_send_sw(SWO_WRONG_DATA_LENGTH);
            buf.ptr = cmd->data; buf.size = cmd->lc; buf.offset = 0;
            return handler_falcon512_flash_keygen(&buf);

        case FALCON512_FLASH_GET_PK:
            buf.ptr = cmd->data; buf.size = cmd->lc; buf.offset = 0;
            return handler_falcon512_flash_get_pk(&buf, cmd->p1, cmd->p2);

        case FALCON512_FLASH_KEYGEN_EXPAND:
            if (cmd->lc != 0) return io_send_sw(SWO_WRONG_DATA_LENGTH);
            buf.ptr = cmd->data; buf.size = cmd->lc; buf.offset = 0;
            return handler_falcon512_flash_keygen_expand(&buf, cmd->p1, cmd->p2);

        case FALCON512_FLASH_SIGN:
            buf.ptr = cmd->data; buf.size = cmd->lc; buf.offset = 0;
            return handler_falcon512_flash_sign(&buf, cmd->p1, cmd->p2);

        case FALCON512_FLASH_GET_SIG:
            buf.ptr = cmd->data; buf.size = cmd->lc; buf.offset = 0;
            return handler_falcon512_flash_get_sig(&buf, cmd->p1, cmd->p2);

        case FALCON512_FLASH_DUMP_NVM:
            buf.ptr = cmd->data; buf.size = cmd->lc; buf.offset = 0;
            return handler_falcon512_flash_dump_nvm(&buf, cmd->p1, cmd->p2);

        case FALCON512_FLASH_SIGN_PROTECT:
            buf.ptr = cmd->data; buf.size = cmd->lc; buf.offset = 0;
            return handler_falcon512_flash_sign_protect(&buf, cmd->p1, cmd->p2);

        /* ---- Falcon-1024 flash variant ---- */
        case FALCON1024_FLASH_KEYGEN:
            if (cmd->p1 != 0 || cmd->p2 != 0) return io_send_sw(SWO_INCORRECT_P1_P2);
            if (cmd->lc != 0) return io_send_sw(SWO_WRONG_DATA_LENGTH);
            buf.ptr = cmd->data; buf.size = cmd->lc; buf.offset = 0;
            return handler_falcon1024_flash_keygen(&buf);

        case FALCON1024_FLASH_GET_PK:
            buf.ptr = cmd->data; buf.size = cmd->lc; buf.offset = 0;
            return handler_falcon1024_flash_get_pk(&buf, cmd->p1, cmd->p2);

        case FALCON1024_FLASH_KEYGEN_EXPAND:
            if (cmd->lc != 0) return io_send_sw(SWO_WRONG_DATA_LENGTH);
            buf.ptr = cmd->data; buf.size = cmd->lc; buf.offset = 0;
            return handler_falcon1024_flash_keygen_expand(&buf, cmd->p1, cmd->p2);

        case FALCON1024_FLASH_SIGN:
            buf.ptr = cmd->data; buf.size = cmd->lc; buf.offset = 0;
            return handler_falcon1024_flash_sign(&buf, cmd->p1, cmd->p2);

        case FALCON1024_FLASH_GET_SIG:
            buf.ptr = cmd->data; buf.size = cmd->lc; buf.offset = 0;
            return handler_falcon1024_flash_get_sig(&buf, cmd->p1, cmd->p2);

        case FALCON1024_FLASH_DUMP_NVM:
            buf.ptr = cmd->data; buf.size = cmd->lc; buf.offset = 0;
            return handler_falcon1024_flash_dump_nvm(&buf, cmd->p1, cmd->p2);

        default:
            return io_send_sw(SWO_INVALID_INS);
    }
}
