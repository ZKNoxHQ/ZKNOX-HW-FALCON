/*****************************************************************************
 *   Ledger App Boilerplate.
 *   Falcon-1024 + Falcon-512 + Falcon-512 flash build (v0.2.0).
 *
 *   Three variants coexist in the same firmware via distinct INS codes:
 *     0x30 / 0x31 / 0x33 / 0x34   Falcon-1024 streaming (v0.7.0)
 *     0x40 / 0x41 / 0x43 / 0x44   Falcon-512  streaming (v0.1.0)
 *     0x60 / 0x61 / 0x62 / 0x63   Falcon-512  flash     (v0.2.0)
 *     0x64 / 0x65                  flash GET_SIG / DUMP_NVM
 *
 *   They share g_zknox storage but cannot run concurrently — each KEYGEN
 *   resets falcon_ready and overwrites the persistent secret material.
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

/* Falcon-512 streaming (v0.1.0) */
#include "handler_falcon512.h"
#include "handler_falcon512_sign.h"
#include "handler_falcon512_keygen_expand.h"

/* Falcon-512 flash variant (phase 2a + 2b, v0.2.0) */
#include "handler_falcon512_flash.h"

int apdu_dispatcher(const command_t *cmd) {
    LEDGER_ASSERT(cmd != NULL, "NULL cmd");

    if (cmd->cla != CLA) {
        return io_send_sw(SWO_INVALID_CLA);
    }

    buffer_t buf = {0};

    switch (cmd->ins) {
        case GET_VERSION:
            if (cmd->p1 != 0 || cmd->p2 != 0) {
                return io_send_sw(SWO_INCORRECT_P1_P2);
            }
            return handler_get_version();

        case GET_APP_NAME:
            if (cmd->p1 != 0 || cmd->p2 != 0) {
                return io_send_sw(SWO_INCORRECT_P1_P2);
            }
            return handler_get_app_name();

        case GET_PUBLIC_KEY:
            if (cmd->p1 > 1 || cmd->p2 > 0) {
                return io_send_sw(SWO_INCORRECT_P1_P2);
            }
            if (!cmd->data) {
                return io_send_sw(SWO_WRONG_DATA_LENGTH);
            }
            buf.ptr = cmd->data;
            buf.size = cmd->lc;
            buf.offset = 0;
            return handler_get_public_key(&buf, (bool) cmd->p1);

        case SIGN_TX:
            if ((cmd->p1 == P1_START && cmd->p2 != P2_MORE) ||
                cmd->p1 > P1_MAX ||
                (cmd->p2 != P2_LAST && cmd->p2 != P2_MORE)) {
                return io_send_sw(SWO_INCORRECT_P1_P2);
            }
            if (!cmd->data) {
                return io_send_sw(SWO_WRONG_DATA_LENGTH);
            }
            buf.ptr = cmd->data;
            buf.size = cmd->lc;
            buf.offset = 0;
            return handler_sign_tx(&buf, cmd->p1, (bool) (cmd->p2 & P2_MORE), false);

        case SIGN_TOKEN_TX:
            if ((cmd->p1 == P1_START && cmd->p2 != P2_MORE) ||
                cmd->p1 > P1_MAX ||
                (cmd->p2 != P2_LAST && cmd->p2 != P2_MORE)) {
                return io_send_sw(SWO_INCORRECT_P1_P2);
            }
            if (!cmd->data) {
                return io_send_sw(SWO_WRONG_DATA_LENGTH);
            }
            buf.ptr = cmd->data;
            buf.size = cmd->lc;
            buf.offset = 0;
            return handler_sign_tx(&buf, cmd->p1, (bool) (cmd->p2 & P2_MORE), true);

        case PROVIDE_TOKEN_INFO:
            buf.ptr = cmd->data;
            buf.size = cmd->lc;
            buf.offset = 0;
            return handler_provide_token_info(&buf);

        /* ---- Falcon-1024 post-quantum signature (v0.7.0) ---- */
        case FALCON_KEYGEN:
            if (cmd->p1 != 0 || cmd->p2 != 0) {
                return io_send_sw(SWO_INCORRECT_P1_P2);
            }
            if (cmd->lc != 0) {
                return io_send_sw(SWO_WRONG_DATA_LENGTH);
            }
            buf.ptr = cmd->data;
            buf.size = cmd->lc;
            buf.offset = 0;
            return handler_falcon_keygen(&buf);

        case FALCON_GET_PK:
            buf.ptr = cmd->data;
            buf.size = cmd->lc;
            buf.offset = 0;
            return handler_falcon_get_pk(&buf, cmd->p1, cmd->p2);

        case FALCON_SIGN:
            buf.ptr = cmd->data;
            buf.size = cmd->lc;
            buf.offset = 0;
            return handler_falcon_sign(&buf, cmd->p1, cmd->p2);

        case FALCON_KEYGEN_EXPAND:
            if (cmd->lc != 0) {
                return io_send_sw(SWO_WRONG_DATA_LENGTH);
            }
            buf.ptr = cmd->data;
            buf.size = cmd->lc;
            buf.offset = 0;
            return handler_falcon_keygen_expand(&buf, cmd->p1, cmd->p2);

        /* ---- Falcon-512 post-quantum signature (v0.1.0) ---- */
        case FALCON512_KEYGEN:
            if (cmd->p1 != 0 || cmd->p2 != 0) {
                return io_send_sw(SWO_INCORRECT_P1_P2);
            }
            if (cmd->lc != 0) {
                return io_send_sw(SWO_WRONG_DATA_LENGTH);
            }
            buf.ptr = cmd->data;
            buf.size = cmd->lc;
            buf.offset = 0;
            return handler_falcon512_keygen(&buf);

        case FALCON512_GET_PK:
            buf.ptr = cmd->data;
            buf.size = cmd->lc;
            buf.offset = 0;
            return handler_falcon512_get_pk(&buf, cmd->p1, cmd->p2);

        case FALCON512_SIGN:
            buf.ptr = cmd->data;
            buf.size = cmd->lc;
            buf.offset = 0;
            return handler_falcon512_sign(&buf, cmd->p1, cmd->p2);

        case FALCON512_KEYGEN_EXPAND:
            if (cmd->lc != 0) {
                return io_send_sw(SWO_WRONG_DATA_LENGTH);
            }
            buf.ptr = cmd->data;
            buf.size = cmd->lc;
            buf.offset = 0;
            return handler_falcon512_keygen_expand(&buf, cmd->p1, cmd->p2);

        /* ---- Falcon-512 flash variant (v0.2.0) ---- */
        case FALCON512_FLASH_KEYGEN:
            if (cmd->p1 != 0 || cmd->p2 != 0) {
                return io_send_sw(SWO_INCORRECT_P1_P2);
            }
            if (cmd->lc != 0) {
                return io_send_sw(SWO_WRONG_DATA_LENGTH);
            }
            buf.ptr = cmd->data;
            buf.size = cmd->lc;
            buf.offset = 0;
            return handler_falcon512_flash_keygen(&buf);

        case FALCON512_FLASH_GET_PK:
            buf.ptr = cmd->data;
            buf.size = cmd->lc;
            buf.offset = 0;
            return handler_falcon512_flash_get_pk(&buf, cmd->p1, cmd->p2);

        case FALCON512_FLASH_KEYGEN_EXPAND:
            if (cmd->lc != 0) {
                return io_send_sw(SWO_WRONG_DATA_LENGTH);
            }
            buf.ptr = cmd->data;
            buf.size = cmd->lc;
            buf.offset = 0;
            return handler_falcon512_flash_keygen_expand(&buf, cmd->p1, cmd->p2);

        case FALCON512_FLASH_SIGN:
            buf.ptr = cmd->data;
            buf.size = cmd->lc;
            buf.offset = 0;
            return handler_falcon512_flash_sign(&buf, cmd->p1, cmd->p2);

        case FALCON512_FLASH_GET_SIG:
            buf.ptr = cmd->data;
            buf.size = cmd->lc;
            buf.offset = 0;
            return handler_falcon512_flash_get_sig(&buf, cmd->p1, cmd->p2);

        case FALCON512_FLASH_DUMP_NVM:
            buf.ptr = cmd->data;
            buf.size = cmd->lc;
            buf.offset = 0;
            return handler_falcon512_flash_dump_nvm(&buf, cmd->p1, cmd->p2);

        default:
            return io_send_sw(SWO_INVALID_INS);
    }
}
