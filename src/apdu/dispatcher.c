/*****************************************************************************
 *   Ledger App Boilerplate.
 *   Falcon-1024-only build (Dilithium and related INS removed).
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

        /* ---- Falcon-1024 post-quantum signature ---- */
        case FALCON_KEYGEN:
            /* v0.6.0: seed derived on-device via BIP-32. No data payload. */
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
            /* Sub-phase selector in P1 (0x00 COMPUTE_L0 … 0x05 GET_NEXT_L).
             * Data payload is always empty. */
            if (cmd->lc != 0) {
                return io_send_sw(SWO_WRONG_DATA_LENGTH);
            }
            buf.ptr = cmd->data;
            buf.size = cmd->lc;
            buf.offset = 0;
            return handler_falcon_keygen_expand(&buf, cmd->p1, cmd->p2);

        default:
            return io_send_sw(SWO_INVALID_INS);
    }
}
