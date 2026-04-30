#pragma once

#include <stdbool.h>  // bool

#if defined(TARGET_NANOX) || defined(TARGET_NANOS2)
#define ICON_APP_ZKNOX   C_app_zknox_14px
#define ICON_APP_HOME    C_home_zknox_14px
#define ICON_APP_WARNING C_icon_warning
#elif defined(TARGET_STAX) || defined(TARGET_FLEX)
#define ICON_APP_ZKNOX   C_app_zknox_64px
#define ICON_APP_HOME    ICON_APP_ZKNOX
#define ICON_APP_WARNING C_Warning_64px
#elif defined(TARGET_APEX_P)
#define ICON_APP_ZKNOX   C_app_zknox_48px
#define ICON_APP_HOME    ICON_APP_ZKNOX
#define ICON_APP_WARNING LARGE_WARNING_ICON
#endif

/**
 * Callback to reuse action with approve/reject in step FLOW.
 */
typedef void (*action_validate_cb)(bool);

/**
 * Display address on the device and ask confirmation to export.
 *
 * @return 0 if success, negative integer otherwise.
 *
 */
int ui_display_address(void);

/**
 * Display transaction information on the device and ask confirmation to sign.
 *
 * @return 0 if success, negative integer otherwise.
 *
 */
int ui_display_transaction(void);

/**
 * Display blind-signed transaction warning.
 *
 * @return 0 if success, negative integer otherwise.
 *
 */
int ui_display_blind_signed_transaction(void);

int ui_display_blind_sign_hash(void);

/**
 * Display token transaction information on the device and ask confirmation.
 *
 * @return 0 if success, negative integer otherwise.
 */
int ui_display_token_transaction(void);
