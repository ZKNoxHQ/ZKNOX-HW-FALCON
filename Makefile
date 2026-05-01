# ****************************************************************************
#    ZKNOX
#    (c) 2025.
#
#   Licensed under the Apache License, Version 2.0 (the "License");
#   you may not use this file except in compliance with the License.
#   You may obtain a copy of the License at
#
#       http://www.apache.org/licenses/LICENSE-2.0
#
#   Unless required by applicable law or agreed to in writing, software
#   distributed under the License is distributed on an "AS IS" BASIS,
#   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#   See the License for the specific language governing permissions and
#   limitations under the License.
# ****************************************************************************

########################################
#         Docker passthrough           #
########################################
# Run `make docker` from the repo root (outside the container) to drop into
# the Ledger build container with the project bind-mounted at /app. Once
# inside, run `make load`, `make`, etc. as usual.
#
# Path-independent: $(CURDIR) is the directory of this Makefile, regardless
# of where you invoke make from. Replaces docker.sh.

DOCKER_IMAGE := ghcr.io/ledgerhq/ledger-app-builder/ledger-app-dev-tools:latest

# Detect if we're outside the container (no BOLOS_SDK set).
# When outside, the `docker` target is the only thing that should work.
# When inside, BOLOS_SDK is exported by the container's entrypoint.

.PHONY: docker docker-pull
docker:
	@echo ">>> Entering Ledger build container with $(CURDIR) -> /app"
	sudo docker run --rm -ti --user 1000:1000 --privileged \
	    -v /dev/bus/usb:/dev/bus/usb \
	    -v $(CURDIR):/app \
	    $(DOCKER_IMAGE)

docker-pull:
	sudo docker pull $(DOCKER_IMAGE)

# All other targets need BOLOS_SDK set (which the container provides).
ifeq ($(BOLOS_SDK),)
ifeq ($(filter docker docker-pull help,$(MAKECMDGOALS)),)
$(error Environment variable BOLOS_SDK is not set. Run `make docker` first to enter the build container.)
endif
else
include $(BOLOS_SDK)/Makefile.target
endif

########################################
#        Mandatory configuration       #
########################################
# Application name
APPNAME := FALCON1024

# Application version
APPVERSION_M = 2
APPVERSION_N = 3
APPVERSION_P = 1
APPVERSION = "$(APPVERSION_M).$(APPVERSION_N).$(APPVERSION_P)"

# Application source files
APP_SOURCE_PATH += src

# Comment out to remove SCA protection (Lin et al PKC 2025).
# Adds ~36% overhead on FALCON_SIGN; KEYGEN/KEYGEN_EXPAND unchanged.
DEFINES += FALCON_SCA_PROTECT=1


# Optimize for embedded


# Application icons following guidelines:
# https://developers.ledger.com/docs/embedded-app/design-requirements/#device-icon
ICON_NANOX = icons/app_zknox_14px.gif
ICON_NANOSP = icons/app_zknox_14px.gif
ICON_STAX = icons/app_zknox_32px.gif
ICON_FLEX = icons/app_zknox_40px.gif
ICON_APEX_P = icons/app_zknox_32px_apex.png

ifeq ($(TARGET_NAME),$(filter $(TARGET_NAME),TARGET_NANOX TARGET_NANOS2))
    # With the Nano NBGL Design, the Home Screen icon is the reverse of the App icon:
    # It should be on white background, with rounded corners.
    # This definition allows SDK Makefiles to automatically generate it based on the App icon.
    # Please note that the icon is dynamically generated, and declared in the .gitignore to avoid storing it.
    ICON_HOME_NANO = glyphs/home_zknox_14px.gif
endif

# Application allowed derivation curves.
# Possibles curves are: secp256k1, secp256r1, ed25519 and bls12381g1
# If your app needs it, you can specify multiple curves by using:
# `CURVE_APP_LOAD_PARAMS = <curve1> <curve2>`
CURVE_APP_LOAD_PARAMS = secp256k1 ed25519

# Application allowed derivation paths.
# You should request a specific path for your app.
# This serve as an isolation mechanism.
# Most application will have to request a path according to the BIP-0044
# and SLIP-0044 standards.
# If your app needs it, you can specify multiple path by using:
# `PATH_APP_LOAD_PARAMS = "44'/1'" "45'/1'"`
PATH_APP_LOAD_PARAMS = "44'/60'" "44'/9004'"   # 60 = Ethereum (ECDSA), 9004 = ZKNOX Falcon

# Setting to allow building variant applications
# - <VARIANT_PARAM> is the name of the parameter which should be set
#   to specify the variant that should be build.
# - <VARIANT_VALUES> a list of variant that can be build using this app code.
#   * It must at least contains one value.
#   * Values can be the app ticker or anything else but should be unique.
VARIANT_PARAM = COIN
VARIANT_VALUES = BOL

# Enabling DEBUG flag will enable PRINTF for speculos
#DEBUG = 1

# Enabling DEBUG_OVER_USB flag will enable PRINTF over USB
# This will force DISABLE_OS_IO_STACK_USE and add USB CDC profile
# The log can be displayed using a COM port terminal
#DEBUG_OVER_USB = 1

########################################
#     Application custom permissions   #
########################################
# See SDK `include/appflags.h` for the purpose of each permission
#HAVE_APPLICATION_FLAG_DERIVE_MASTER = 1
#HAVE_APPLICATION_FLAG_GLOBAL_PIN = 1
#HAVE_APPLICATION_FLAG_BOLOS_SETTINGS = 1
#HAVE_APPLICATION_FLAG_LIBRARY = 1

########################################
# Application communication interfaces #
########################################
ENABLE_BLUETOOTH = 1
#ENABLE_NFC = 1
ENABLE_NBGL_FOR_NANO_DEVICES = 1

########################################
#         NBGL custom features         #
########################################
ENABLE_NBGL_QRCODE = 1
#ENABLE_NBGL_KEYBOARD = 1
#ENABLE_NBGL_KEYPAD = 1

########################################
#       SWAP FEATURE FLAG      		   #
# This flag enables the swap feature   #
# in the Boilerplate application.      #
########################################
# This is a smart documentation inclusion. The full documentation is available at https://ledgerhq.github.io/app-exchange/
# --8<-- [start:variables]
ifeq ($(APPNAME), "Boilerplate")
# Two flags exist for enabling the SWAP
#   - ENABLE_SWAP           will lead to the enabling of the swap related C code of the standard_app
#                           AND will lead to the enabling of the APP_LOAD_PARAM required for os_lib_call working on device
#   - ENABLE_TESTING_SWAP:  will lead to the enabling of the swap related C code of the standard_app
#                           ONLY works on Speculos, not on device
# Testing only SWAP flag
ENABLE_TESTING_SWAP = 1
# Production enabled SWAP flag
# ENABLE_SWAP = 1
endif
# --8<-- [end:variables]

########################################
#          TLV & PKI features          #
########################################
# Both are used in the Dynamic Token example
ENABLE_TLV_LIBRARY = 1
ENABLE_PKI_LIBRARY = 1


########################################
#          Features disablers          #
########################################
# These advanced settings allow to disable some feature that are by
# default enabled in the SDK `Makefile.standard_app`.
#DISABLE_STANDARD_APP_FILES = 1
DISABLE_DEFAULT_IO_SEPROXY_BUFFER_SIZE = 1 # To allow custom size declaration
#DISABLE_STANDARD_APP_DEFINES = 1 # Will set all the following disablers
#DISABLE_STANDARD_SNPRINTF = 1
#DISABLE_STANDARD_USB = 1
#DISABLE_STANDARD_WEBUSB = 1
#DISABLE_DEBUG_LEDGER_ASSERT = 1
#DISABLE_DEBUG_THROW = 1

########################################
#       Extended APDU buffer size      #
########################################
# Default Ledger APDU buffer on Nano S+ is 260 B. We raise it so the host
# can stream the Falcon-1024 LDL tree in much larger chunks, cutting the
# APDU roundtrip overhead during sign. See DECISIONS.md (streaming tree
# protocol). Start with 2048; if the link step reports a RAM overflow,
# drop to 1024. 4096 is the theoretical upper bound for sub-10 APDU
# streaming but is unlikely to fit given the current BSS usage.
#DEFINES += IO_SEPROXYHAL_BUFFER_SIZE_B=4096

ifneq ($(BOLOS_SDK),)
include $(BOLOS_SDK)/Makefile.standard_app
endif
