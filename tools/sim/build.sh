#!/bin/sh
# Host simulation of the app's low-RAM Falcon APDUs, with the UNMODIFIED
# app sources (dispatcher + handler_fndsa + src/fndsa) linked against a tiny BOLOS shim.
# Usage: ./build.sh [SCA=0|1] && python3 derive_seed.py && ./sim_lowram
set -e
SCA=${SCA:-1}
S=${SRC:-../../src}
CF="-O2 -std=gnu11 -w -DAPPNAME=\"Falcon\" -DFALCON_CORE_LOWRAM=1 -DFNDSA_FALCON_R3=1 -DFNDSA_SAMPLER_PROTECT=$SCA -DFNDSA_SSE2=0 -DFNDSA_AVX2=0 -DFNDSA_NEON=0 -DFNDSA_64=0 -DFNDSA_ASM_CORTEXM4=0 -Ishim -I$S -I$S/handler -I$S/apdu -I$S/helper -I$S/falcon_lowram -I$S/zknox -I$S/zknox/keys -I$S/transaction"
mkdir -p obj objv
for f in $S/falcon_lowram/*.c; do gcc $CF -c $f -o obj/$(basename $f .c).o; done
gcc $CF -c $S/handler/handler_falcon_lowram.c -o obj/handler_falcon_lowram.o
gcc $CF -c $S/zknox/keys/derive.c -o obj/derive.o
gcc $CF -c $S/apdu/dispatcher.c -o obj/dispatcher.o
# verification-only build of the archived Falcon reference library (host oracle): verify_raw, hash_to_point
L=${LEGACY:-../../legacy/src}
CV="-O2 -std=gnu11 -w -DFALCON_FPEMU=1 -I$L/zknox/falcon"
for f in vrfy common shake codec fpr; do gcc $CV -c $L/zknox/falcon/$f.c -o objv/$f.o; done
gcc $CF -c sim_lowram.c -o obj/sim_lowram.o
gcc $CV -c oracle.c -o obj/oracle.o
gcc obj/*.o objv/*.o -o sim_lowram -lm
echo "BUILD OK (SCA=$SCA)"
