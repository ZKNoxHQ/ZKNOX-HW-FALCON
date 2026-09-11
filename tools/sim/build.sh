#!/bin/sh
# Host simulation of the app's low-RAM Falcon APDUs, with the UNMODIFIED
# app sources (dispatcher + handler_fndsa + src/fndsa) linked against a tiny BOLOS shim.
# Usage: [SCA=0|1] [PERSIST=0|1] ./build.sh && python3 derive_seed.py && ./sim_lowram
set -e
SCA=${SCA:-1}
PERSIST=${PERSIST:-0}
S=${SRC:-../../src}
CF="-O2 -std=gnu11 -w -DAPPNAME=\"Falcon\" -DFNDSA_FALCON_R3=1 -DFNDSA_SAMPLER_PROTECT=$SCA -DFALCON_LR_PERSIST_KEY=$PERSIST -DFNDSA_SSE2=0 -DFNDSA_AVX2=0 -DFNDSA_NEON=0 -DFNDSA_64=0 -DFNDSA_ASM_CORTEXM4=0 -Ishim -I$S -I$S/handler -I$S/apdu -I$S/helper -I$S/falcon_lowram -I$S/zknox -I$S/zknox/keys -I$S/transaction"
mkdir -p obj
for f in $S/falcon_lowram/*.c; do gcc $CF -c $f -o obj/$(basename $f .c).o; done
gcc $CF -c $S/handler/handler_falcon_lowram.c -o obj/handler_falcon_lowram.o
gcc $CF -c $S/zknox/keys/derive.c -o obj/derive.o
gcc $CF -c $S/apdu/dispatcher.c -o obj/dispatcher.o
# host oracle (Falcon verification on the core's own primitives)
gcc $CF -c oracle.c -o obj/oracle.o
gcc $CF -c sim_lowram.c -o obj/sim_lowram.o
gcc obj/*.o -o sim_lowram -lm
echo "BUILD OK (SCA=$SCA PERSIST=$PERSIST)"
