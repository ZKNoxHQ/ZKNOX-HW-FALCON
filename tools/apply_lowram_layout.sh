#!/bin/sh
# Run from the repository root AFTER unzipping the delivery over the clone: removes the files that moved to legacy/.
set -e
git rm -q -r src/zknox/falcon src/zknox/zkn_common.h src/zknox/zkn_errors.h src/falcon_inner.h src/FALCON_ONLY_README.md \
  src/handler/handler_falcon.c src/handler/handler_falcon.h src/handler/handler_falcon_keygen_expand.c src/handler/handler_falcon_keygen_expand.h \
  src/handler/handler_falcon_sign.c src/handler/handler_falcon_sign.h src/handler/cx_outsourced.c src/handler/cx_outsourced.h \
  js/falcon1024-compliance-simple.js js/falcon1024-full-chain.js js/falcon1024-ledger-keygen-expand.js js/falcon1024-ledger-sign.js \
  js/falcon1024_yellow12_pk.bin js/falcon1024_yellow12_wire.bin
git add -A
echo "layout applied: legacy core under legacy/, low-RAM core under src/falcon_lowram/"
