#!/bin/sh
# Run from the repository root on the lowram-light branch, AFTER unzipping lowram-light.zip:
# removes what this branch does not carry (archived v0.7.0 core, core switch, layout helper).
set -e
git rm -q -r --ignore-unmatch legacy src/falcon_core.h tools/apply_lowram_layout.sh
git add -A
echo "lowram-light layout applied"
