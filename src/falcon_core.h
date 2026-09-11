/*
 * falcon_core.h — selects the Falcon signing core compiled into the app.
 *
 *   FALCON_CORE_LOWRAM=1  (default, Makefile FALCON_CORE=lowram)
 *       Falcon Round 3 on Thomas Pornin's low-RAM core, c-fn-dsa-alt (src/falcon_lowram/):
 *       no LDL tree, no expand, keygen + sign fit in ~27 KB, INS 0x50..0x54.
 *   FALCON_CORE_LEGACY=1  (Makefile FALCON_CORE=legacy)
 *       The archived v0.7.0 tree-streaming implementation (legacy/src/:
 *       reference library + handler_falcon* handlers, INS 0x30..0x34).
 *
 * The two cores are exclusive: they need the same RAM.
 */
#pragma once

#if defined(FALCON_CORE_LEGACY) && FALCON_CORE_LEGACY
#undef FALCON_CORE_LOWRAM
#define FALCON_CORE_LOWRAM 0
#else
#undef FALCON_CORE_LEGACY
#define FALCON_CORE_LEGACY 0
#ifndef FALCON_CORE_LOWRAM
#define FALCON_CORE_LOWRAM 1
#endif
#endif
