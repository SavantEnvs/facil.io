/* Harness-side round-trip / contract checks. Only the run-once -standalone reproducers (built with
 * -DMAYHEM_STRICT_INVARIANTS) abort on a violation; the libFuzzer binaries ignore it, so every
 * crash Mayhem reports has an application frame, never a harness one. */
#ifndef MAYHEM_INVARIANTS_H
#define MAYHEM_INVARIANTS_H
#include <stdlib.h>
#ifdef MAYHEM_STRICT_INVARIANTS
#define MAYHEM_INVARIANT_VIOLATED() abort()
#else
#define MAYHEM_INVARIANT_VIOLATED() ((void)0)
#endif
#endif
