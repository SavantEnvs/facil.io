# fuzz_fio_util known findings (upstream bugs, left unfixed)

Each `.bin` replays with `/mayhem/fuzz_fio_util-standalone <file>`. The first byte selects the op (`data[0] % 5`: 0 url, 1 atol/atof,
2 base64, 3 sha1/sha2, 4 ltoa/ftoa). Round-trip and split-write checks abort only in `-standalone`
(`MAYHEM_INVARIANT_VIOLATED()` in `mayhem/invariants.h`); in the libFuzzer binary they are no-ops, so the sanitizer reports below are
what Mayhem sees. The library functions are called with ordinary arguments, so these are library bugs, not harness misuse.

## `base64-decode-reads-before-buffer.bin` (op 2) — `fio_base64_decode`, `fio.c:8629`

The `finish:` block reads `encoded[-1]` and `encoded[-2]` to strip `=` padding. When the input has no decodable characters
(here `!!!!`), `encoded` was never advanced, so both reads land before the buffer: ASan heap-buffer-overflow READ.
This is the root cause of four of the six defects Mayhem reports for this target.
Fix: only inspect the previous bytes when something was consumed, `if (written > 0 && encoded[-1] == '=')`, and `written > 0` on the
nested `encoded[-2]` check.

## `base64-decode-writes-before-buffer.bin` (op 2) — `fio_base64_decode`, same block

Input `AAA=AAAA`: the first 4-byte group contains `=`, which is not decodable, so the decoder jumps to `finish:` with `written == 0`.
`encoded[-1]` is that `=`, so `target--` runs and `*target = 0` writes one byte before the output buffer (ASan heap-buffer-overflow
WRITE). Same one-line guard as above fixes it.

## `base64-trailing-A-truncation.bin` (op 2) — `fio_base64_encode` / `fio_base64_decode`

The round trip is lossy: a payload whose final decoded bytes are zero is truncated, because the decoder's "skip unknown data at end"
loop treats trailing `A` characters (value 0) as padding. Impact: silent data corruption. Reproduce:
`/mayhem/fuzz_fio_util-standalone mayhem/fuzz_fio_util/known-findings/base64-trailing-A-truncation.bin` aborts in the base64
round-trip check of `fuzz_fio_util.c` (op 2, `m != size || memcmp`).

## `sha1-sha2-split-write-wrong-digest.bin` (op 3) — `fio_sha1_write`, `fio_sha2_write`

Writing 1 byte and then 69 more gives a different digest than hashing the 70 bytes at once. After the buffered block is flushed,
the trailing `memcpy(s->buffer + in_buffer, data, len)` still uses the `in_buffer` offset computed before the flush; the tail belongs at
`s->buffer`. `fio_sha2_write` has the same line in both its 128-byte and 64-byte block variants.
Fix: `memcpy(s->buffer, data, len)` in each. For this short input no sanitizer fires (the stale offset stays inside the struct), so the
wrong digest is only visible in `-standalone`, where the digest comparison aborts; the libFuzzer build cannot catch it.

`sha1-write-stack-overflow.bin` (op 3) is the same bug with a longer tail: 60 bytes, then 43 more. The 40-byte tail is copied to
`s->buffer + 60`, past the end of the 96-byte `fio_sha1_s` on the harness stack: ASan stack-buffer-overflow WRITE in `fio_sha1_write`.
This is the sanitizer-visible form Mayhem reports.

## `ltoa-int64-min-overflow.bin` (op 4) — `fio_ltoa`, `fio.c:4191`

`num = 0 - num` for base 8 is a signed overflow on `INT64_MIN` (UBSan halts). Without UBSan the value stays negative, `num >> 3` is an
arithmetic shift that never reaches 0, and the digit loop writes past the 48-byte `buf` (stack overflow). The base 10 and rare-base
branches negate the same way.
Fix: negate into a `uint64_t` (`uint64_t un = (uint64_t)num; if (num < 0) un = 0 - un;`) and loop on `un`.
After that fix `-standalone` still aborts on this input, but only in the harness' `fio_atol(fio_ltoa(INT64_MIN)) == INT64_MIN` check:
`fio_atol` saturates to `INT64_MIN + 1`.

## `url-parse-scheme-overread.bin` (op 0) — `fio_url_parse`, `fio.c:4858`

Input `a:/`: at the `:` the code tests `pos + 2 <= end` and then reads `pos[2]`, which is `end`, one byte past the input
(ASan heap-buffer-overflow READ).
Fix: `pos + 2 < end`.
