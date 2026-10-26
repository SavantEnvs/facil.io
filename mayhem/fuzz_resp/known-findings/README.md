# fuzz_resp known findings (upstream bugs, left unfixed)

`resp-resend-exceeds-length.bin` — the RESP parser (resp_parser.h) returns a "bytes still needed" value larger than the bytes
already buffered for a chunked bulk string; a caller doing `memmove(buf, buf + consumed, have - consumed)` underflows. The `-standalone` build
(strict invariants) aborts on `resend > have`; the libFuzzer target just stops feeding that input.

Reproduce: `/mayhem/fuzz_resp-standalone mayhem/fuzz_resp/known-findings/resp-resend-exceeds-length.bin`.
