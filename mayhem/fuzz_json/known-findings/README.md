# fuzz_json known findings (upstream bugs, left unfixed)

`json-unterminated-comment-hang.bin` — endless loop in `fio_json_parse` (lib/facil/fiobj/fio_json_parser.h, `/* ... */` comment case).
The loop `do { tmp = memchr(tmp, '/', limit - tmp); } while (tmp && tmp[-1] != '*');` never advances `tmp`
when a `/` not preceded by `*` is found, so it re-finds the same byte forever. Impact: denial of service on any
JSON input containing `/* ... / ...` without a closing `*/`. Fix: `tmp = memchr(tmp + 1, ...)` inside the loop.

Reproduce: `/mayhem/fuzz_json-standalone mayhem/fuzz_json/known-findings/json-unterminated-comment-hang.bin` (hangs).
