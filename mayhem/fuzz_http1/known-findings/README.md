# fuzz_http1 known findings (upstream bugs, left unfixed)

`http1-oob-read.bin` — heap-buffer-overflow read at lib/facil/http/parsers/http1_parser.h:838 in the HTTP/1 request/response
parser on a truncated message. Impact: out-of-bounds read of attacker-controlled network data.

Reproduce: `/mayhem/fuzz_http1-standalone mayhem/fuzz_http1/known-findings/http1-oob-read.bin`.
