# fuzz_mustache known findings (upstream bugs, left unfixed)

`json-numeral-table-index-255.bin` — `JSON_NUMERAL[*tmp]` (fio_json_parser.h:456) indexes a `uint8_t[255]` table with a byte
that can be 255, a one-byte out-of-bounds read (UBSan array-bounds). Reached via the JSON/mustache data parser after a number
followed by byte 0xFF. Impact: 1-byte global over-read. Fix: size the table 256.

Reproduce: `/mayhem/fuzz_mustache-standalone mayhem/fuzz_mustache/known-findings/json-numeral-table-index-255.bin`.
