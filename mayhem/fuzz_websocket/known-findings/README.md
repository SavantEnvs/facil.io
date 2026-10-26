# fuzz_websocket known findings (upstream bugs, left unfixed)

`websocket-consume-length-2pow62-hang.bin` — `websocket_consume` (lib/facil/http/parsers/websocket_parser.h, the `while` loop at
~l.439) never returns when a complete frame is followed by a header whose 64-bit payload length is >= 2^62. For that header
`websocket_buffer_peek` answers `{packet_length 0, head_length 0}`; the loop condition `head_length + packet_length <= reminder`
is then always true, `reminder` and `pos` never advance, and the callback fires on the same frame forever. (When such a header is
the *first* one, `websocket_consume` correctly reports a protocol error; only the in-loop re-peek lacks that check.) Impact: a
remote peer pins a CPU with one 10-byte header. Fix: `if (!info.head_length) { websocket_on_protocol_error(udata); return 0; }`
after the in-loop `websocket_buffer_peek`.

The libFuzzer target skips exactly these inputs (`would_hang()` in fuzz_websocket.c, matches only that header), so the rest of
the parser keeps being fuzzed; the `-standalone` build does not skip.

Reproduce: `/mayhem/fuzz_websocket-standalone mayhem/fuzz_websocket/known-findings/websocket-consume-length-2pow62-hang.bin` (hangs).
