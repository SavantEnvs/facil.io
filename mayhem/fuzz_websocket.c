/* Fuzz the WebSocket frame parser and check wrap -> consume round trips. */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <websocket_parser.h>

#include "invariants.h"

typedef struct {
  size_t frames;
  size_t errors;
  size_t sum;
  const uint8_t *expect;
  size_t expect_len;
  int check;
} ws_state_s;

static void websocket_on_unwrapped(void *udata, void *msg, uint64_t len,
                                   char first, char last, char text,
                                   unsigned char rsv) {
  ws_state_s *s = udata;
  (void)first; (void)last; (void)text; (void)rsv;
  for (uint64_t i = 0; i < len; ++i)
    s->sum += ((uint8_t *)msg)[i];
  if (s->check && (len != s->expect_len ||
                   (len && memcmp(msg, s->expect, len))))
    MAYHEM_INVARIANT_VIOLATED();
  ++s->frames;
}
static void websocket_on_protocol_ping(void *udata, void *msg, uint64_t len) {
  ws_state_s *s = udata;
  for (uint64_t i = 0; i < len; ++i)
    s->sum += ((uint8_t *)msg)[i];
  ++s->frames;
}
static void websocket_on_protocol_pong(void *udata, void *msg, uint64_t len) {
  websocket_on_protocol_ping(udata, msg, len);
}
static void websocket_on_protocol_close(void *udata) { ++((ws_state_s *)udata)->frames; }
static void websocket_on_protocol_error(void *udata) { ++((ws_state_s *)udata)->errors; }

#ifndef MAYHEM_STRICT_INVARIANTS
/* websocket_consume() never returns when a frame is followed by a header whose 64-bit payload length
 * is >= 2^62: websocket_buffer_peek() answers {0,0,0} and the loop never advances (a real upstream
 * bug, reproducer in known-findings/). Skip exactly those inputs so the rest of the parser keeps
 * getting fuzzed; the -standalone build does not skip, and replays the reproducer. */
static int would_hang(const uint8_t *data, size_t size) {
  uint64_t rem = size;
  const uint8_t *pos = data;
  struct websocket_packet_info_s info = websocket_buffer_peek((void *)pos, rem);
  if (!info.head_length || info.head_length + info.packet_length > rem)
    return 0;
  while (info.head_length + info.packet_length <= rem) {
    rem -= info.head_length + info.packet_length;
    if (!rem)
      return 0;
    pos += info.head_length + info.packet_length;
    info = websocket_buffer_peek((void *)pos, rem);
    if (!info.head_length)
      return 1;
  }
  return 0;
}
#endif

static void consume_all(const uint8_t *data, size_t size, uint8_t require_mask,
                        ws_state_s *s) {
  uint8_t *buf = malloc(size ? size : 1);
  if (!buf)
    return;
  memcpy(buf, data, size);
  uint64_t rem = size;
  while (rem) {
    uint64_t left = websocket_consume(buf, rem, s, require_mask);
    if (!left || left == rem)
      break;
    rem = left;
  }
  free(buf);
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (size < 2)
    return -1;
  const uint8_t mode = data[0];
  data++;
  size--;

  ws_state_s raw = {0};
#ifndef MAYHEM_STRICT_INVARIANTS
  if (would_hang(data, size))
    return -1;
#endif
  consume_all(data, size, mode & 1, &raw);

  /* a wrapped message must come back unchanged */
  if (size <= 60000) {
    uint8_t *wrapped = malloc(websocket_wrapped_len(size) + 4 + 16);
    if (!wrapped)
      return 0;
    ws_state_s rt = {.expect = data, .expect_len = size, .check = 1};
    unsigned char opcode = (mode & 2) ? 2 : 1;
    uint64_t n;
    if (mode & 4) {
      n = websocket_client_wrap(wrapped, (void *)data, size, opcode, 1, 1, 0);
      consume_all(wrapped, n, 1, &rt);
    } else {
      n = websocket_server_wrap(wrapped, (void *)data, size, opcode, 1, 1, 0);
      consume_all(wrapped, n, 0, &rt);
    }
    if (rt.frames != 1 || rt.errors)
      MAYHEM_INVARIANT_VIOLATED();
    free(wrapped);
  }
  return 0;
}
