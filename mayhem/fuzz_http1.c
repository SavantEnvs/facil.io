/* Fuzz the HTTP/1.x request/response parser, whole and fed in small pieces. */
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <http1_parser.h>

typedef struct {
  http1_parser_s p;
  size_t events;
  size_t sum;
  int error;
} state_s;

#define STATE(parser) ((state_s *)(parser))
static void touch(state_s *s, const char *d, size_t len) {
  for (size_t i = 0; i < len; ++i)
    s->sum += (uint8_t)d[i];
  ++s->events;
}
static int http1_on_request(http1_parser_s *p) { ++STATE(p)->events; return 0; }
static int http1_on_response(http1_parser_s *p) { ++STATE(p)->events; return 0; }
static int http1_on_method(http1_parser_s *p, char *m, size_t l) { touch(STATE(p), m, l); return 0; }
static int http1_on_status(http1_parser_s *p, size_t st, char *s, size_t l) {
  STATE(p)->sum += st;
  touch(STATE(p), s, l);
  return 0;
}
static int http1_on_path(http1_parser_s *p, char *d, size_t l) { touch(STATE(p), d, l); return 0; }
static int http1_on_query(http1_parser_s *p, char *d, size_t l) { touch(STATE(p), d, l); return 0; }
static int http1_on_version(http1_parser_s *p, char *d, size_t l) { touch(STATE(p), d, l); return 0; }
static int http1_on_header(http1_parser_s *p, char *n, size_t nl, char *d, size_t dl) {
  touch(STATE(p), n, nl);
  touch(STATE(p), d, dl);
  return 0;
}
static int http1_on_body_chunk(http1_parser_s *p, char *d, size_t l) { touch(STATE(p), d, l); return 0; }
static int http1_on_error(http1_parser_s *p) { STATE(p)->error = 1; return -1; }

static void run_whole(const uint8_t *data, size_t size) {
  uint8_t *buf = malloc(size);
  if (!buf)
    return;
  memcpy(buf, data, size);
  state_s s = {.p = HTTP1_PARSER_INIT};
  size_t off = 0;
  while (off < size && !s.error) {
    size_t used = http1_parse(&s.p, buf + off, size - off);
    if (!used)
      break;
    off += used;
  }
  free(buf);
}

static void run_chunked(const uint8_t *data, size_t size, size_t step) {
  uint8_t *buf = malloc(size + 1);
  if (!buf)
    return;
  state_s s = {.p = HTTP1_PARSER_INIT};
  size_t have = 0, fed = 0;
  while (fed < size && !s.error) {
    size_t n = size - fed < step ? size - fed : step;
    memcpy(buf + have, data + fed, n);
    have += n;
    fed += n;
    size_t off = 0;
    while (off < have && !s.error) {
      size_t used = http1_parse(&s.p, buf + off, have - off);
      if (!used)
        break;
      if (used > have - off)
        used = have - off;
      off += used;
    }
    memmove(buf, buf + off, have - off);
    have -= off;
  }
  free(buf);
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (size < 4)
    return -1;
  run_whole(data + 1, size - 1);
  run_chunked(data + 1, size - 1, (size_t)(data[0] & 15) + 1);
  return 0;
}
