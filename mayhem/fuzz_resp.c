/* Fuzz the Redis RESP protocol parser, whole and fed in small pieces. */
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <resp_parser.h>

#include "invariants.h"

typedef struct {
  resp_parser_s p;
  size_t events;
  size_t sum;
  int error;
} resp_state_s;
#define ST(parser) ((resp_state_s *)(parser))

static int resp_on_message(resp_parser_s *p) { ++ST(p)->events; return 0; }
static int resp_on_number(resp_parser_s *p, int64_t n) { ST(p)->sum += (size_t)n; return 0; }
static int resp_on_okay(resp_parser_s *p) { ++ST(p)->events; return 0; }
static int resp_on_null(resp_parser_s *p) { ++ST(p)->events; return 0; }
static int resp_on_start_string(resp_parser_s *p, size_t l) { ST(p)->sum += l; return 0; }
static int resp_on_string_chunk(resp_parser_s *p, void *d, size_t l) {
  for (size_t i = 0; i < l; ++i)
    ST(p)->sum += ((uint8_t *)d)[i];
  return 0;
}
static int resp_on_end_string(resp_parser_s *p) { ++ST(p)->events; return 0; }
static int resp_on_err_msg(resp_parser_s *p, void *d, size_t l) {
  for (size_t i = 0; i < l; ++i)
    ST(p)->sum += ((uint8_t *)d)[i];
  return 0;
}
static int resp_on_start_array(resp_parser_s *p, size_t l) { ST(p)->sum += l; return 0; }
static int resp_on_parser_error(resp_parser_s *p) { ST(p)->error = 1; return -1; }

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (size < 2)
    return -1;
  const size_t step = (size_t)(data[0] & 15) + 1;
  data++;
  size--;

  {
    uint8_t *buf = malloc(size);
    if (!buf)
      return -1;
    memcpy(buf, data, size);
    resp_state_s s = {{0}};
    size_t off = 0;
    while (off < size && !s.error) {
      size_t resend = resp_parse(&s.p, buf + off, size - off);
      if (resend >= size - off)
        break;
      off = size - resend;
    }
    free(buf);
  }
  {
    uint8_t *buf = malloc(size + 1);
    if (!buf)
      return -1;
    resp_state_s s = {{0}};
    size_t have = 0, fed = 0;
    while (fed < size && !s.error) {
      size_t n = size - fed < step ? size - fed : step;
      memcpy(buf + have, data + fed, n);
      have += n;
      fed += n;
      size_t resend = resp_parse(&s.p, buf, have);
      if (resend > have) {
        /* parser claims more unparsed bytes than it was given: a parser bug, not ours to crash on */
        MAYHEM_INVARIANT_VIOLATED();
        break;
      }
      memmove(buf, buf + have - resend, resend);
      have = resend;
    }
    free(buf);
  }
  return 0;
}
