/* Fuzz the HTTP request-parameter helpers: query string, Cookie header and
 * request body (urlencoded / JSON / multipart) parsing, plus URL decoding.
 * Input: "<query>\0<cookie>\0<content-type>\0<body>". */
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <fiobj.h>
#include <http.h>

static const uint8_t *field(const uint8_t **p, const uint8_t *end, size_t *len) {
  const uint8_t *start = *p;
  const uint8_t *z = memchr(start, 0, (size_t)(end - start));
  if (z) {
    *len = (size_t)(z - start);
    *p = z + 1;
  } else {
    *len = (size_t)(end - start);
    *p = end;
  }
  return start;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (size < 4)
    return -1;
  const uint8_t *p = data, *end = data + size;
  size_t qlen, clen, tlen;
  const uint8_t *q = field(&p, end, &qlen);
  const uint8_t *c = field(&p, end, &clen);
  const uint8_t *t = field(&p, end, &tlen);
  size_t blen = (size_t)(end - p);

  http_s h;
  memset(&h, 0, sizeof(h));
  h.query = fiobj_str_new((const char *)q, qlen);
  h.headers = fiobj_hash_new();
  FIOBJ k = fiobj_str_new("cookie", 6);
  fiobj_hash_set(h.headers, k, fiobj_str_new((const char *)c, clen));
  fiobj_free(k);
  k = fiobj_str_new("content-type", 12);
  fiobj_hash_set(h.headers, k, fiobj_str_new((const char *)t, tlen));
  fiobj_free(k);
  h.body = fiobj_data_newstr();
  fiobj_data_write(h.body, (void *)p, blen);

  http_parse_cookies(&h, 1);
  http_parse_query(&h);
  http_parse_body(&h);

  char *dec = malloc(size + 1);
  if (dec) {
    char *s = malloc(size + 1);
    if (s) {
      memcpy(s, data, size);
      s[size] = 0;
      http_decode_url(dec, s, size);
      http_decode_path(dec, s, size);
      free(s);
    }
    free(dec);
  }

  fiobj_free(h.params);
  fiobj_free(h.cookies);
  fiobj_free(h.body);
  fiobj_free(h.headers);
  fiobj_free(h.query);
  return 0;
}
