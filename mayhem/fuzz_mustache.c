/* Fuzz the mustache template loader and renderer.
 * Input: "<template>\0<json data>". Templates that contain '>' are rejected
 * because a partial tag ("{{> name}}") makes the loader read files by name. */
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <fiobj.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (!size)
    return -1;
  const uint8_t *sep = memchr(data, 0, size);
  size_t tlen = sep ? (size_t)(sep - data) : size;
  const uint8_t *json = sep ? sep + 1 : data + size;
  size_t jlen = sep ? size - tlen - 1 : 0;
  if (!tlen || memchr(data, '>', tlen))
    return -1;

  char *tmpl = malloc(tlen);
  char *jbuf = malloc(jlen + 1);
  if (!tmpl || !jbuf) {
    free(tmpl);
    free(jbuf);
    return -1;
  }
  memcpy(tmpl, data, tlen);
  memcpy(jbuf, json, jlen);
  jbuf[jlen] = 0;

  mustache_error_en err = MUSTACHE_OK;
  mustache_s *m = fiobj_mustache_new(.data = tmpl, .data_len = tlen, .err = &err);
  if (!m) {
    free(tmpl);
    free(jbuf);
    return -1;
  }

  FIOBJ obj = FIOBJ_INVALID;
  if (!fiobj_json2obj(&obj, jbuf, jlen))
    obj = FIOBJ_INVALID;
  FIOBJ out = fiobj_mustache_build(m, obj);
  fiobj_free(out);
  fiobj_free(obj);
  fiobj_mustache_free(m);
  free(tmpl);
  free(jbuf);
  return 0;
}
