/* Fuzz the FIOBJ JSON parser and serializer. */
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <fiobj.h>

size_t fiobj_hash_update_json(FIOBJ hash, const void *data, size_t len);

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (!size)
    return -1;
  char *buf = malloc(size + 1);
  if (!buf)
    return -1;
  memcpy(buf, data, size);
  buf[size] = 0;

  FIOBJ obj = FIOBJ_INVALID;
  size_t consumed = fiobj_json2obj(&obj, buf, size);
  if (!consumed) {
    fiobj_free(obj);
    free(buf);
    return -1;
  }

  for (uint8_t pretty = 0; pretty < 2; ++pretty) {
    FIOBJ json = fiobj_obj2json(obj, pretty);
    if (json) {
      fio_str_info_s s = fiobj_obj2cstr(json);
      FIOBJ again = FIOBJ_INVALID;
      fiobj_json2obj(&again, s.data, s.len);
      fiobj_free(again);
      fiobj_free(json);
    }
  }

  FIOBJ h = fiobj_hash_new();
  fiobj_hash_update_json(h, buf, size);
  fiobj_free(h);

  fiobj_free(obj);
  free(buf);
  return 0;
}
