/* Drive the FIOBJ String / Array / Hash / Data containers with an op stream. */
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <fiobj.h>

typedef struct {
  const uint8_t *p;
  size_t left;
} rd_s;

static uint8_t rd8(rd_s *r) {
  if (!r->left)
    return 0;
  --r->left;
  return *r->p++;
}
static int64_t rdpos(rd_s *r) { return (int64_t)(int8_t)rd8(r) / 4; }
static size_t rdbytes(rd_s *r, const uint8_t **out) {
  size_t n = rd8(r) & 63;
  if (n > r->left)
    n = r->left;
  *out = r->p;
  r->p += n;
  r->left -= n;
  return n;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (size < 2)
    return -1;
  rd_s r = {data + 1, size - 1};
  FIOBJ ary = fiobj_ary_new();
  FIOBJ hash = fiobj_hash_new();
  FIOBJ str = fiobj_str_new(NULL, 0);
  FIOBJ io = (data[0] & 1) ? fiobj_data_newtmpfile() : fiobj_data_newstr();

  for (unsigned ops = 0; r.left && ops < 512; ++ops) {
    const uint8_t *b;
    size_t n;
    switch (rd8(&r) % 28) {
    case 0:
      n = rdbytes(&r, &b);
      fiobj_ary_push(ary, fiobj_str_new((const char *)b, n));
      break;
    case 1:
      n = rdbytes(&r, &b);
      fiobj_ary_unshift(ary, fiobj_str_new((const char *)b, n));
      break;
    case 2:
      fiobj_free(fiobj_ary_pop(ary));
      break;
    case 3:
      fiobj_free(fiobj_ary_shift(ary));
      break;
    case 4:
      fiobj_ary_remove(ary, rdpos(&r));
      break;
    case 5: {
      int64_t pos = rdpos(&r);
      fiobj_ary_set(ary, fiobj_num_new(pos), pos);
      break;
    }
    case 6:
      (void)fiobj_ary_index(ary, rdpos(&r));
      break;
    case 7:
      fiobj_ary_compact(ary);
      break;
    case 8: {
      const uint8_t *vb;
      n = rdbytes(&r, &b);
      size_t vn = rdbytes(&r, &vb);
      FIOBJ key = fiobj_str_new((const char *)b, n);
      fiobj_hash_set(hash, key, fiobj_str_new((const char *)vb, vn));
      fiobj_free(key);
      break;
    }
    case 9: {
      n = rdbytes(&r, &b);
      FIOBJ key = fiobj_str_new((const char *)b, n);
      (void)fiobj_hash_get(hash, key);
      (void)fiobj_hash_haskey(hash, key);
      fiobj_free(key);
      break;
    }
    case 10: {
      n = rdbytes(&r, &b);
      FIOBJ key = fiobj_str_new((const char *)b, n);
      fiobj_hash_delete(hash, key);
      fiobj_free(key);
      break;
    }
    case 11: {
      n = rdbytes(&r, &b);
      FIOBJ key = fiobj_str_new((const char *)b, n);
      fiobj_free(fiobj_hash_remove(hash, key));
      fiobj_free(key);
      break;
    }
    case 12:
      fiobj_hash_rehash(hash);
      break;
    case 13:
      fiobj_hash_clear(hash);
      break;
    case 14:
      n = rdbytes(&r, &b);
      fiobj_str_write(str, (const char *)b, n);
      break;
    case 15:
      fiobj_str_write_i(str, rdpos(&r) * 1000003);
      break;
    case 16:
      fiobj_str_resize(str, (size_t)rd8(&r) * 3);
      break;
    case 17:
      fiobj_str_compact(str);
      break;
    case 18:
      fiobj_str_clear(str);
      break;
    case 19:
      fiobj_str_concat(str, str);
      break;
    case 20:
      n = rdbytes(&r, &b);
      fiobj_data_write(io, (void *)b, n);
      break;
    case 21:
      fiobj_data_seek(io, rdpos(&r));
      break;
    case 22:
      (void)fiobj_data_read(io, rdpos(&r));
      break;
    case 23:
      (void)fiobj_data_read2ch(io, rd8(&r));
      break;
    case 24: {
      int64_t start = rdpos(&r);
      (void)fiobj_data_pread(io, start, rd8(&r));
      break;
    }
    case 25:
      n = rdbytes(&r, &b);
      fiobj_data_puts(io, (void *)b, n);
      break;
    case 26: {
      int64_t off = rdpos(&r);
      FIOBJ slice = fiobj_data_slice(io, off, rd8(&r));
      if (slice) {
        (void)fiobj_data_read(slice, 0);
        fiobj_free(slice);
      }
      break;
    }
    case 27:
      fiobj_free(fiobj_obj2json(ary, 0));
      fiobj_free(fiobj_obj2json(hash, 1));
      fiobj_free(fiobj_obj2json(str, 0));
      break;
    }
  }
  fiobj_free(io);
  fiobj_free(str);
  fiobj_free(hash);
  fiobj_free(ary);
  return 0;
}
