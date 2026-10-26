/* Fuzz fio.h helpers: URL parsing, number conversion, Base64, SHA-1 / SHA-2.
 * Several ops check round-trip / streaming invariants (see invariants.h). */
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <fio.h>

#include "invariants.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (size < 2)
    return -1;
  const uint8_t op = data[0] % 5;
  data++;
  size--;

  switch (op) {
  case 0: {
    fio_url_s u = fio_url_parse((const char *)data, size);
    size_t sum = u.scheme.len + u.user.len + u.password.len + u.host.len +
                 u.port.len + u.path.len + u.query.len + u.target.len;
    fio_str_info_s *all[] = {&u.scheme, &u.user,  &u.password, &u.host,
                             &u.port,   &u.path,  &u.query,    &u.target};
    for (size_t i = 0; i < 8; ++i)
      for (size_t j = 0; j < all[i]->len; ++j)
        sum += (uint8_t)all[i]->data[j];
    if (sum == (size_t)-1)
      return -1;
    break;
  }
  case 1: {
    char *s = malloc(size + 1);
    if (!s)
      return -1;
    memcpy(s, data, size);
    s[size] = 0;
    char *e = s;
    (void)fio_atol(&e);
    e = s;
    (void)fio_atof(&e);
    free(s);
    break;
  }
  case 2: {
    char *enc = malloc(size * 4 / 3 + 8);
    char *dec = malloc(size + 8);
    char *raw = malloc(size + 8);
    if (!enc || !dec || !raw) {
      free(enc); free(dec); free(raw);
      return -1;
    }
    for (int url = 0; url < 2; ++url) {
      int n = url ? fio_base64url_encode(enc, (const char *)data, (int)size)
                  : fio_base64_encode(enc, (const char *)data, (int)size);
      int m = fio_base64_decode(dec, enc, n);
      if (m != (int)size || (size && memcmp(dec, data, size)))
        MAYHEM_INVARIANT_VIOLATED();
    }
    /* decoding arbitrary bytes must stay inside the documented buffer size */
    char *junk = malloc(size + 1);
    char *out = malloc(size / 4 * 3 + 3);
    if (junk && out) {
      memcpy(junk, data, size);
      junk[size] = 0;
      (void)fio_base64_decode(out, junk, (int)size);
    }
    free(junk);
    free(out);
    free(enc); free(dec); free(raw);
    break;
  }
  case 3: {
    size_t cut = data[0] % (size + 1);
    fio_sha1_s a = fio_sha1_init(), b = fio_sha1_init();
    char d1[20], d2[20];
    memcpy(d1, fio_sha1(&a, data, size), 20);
    fio_sha1_write(&b, data, cut);
    fio_sha1_write(&b, data + cut, size - cut);
    memcpy(d2, fio_sha1_result(&b), 20);
    if (memcmp(d1, d2, 20))
      MAYHEM_INVARIANT_VIOLATED();
    fio_sha2_variant_e vars[] = {SHA_256, SHA_384, SHA_512};
    for (size_t v = 0; v < 3; ++v) {
      fio_sha2_s x = fio_sha2_init(vars[v]), y = fio_sha2_init(vars[v]);
      char e1[64], e2[64];
      size_t dl = vars[v] == SHA_256 ? 32 : vars[v] == SHA_384 ? 48 : 64;
      fio_sha2_write(&x, data, size);
      memcpy(e1, fio_sha2_result(&x), dl);
      fio_sha2_write(&y, data, cut);
      fio_sha2_write(&y, data + cut, size - cut);
      memcpy(e2, fio_sha2_result(&y), dl);
      if (memcmp(e1, e2, dl))
        MAYHEM_INVARIANT_VIOLATED();
    }
    break;
  }
  default: {
    if (size < 9)
      return -1;
    int64_t num;
    memcpy(&num, data + 1, 8);
    uint8_t bases[] = {2, 8, 10, 16};
    char buf[130];
    for (size_t i = 0; i < 4; ++i)
      (void)fio_ltoa(buf, num, bases[i]);
    size_t l = fio_ltoa(buf, num, 10);
    char *e = buf;
    if (l >= sizeof(buf) || fio_atol(&e) != num)
      MAYHEM_INVARIANT_VIOLATED();
    double dbl;
    memcpy(&dbl, data + (size - 8), 8);
    for (size_t i = 0; i < 4; ++i)
      (void)fio_ftoa(buf, dbl, bases[i]);
    break;
  }
  }
  return 0;
}
