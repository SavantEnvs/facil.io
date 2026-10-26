/* Known-answer probe: prints the result of fixed inputs through the library so that
 * mayhem/test.sh can diff them against golden values. */
#include <stdio.h>
#include <string.h>

#include <fiobj.h>
#include <fio.h>
#include <http.h>
#include <http1_parser.h>
#include <websocket_parser.h>

static void hex(const char *label, const void *d, size_t n) {
  printf("%s ", label);
  for (size_t i = 0; i < n; ++i)
    printf("%02x", ((const uint8_t *)d)[i]);
  printf("\n");
}

static void kat_json(void) {
  const char src[] = "{\"a\":[1,2.5,\"x\\ny\"],\"b\":null,\"c\":{\"d\":true}}";
  FIOBJ o = FIOBJ_INVALID;
  size_t n = fiobj_json2obj(&o, src, sizeof(src) - 1);
  printf("json consumed %zu\n", n);
  FIOBJ s = fiobj_obj2json(o, 0);
  fio_str_info_s i = fiobj_obj2cstr(s);
  printf("json out %.*s\n", (int)i.len, i.data);
  fiobj_free(s);
  fiobj_free(o);
  o = FIOBJ_INVALID;
  printf("json bad consumed %zu\n", fiobj_json2obj(&o, "{\"a\":", 5));
  fiobj_free(o);
}

static void kat_mustache(void) {
  const char tmpl[] = "Hi {{name}}! {{#items}}<{{n}}>{{/items}} {{&raw}} {{esc}}.";
  const char json[] = "{\"name\":\"World\",\"items\":[{\"n\":1},{\"n\":2}],\"raw\":\"<b>\",\"esc\":\"<b>\"}";
  mustache_error_en err = MUSTACHE_OK;
  mustache_s *m = fiobj_mustache_new(.data = tmpl, .data_len = sizeof(tmpl) - 1, .err = &err);
  FIOBJ d = FIOBJ_INVALID;
  fiobj_json2obj(&d, json, sizeof(json) - 1);
  FIOBJ out = fiobj_mustache_build(m, d);
  fio_str_info_s i = fiobj_obj2cstr(out);
  printf("mustache %.*s\n", (int)i.len, i.data);
  fiobj_free(out);
  fiobj_free(d);
  fiobj_mustache_free(m);
}

static void kat_fio(void) {
  char buf[128];
  int n = fio_base64_encode(buf, "foobar", 6);
  printf("base64 %.*s\n", n, buf);
  char dec[32];
  n = fio_base64_decode(dec, (char *)"Zm9vYmE=", 8);
  printf("base64 decoded %.*s\n", n, dec);
  fio_sha1_s s1 = fio_sha1_init();
  hex("sha1", fio_sha1(&s1, "abc", 3), 20);
  fio_sha2_s s2 = fio_sha2_init(SHA_256);
  hex("sha256", fio_sha2_256(&s2, "abc", 3), 32);
  fio_url_s u = fio_url_parse("http://user:pw@host.io:8080/p/a?q=1&r=2#t", 41);
  printf("url %.*s|%.*s|%.*s|%.*s|%.*s|%.*s|%.*s|%.*s\n", (int)u.scheme.len, u.scheme.data,
         (int)u.user.len, u.user.data, (int)u.password.len, u.password.data, (int)u.host.len,
         u.host.data, (int)u.port.len, u.port.data, (int)u.path.len, u.path.data,
         (int)u.query.len, u.query.data, (int)u.target.len, u.target.data);
  char num[] = "0x1F";
  char *e = num;
  printf("atol %lld\n", (long long)fio_atol(&e));
  size_t l = fio_ltoa(buf, -1234567, 10);
  printf("ltoa %.*s\n", (int)l, buf);
}

static void kat_http(void) {
  http_s h;
  memset(&h, 0, sizeof(h));
  h.query = fiobj_str_new("a=1&b=x%20y&c=2.5", 17);
  http_parse_query(&h);
  FIOBJ j = fiobj_obj2json(h.params, 0);
  fio_str_info_s i = fiobj_obj2cstr(j);
  printf("query %.*s\n", (int)i.len, i.data);
  fiobj_free(j);
  fiobj_free(h.params);
  fiobj_free(h.query);
  char out[64];
  ssize_t n = http_decode_url(out, "a%20b%2Bc+d", 11);
  printf("decode_url %zd %s\n", n, out);
  time_t t = 784111777;
  n = (ssize_t)http_time2str(out, t);
  printf("time %zd %s\n", n, out);
}

static size_t ev_sum;
static char ev_log[1024];
static size_t ev_len;
static void ev(const char *tag, const char *d, size_t l) {
  ev_len += (size_t)snprintf(ev_log + ev_len, sizeof(ev_log) - ev_len, "%s=%.*s;", tag, (int)l, d);
}
static int http1_on_request(http1_parser_s *p) { (void)p; ev("REQ", "", 0); return 0; }
static int http1_on_response(http1_parser_s *p) { (void)p; ev("RES", "", 0); return 0; }
static int http1_on_method(http1_parser_s *p, char *m, size_t l) { (void)p; ev("M", m, l); return 0; }
static int http1_on_status(http1_parser_s *p, size_t s, char *d, size_t l) { (void)p; (void)s; ev("S", d, l); return 0; }
static int http1_on_path(http1_parser_s *p, char *d, size_t l) { (void)p; ev("P", d, l); return 0; }
static int http1_on_query(http1_parser_s *p, char *d, size_t l) { (void)p; ev("Q", d, l); return 0; }
static int http1_on_version(http1_parser_s *p, char *d, size_t l) { (void)p; ev("V", d, l); return 0; }
static int http1_on_header(http1_parser_s *p, char *n, size_t nl, char *d, size_t dl) {
  (void)p; ev("HN", n, nl); ev("HV", d, dl); return 0;
}
static int http1_on_body_chunk(http1_parser_s *p, char *d, size_t l) { (void)p; ev("B", d, l); return 0; }
static int http1_on_error(http1_parser_s *p) { (void)p; ev("ERR", "", 0); return -1; }

static void kat_http1(void) {
  char req[] = "POST /a/b?x=1 HTTP/1.1\r\nHost: Example.COM\r\nContent-Length: 5\r\n\r\nhello";
  http1_parser_s p = HTTP1_PARSER_INIT;
  size_t n = http1_parse(&p, req, sizeof(req) - 1);
  printf("http1 consumed %zu/%zu %s\n", n, sizeof(req) - 1, ev_log);
  (void)ev_sum;
}

void kat_resp(void);

static int ws_frames;
static void websocket_on_unwrapped(void *u, void *m, uint64_t l, char f, char la, char t, unsigned char r) {
  (void)u; (void)r;
  printf("ws msg %.*s first=%d last=%d text=%d\n", (int)l, (char *)m, f, la, t);
  ++ws_frames;
}
static void websocket_on_protocol_ping(void *u, void *m, uint64_t l) { (void)u; printf("ws ping %.*s\n", (int)l, (char *)m); }
static void websocket_on_protocol_pong(void *u, void *m, uint64_t l) { (void)u; printf("ws pong %.*s\n", (int)l, (char *)m); }
static void websocket_on_protocol_close(void *u) { (void)u; printf("ws close\n"); }
static void websocket_on_protocol_error(void *u) { (void)u; printf("ws error\n"); }

static void kat_ws(void) {
  uint8_t buf[64];
  uint64_t n = websocket_server_wrap(buf, (void *)"hi", 2, 1, 1, 1, 0);
  hex("ws wrap", buf, n);
  printf("ws left %llu\n", (unsigned long long)websocket_consume(buf, n, NULL, 0));
  n = websocket_client_wrap(buf, (void *)"masked", 6, 2, 1, 1, 0);
  printf("ws client len %llu\n", (unsigned long long)n);
  printf("ws left %llu\n", (unsigned long long)websocket_consume(buf, n, NULL, 1));
  uint8_t ping[] = {0x89, 0x02, 'o', 'k'};
  websocket_consume(ping, sizeof(ping), NULL, 0);
}

int main(void) {
  kat_json();
  kat_mustache();
  kat_fio();
  kat_http();
  kat_http1();
  kat_resp();
  kat_ws();
  return 0;
}
