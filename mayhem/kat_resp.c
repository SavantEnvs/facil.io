#include <stdio.h>
#include <string.h>
#include <resp_parser.h>

static int resp_on_message(resp_parser_s *p) { (void)p; printf("resp message\n"); return 0; }
static int resp_on_number(resp_parser_s *p, int64_t n) { (void)p; printf("resp number %lld\n", (long long)n); return 0; }
static int resp_on_okay(resp_parser_s *p) { (void)p; printf("resp ok\n"); return 0; }
static int resp_on_null(resp_parser_s *p) { (void)p; printf("resp null\n"); return 0; }
static int resp_on_start_string(resp_parser_s *p, size_t l) { (void)p; printf("resp string %zu\n", l); return 0; }
static int resp_on_string_chunk(resp_parser_s *p, void *d, size_t l) { (void)p; printf("resp chunk %.*s\n", (int)l, (char *)d); return 0; }
static int resp_on_end_string(resp_parser_s *p) { (void)p; return 0; }
static int resp_on_err_msg(resp_parser_s *p, void *d, size_t l) { (void)p; printf("resp err %.*s\n", (int)l, (char *)d); return 0; }
static int resp_on_start_array(resp_parser_s *p, size_t l) { (void)p; printf("resp array %zu\n", l); return 0; }
static int resp_on_parser_error(resp_parser_s *p) { (void)p; printf("resp error\n"); return -1; }

void kat_resp(void) {
  const char msg[] = "*3\r\n$3\r\nfoo\r\n:-42\r\n$-1\r\n";
  resp_parser_s p;
  memset(&p, 0, sizeof(p));
  printf("resp resend %zu\n", resp_parse(&p, msg, sizeof(msg) - 1));
}

