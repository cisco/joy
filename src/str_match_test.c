/*
 * str_match_test.c
 *
 * unit test for multiple string matching functions
 */
#include <stdarg.h>
#include <malloc.h>
#include "str_match.h"

char *text = "prefix middle suffix prefixmiddle middlesuffix prefixmiddlesuffix frogers2 velmad vdinkey";

int main() {
  str_match_ctx ctx;
  struct matches matches;
  struct mallinfo info;
  char *search = text;

  info = mallinfo();
  printf ("allocated space before loading context:  %d bytes\n", info.uordblks);
  
  ctx = str_match_ctx_alloc();
  if (ctx == NULL) {
    fprintf(stderr, "error: could not allocate string matching context\n");
    return -1;
  }
  if (str_match_ctx_init_from_file(ctx, "test/userid-example.txt") != 0) {
    fprintf(stderr, "error: could not init string matching context from file\n");
    exit(EXIT_FAILURE);
  }
  
  info = mallinfo();
  printf ("allocated space after loading context:  %d bytes\n", info.uordblks);
  
  printf("text being searched: %s\n", search);
  
  str_match_ctx_find_all_longest(ctx, (const unsigned char *)search, strlen(text), &matches);
  
  matches_print(&matches, (char *)search);
  
  str_match_ctx_free(ctx);
  
  return 0;
}

