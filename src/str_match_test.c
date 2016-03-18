/*
 * str_match_test.c
 *
 * unit test for multiple string matching functions
 */
#include <stdarg.h>
#include <malloc.h>
#include "str_match.h"
#include "anon.h"

void matches_print(struct matches *matches, char *text) {
  unsigned int i;
  char tmp[1024];

  printf("no matches\n");
  for (i=0; i < matches->count; i++) {
    size_t len = matches->stop[i] - matches->start[i] + 1;
    if (len > 1024) {
      return;
    }
    memcpy(tmp, text + matches->start[i], len);
    tmp[len] = 0;
    printf("match %d: %s\n", i, tmp);
  }
}


void anon_print(FILE *f, struct matches *matches, char *text) {
  unsigned int i;

  if (matches->count == 0) {
    fprintf(f, "%s", text);
    return;
  }

  fprintf_nbytes(f, text, matches->start[0]);   /* nonmatching */
  for (i=0; i < matches->count; i++) {
    fprintf_anon_nbytes(f, text + matches->start[i], matches->stop[i] - matches->start[i] + 1);   /* matching */
    if (i < matches->count-1) {
      fprintf_nbytes(f, text + matches->stop[i] + 1, matches->start[i+1] - matches->stop[i] - 1); /* nonmatching */
    } else {
      fprintf(f, "%s", text + matches->stop[i] + 1);  /* nonmatching */
    }
  }
}


void str_match_test(str_match_ctx ctx, char *search) {
  struct matches matches;

  
  str_match_ctx_find_all_longest(ctx, (const unsigned char *)search, strlen(search), &matches);
  
  matches_print(&matches, (char *)search);

  printf("text being searched:   %s\n", search);  
  printf("anonymized string:     ");
  anon_print(stdout, &matches, (char *)search);
  printf("\n");
  printf("anonymized uri string: ");
  anon_print_uri(stdout, &matches, (char *)search);
  printf("\n");
}

char *text = "prefix middle suffix prefixmiddle middlesuffix prefixmiddlesuffix frogers2 velmad vdinkey";

char *text2 = "EXAMPLE TEXT WITH prefix AND middle BUT NOT suffix HAS prefixmiddle THIS middlesuffix TEST TEST prefixmiddlesuffix, IPSO FACTO frogers2 BLAHvelmadBLAH BLAHvdinkey EXCELSIOR";

char *text3 = "/root/shaggy/blahvelmablah/query?username=fred;subject=daphne;docname=blahscooby;alt=scoobyblah;path=velma";

// char *text4 = "/pca3.crl";
char *text4 = "/bg/api/Pickup.ashx?c={%22c%22:%225a9760de94b24d3c806a6400e76571fe%22,%22s%22:%2210.241.40.128%22}&m=[]&_=1458318857011";

int main() {
  str_match_ctx ctx;
  struct mallinfo info;

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

  str_match_test(ctx, text);
  str_match_test(ctx, text2);
  str_match_test(ctx, text3);
  str_match_test(ctx, text4);

  str_match_ctx_free(ctx);
  
  return 0;
}

