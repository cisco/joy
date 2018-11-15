
bin_PROGRAMS = joy unit_test joy_api_test joy_api_test2 jfd-anon joy-anon str_match_test
joy_SOURCES = \
	../src/p2f.c \
	../src/osdetect.c \
	../src/anon.c \
	../src/pkt_proc.c \
	../src/nfv9.c \
	../src/tls.c \
	../src/classify.c \
	../src/radix_trie.c \
	../src/hdr_dsc.c \
	../src/procwatch.c \
	../src/addr_attr.c \
	../src/addr.c \
	../src/wht.c \
	../src/http.c \
	../src/str_match.c \
	../src/acsm.c \
	../src/dns.c \
	../src/example.c \
	../src/updater.c \
	../src/ipfix.c \
	../src/ssh.c \
	../src/ike.c \
	../src/salt.c \
	../src/parson.c \
	../src/fingerprint.c \
	../src/ppi.c \
	../src/utils.c \
	../src/dhcp.c \
	../src/payload.c \
	../src/config.c \
	../src/proto_identify.c \
	../src/fp_tls.c \
	../src/extractor.c \
	../src/joy.c 

unit_test_SOURCES = ../src/unit_test.c
joy_api_test_SOURCES = ../src/joy_api_test.c
joy_api_test2_SOURCES = ../src/joy_api_test2.c
jfd_anon_SOURCES = \
	../src/jfd-anon.c \
	../src/anon.c \
	../src/addr.c \
	../src/str_match.c \
	../src/acsm.c

joy_anon_SOURCES = \
	../src/anon.c \
	../src/addr.c \
	../src/str_match.c \
	../src/acsm.c \
	../src/joy-anon.c

str_match_test_SOURCES = ../src/str_match_test.c



joy_CFLAGS = -I ../src/include -DJOY_LIB_API -I $(SSL_CFLAGS) $(LIBCURL_CFLAGS) $(AM_CFLAGS)
unit_test_CFLAGS = -I../src/include  -I $(SSL_CFLAGS) $(AM_CFLAGS)
jfd_anon_CFLAGS = -I../src/include  -DFORCED_COMPRESSED_OUTPUT_OFF=1 -I $(SSL_CFLAGS) $(AM_CFLAGS)
joy_anon_CFLAGS = -I../src/include  -DFORCED_COMPRESSED_OUTPUT_OFF=1 -I $(SSL_CFLAGS) $(AM_CFLAGS)
joy_api_test_CFLAGS = -I../src/include -DFORCED_COMPRESSED_OUTPUT_OFF=1 -I $(SSL_CFLAGS) $(AM_CFLAGS)
joy_api_test2_CFLAGS = -I../src/include -DFORCED_COMPRESSED_OUTPUT_OFF=1 -I $(SSL_CFLAGS) $(AM_CFLAGS)
str_match_test_CFLAGS = -I../src/include -DFORCED_COMPRESSED_OUTPUT_OFF=1 -I $(SSL_CFLAGS) $(AM_CFLAGS)

if BUILD_MAC
joy_LDFLAGS = $(SSL_LDFLAGS) $(LIBCURL_CFLAGS) -lcrypto -lm -lpcap -lcurl -lpthread -Wl,-pie
unit_test_LDFLAGS = -lm -lpcap -L../lib/.libs -ljoy -Wl,-pie
joy_anon_LDFLAGS = $(SSL_LDFLAGS) -lcrypto  -Wl,-pie
jfd_anon_LDFLAGS = $(SSL_LDFLAGS) -lcrypto  -Wl,-pie
str_match_test_LDFLAGS = $(SSL_LDFLAGS) -lcrypto  -L../lib/.libs -ljoy -lm -lpcap -Wl,-pie
joy_api_test_LDADD= $(LDFLAGS) $(SSL_LDFLAGS) -lcrypto -lpthread -L../lib/.libs -ljoy -lm -lpcap 
joy_api_test2_LDADD= $(LDFLAGS) $(SSL_LDFLAGS) -lcrypto -L../lib/.libs -ljoy -lm -lpcap

else
joy_LDFLAGS = $(SSL_LDFLAGS) $(LIBCURL_CFLAGS) -lcrypto -lm -lpcap -lcurl -lpthread -pie
unit_test_LDFLAGS = $(LDFLAGS) -L../lib/.libs -ljoy -lm -lpcap -pie
joy_anon_LDFLAGS = $(LDFLAGS) $(SSL_LDFLAGS) -lcrypto -pie
jfd_anon_LDFLAGS = $(LDFLAGS) $(SSL_LDFLAGS) -lcrypto -pie
str_match_test_LDFLAGS = $(LDFLAGS) $(SSL_LDFLAGS) -lcrypto  -L../lib/.libs -ljoy -lm -lpcap -pie
joy_api_test_LDADD= $(LDFLAGS) $(SSL_LDFLAGS) -lcrypto -lpthread -L../lib/.libs -ljoy -lm -lpcap
joy_api_test2_LDADD= $(LDFLAGS) $(SSL_LDFLAGS) -lcrypto -L../lib/.libs -ljoy -lm -lpcap
endif
