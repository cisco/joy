
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
	../src/joy.c 

unit_test_SOURCES = ../src/unit_test.c
joy_api_test_SOURCES = ../src/joy_api_test.c
joy_api_test2_SOURCES = ../src/joy_api_test2.c
jfd_anon_SOURCES = ../src/jfd-anon.c
joy_anon_SOURCES = ../src/joy-anon.c
str_match_test_SOURCES = ../src/str_match_test.c



joy_CFLAGS = -I ../src/include -DJOY_LIB_API -I $(SSL_CFLAGS) $(LIBCURL_CFLAGS) $(AM_CFLAGS)
unit_test_CFLAGS = -I../src/include  -I $(SSL_CFLAGS) $(AM_CFLAGS)
jfd_anon_CFLAGS = -I../src/include -DCOMPRESSED_OUTPUT=0  -I $(SSL_CFLAGS) $(AM_CFLAGS)
joy_anon_CFLAGS = -I../src/include -DCOMPRESSED_OUTPUT=0  -I $(SSL_CFLAGS) $(AM_CFLAGS)
joy_api_test_CFLAGS = -I../src/include -DCOMPRESSED_OUTPUT=0  -I $(SSL_CFLAGS) $(AM_CFLAGS)
joy_api_test2_CFLAGS = -I../src/include -DCOMPRESSED_OUTPUT=0  -I $(SSL_CFLAGS) $(AM_CFLAGS)
str_match_test_CFLAGS = -I../src/include -DCOMPRESSED_OUTPUT=0  -I $(SSL_CFLAGS) $(AM_CFLAGS)


joy_LDFLAGS = $(LIBCURL_CFLAGS) -lcrypto -lm -lpcap -lcurl -pie
unit_test_LDFLAGS = -lm -lpcap -L../lib/.libs -ljoy -pie
joy_api_test_LDFLAGS = -lm -lpcap -L../lib/.libs -ljoy -pie
str_match_test_LDFLAGS = -lm -lpcap -L../lib/.libs -ljoy -pie
jfd_anon_LDADD= -lm -lpcap ../lib/.libs/libjoy.a $(LIBOBJS)
joy_anon_LDADD= -lm -lpcap ../lib/.libs/libjoy.a $(LIBOBJS)
#joy_api_test_LDADD= -lm -lpcap ../lib/.libs/libjoy.a $(LIBOBJS)
joy_api_test2_LDADD= -lm -lpcap ../lib/.libs/libjoy.a $(LIBOBJS)
str_match_test_LDADD= ../lib/.libs/libjoy.a $(LIBOBJS)