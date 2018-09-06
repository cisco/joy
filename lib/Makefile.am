

lib_LTLIBRARIES = libjoy.la
libjoy_la_SOURCES = \
	../src/joy_api.c \
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
	../src/joy_version.c

libjoy_la_CFLAGS = -I ../src/include $(AM_CFLAGS)

libjoy_la_LDFLAGS = -version-info $(JOY_LIBRARY_VERSION)

include_HEADERS=../src/include/joy_api.h

libjoy_la_LIBADD = $(LIBOBJS)