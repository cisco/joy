
lib_LTLIBRARIES = libjoy.la

libjoy_la_SOURCES = joy_api.c \
        p2f.c \
	osdetect.c \
        anon.c \
        pkt_proc.c \
        nfv9.c \
        tls.c \
        classify.c \
        radix_trie.c \
        hdr_dsc.c \
        procwatch.c \
        addr_attr.c \
        addr.c \
        wht.c \
        http.c \
        str_match.c \
        acsm.c \
        dns.c \
        example.c \
	updater.c \
        ipfix.c \
        ssh.c \
        ike.c \
        salt.c \
        parson.c \
        fingerprint.c \
        ppi.c \
        utils.c \
        dhcp.c \
        payload.c \
        config.c \
        proto_identify.c \
	joy_version.c

libjoy_la_CFLAGS = \
-I ./ \
-I include/ \
$(AM_CFLAGS)

libjoy_la_LDFLAGS = -version-info $(PKG_VERSION_NUMBER)

libjoy_la_LIBADD = $(SAFEC_LDFLAGS) $(LIBOBJS)
library_includedir=$(includedir)/joy
library_include_HEADERS = include/joy_api.h