# makefile for pcap2flow 
#
# Copyright (c) 2016 Cisco Systems 

# variables 
#

# CWD is the name of the current directory
#
TMP = $(shell pwd)
CWD = $(shell basename $(TMP))

# The version variable identifies the version number of the source
# code (and not the version of the protocol).
#
version = $(shell cat VERSION)

# The sysname variable identifies the system by kernel name, and is
# used to define a C preprocessor symbol (in the CFLAGS variable) that
# indicates the operating system type.  Note that it does *not* affect
# the endianness choice, which is picked up from <sys/types.h>.
#
sysname = $(shell uname -s | tr "[:lower:]" "[:upper:]" )

# required libraries for pcap2flow
#
LIBS = -lpcap    # packet capture library; hard requirement
LIBS += -lm      # math library; logf() used in entropy computation
LIBS += -lcrypto # openSSL crypto library; used in anonymization
LIBS += -lz

INCLUDEDIR = 

CDEFS     = -D$(sysname)=1 -DVERSION=\"$(version)\"

CFLAGS = -Wall -Wno-deprecated-declarations -g -O3  # -pg # -g # -fstack-protector-all 

NFV9_FILES = exporter.c nfv9.c nfv9.h Makefile
TLS_FILES = tls.c tls.h
CLASSIFY_FILES = classify.c classify.h

PCAP2FLOW_SRC = p2f.c config.c osdetect.c anon.c pkt_proc.c nfv9.c tls.c classify.c radix_trie.c hdr_dsc.c procwatch.c addr_attr.c addr.c wht.c http.c str_match.c acsm.c dns.c
PCAP2FLOW_HDR = osdetect.h anon.h p2f.h pkt.h tls.h pkt_proc.h radix_trie.h classify.h hdr_dsc.h addr_attr.h addr.h err.h dns.h

ifeq ($(sysname),LINUX)
	CFLAGS += # -Wno-maybe-uninitialized 
endif

ifeq ($(sysname),DARWIN)
	CFLAGS += -mmacosx-version-min=10.5
endif

PCAP2FLOW_FILES = $(PCAP2FLOW_SRC) $(PCAP2FLOW_HDR)

CFGFILES = addr.cfg macosx.cfg flocap.cfg VERSION 

FILES = $(NFV9_FILES) $(TLS_FILES) $(CLASSIFY_FILES) $(PCAP2FLOW_FILES) $(CFGFILES) 

# targets
#

.PHONY: print

all:	print pcap2flow jfd-anon unit_test str_match_test

print:
	@echo "Makefile variables:"
	@echo "sysname="$(sysname)
	@echo "version="$(version)
	@echo "CWD="$(CWD)

tls: tls.c tls.h Makefile
	gcc $(CFLAGS) -o tls tls.c

classify: classify.c classify.h Makefile
	gcc $(CFLAGS) -o classify classify.c

pcap2flow: $(PCAP2FLOW_FILES) Makefile VERSION
	gcc $(CFLAGS) $(CDEFS) -o pcap2flow $(INCLUDEDIR) pcap2flow.c $(PCAP2FLOW_SRC) $(LIBS) 
#	strip pcap2flow
	cp pcap2flow ./..

unit_test: unit_test.c Makefile VERSION $(PCAP2FLOW_FILES)
	gcc $(CFLAGS) $(CDEFS) -o unit_test $(INCLUDEDIR) unit_test.c $(PCAP2FLOW_SRC) $(LIBS) 

str_match_test: str_match_test.c Makefile VERSION $(PCAP2FLOW_FILES)
	gcc $(CFLAGS) $(CDEFS) -o str_match_test str_match_test.c $(PCAP2FLOW_SRC) $(LIBS) 

jfd-anon: jfd-anon.c anon.c addr.c Makefile
	gcc $(CFLAGS) $(CDEFS) -o jfd-anon $(INCLUDEDIR) jfd-anon.c anon.c addr.c str_match.c acsm.c $(LIBS)

jfd-analysis: jfd-analysis.c 
	gcc $(CFLAGS) $(CDEFS) jfd-analysis.c -o jfd-analysis $(LIBS)

huffman: huffman.c Makefile
	gcc $(CFLAGS) $(CDEFS) -o huffman $(INCLUDEDIR) huffman.c $(LIBS)

# STATIC ANALYSIS

SPLINT_OPT =  -nestcomment -warnposixheaders -retvalother -retvalint -nullassign 
SPLINT_OPT += -initallelements -fullinitblock -type -boolops -predboolint -predboolothers
SPLINT_OPT += -globstate -mustfreeonly -nullstate -nullret +charindex -kepttrans -onlytrans
SPLINT_OPT += -unqualifiedtrans -fixedformalarray +charint
SPLINT_OPT += -I/usr/include/x86_64-linux-gnu # +posixlib 

splint: $(PCAP2FLOW_FILES) Makefile VERSION
	splint $(SPLINT_OPT) $(PCAP2FLOW_FILES) $(INCLUDEDIR) # $(CFLAGS) $(CDEFS)  $(LIBS) 

# DOCUMENTATION

man: pcap2flow.1
	man ./pcap2flow.1 > pcap2flow.txt 
	man -Tdvi ./pcap2flow.1 > pcap2flow.dvi 
	dvipdf pcap2flow.dvi
	rm -f pcap2flow.dvi

clean: 
	rm -f tls classify pcap2flow pcap2flow.pdf pcap2flow.dvi pcap2flow.txt jfd-anon jfd-analysis unit_test str_match_test
	for a in * .*; do if [ -f "$$a~" ] ; then rm $$a~; fi; done;


# EOF
