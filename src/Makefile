# Makefile for joy binaries 
#
# Builds binary files for joy open source modules. 
#
# Copyright (c) 2016 Cisco Systems 

##
# variables 
##

##
# CWD is the name of the current directory
##
TMP = $(shell pwd)
CWD = $(shell basename $(TMP))

##
# required libraries for joy
##
LIBS = -lpcap     # packet capture library; hard requirement
LIBS += -lm       # math library; logf() used in entropy computation
LIBS += -lcrypto  # openSSL crypto library; used in anonymization
LIBS += -lcurl    # curl library; used in updater thread
LIBS += -lpthread # thread library; used in updater thread

ifeq ($(COMPDEF),-DUSE_BZIP2)
LIBS += -lbz2     # bzip2 library
else
  ifeq ($(COMPDEF),-DUSE_GZIP)
    LIBS += -lz       # gzip library
  endif
endif

##
# check for additional paths to use searching for header files
##
INCLUDEDIR = -I ./include $(SSLPATH) $(CURLPATH)

##
# check for additional paths to use searching for library files
##
ifndef LIBPATH
LIBRARYPATH = 
else
LIBRARYPATH = $(LIBPATH)
endif

##
# make sure we have a definition for BINDIR, LIBDIR, TESTDIR
##
ifndef BINDIR
BINDIR = ../bin
endif

ifndef LIBDIR
LIBDIR = ../lib
endif

ifndef TESTDIR
TESTDIR = ../test
endif

##
# compiler directives
##
CDEFS     = -D$(SYS_NAME)=1 -DVERSION=\"$(JOY_VERSION)\"
CFLAGS = -Wall -Wno-deprecated-declarations -g -O3  # -pg # -g # -fstack-protector-all 

##
# variables to make source file handling easier
##
JOY_SRC = p2f.c config.c osdetect.c anon.c pkt_proc.c nfv9.c tls.c classify.c radix_trie.c hdr_dsc.c procwatch.c addr_attr.c addr.c wht.c http.c str_match.c acsm.c dns.c example.c updater.c ipfix.c ssh.c ike.c salt.c parson.c fingerprint.c ppi.c utils.c dhcp.c payload.c
JFDANON_SRC = anon.c addr.c str_match.c acsm.c
ALL_HEADER_FILES = acsm.h config.h hdr_dsc.h osdetect.h procwatch.h addr.h dns.h http.h output.h radix_trie.h addr_attr.h err.h map.h p2f.h str_match.h anon.h example.h modules.h pkt.h tls.h classify.h feature.h nfv9.h pkt_proc.h wht.h updater.h ipfix.h ssh.h ike.h salt.h parson.h fingerprint.h ppi.h utils.h dhcp.h payload.h
ALL_FILES = joy.c jfd-anon.c unit_test.c str_match_test.c $(JOY_SRC) $(JFDANON_SRC) $(ALL_HEADER_FILES)
LIBJOY_SRC = joy_api.c p2f.c osdetect.c anon.c pkt_proc.c nfv9.c tls.c classify.c radix_trie.c hdr_dsc.c procwatch.c addr_attr.c addr.c wht.c http.c str_match.c acsm.c dns.c example.c ipfix.c ssh.c ike.c salt.c parson.c fingerprint.c ppi.c utils.c dhcp.c payload.c config.c
LIBJOY_OBJ = joy_api.o p2f.o osdetect.o anon.o pkt_proc.o nfv9.o tls.o classify.o radix_trie.o hdr_dsc.o procwatch.o addr_attr.o addr.o wht.o http.o str_match.o acsm.o dns.o example.o ipfix.o ssh.o ike.o salt.o parson.o fingerprint.o ppi.o utils.o dhcp.o payload.o config.o

##
# additional CFLAG options
##
ifeq ($(sysname),LINUX)
	CFLAGS += # -Wno-maybe-uninitialized 
endif
ifeq ($(sysname),DARWIN)
	CFLAGS += -mmacosx-version-min=10.5
	INCLUDEDIR += -I/opt/local/include/
endif

##
# targets
##

.PHONY: print

all:	print joy jfd-anon unit_test str_match_test joy-anon

print:
	@echo "Makefile variables:"
	@echo "buildroot="$(ROOT_DIR)
	@echo "sysname="$(SYS_NAME)
	@echo "version="$(JOY_VERSION)
	@echo "cwd="$(CWD)

joy: joy.c $(JOY_SRC)
	gcc $(CFLAGS) $(CDEFS) $(COMPDEF) $(COMPRESSED) -o "$(BINDIR)/joy" $(INCLUDEDIR) joy.c $(JOY_SRC) $(LIBRARYPATH) $(LIBS)
#	strip joy

jfd-anon: jfd-anon.c $(JFDANON_SRC)
	gcc $(CFLAGS) $(CDEFS) $(COMPDEF) -DCOMPRESSED_OUTPUT=0 -o "$(BINDIR)/jfd-anon" $(INCLUDEDIR) jfd-anon.c $(JFDANON_SRC) $(LIBRARYPATH) $(LIBS)

joy-anon: joy-anon.c $(JFDANON_SRC)
	gcc $(CFLAGS) $(CDEFS) $(COMPDEF) -DCOMPRESSED_OUTPUT=0 -o "$(BINDIR)/joy-anon" $(INCLUDEDIR) joy-anon.c $(JFDANON_SRC) $(LIBRARYPATH) $(LIBS)

unit_test: unit_test.c $(JOY_SRC)
	gcc $(CFLAGS) $(CDEFS) $(COMPDEF) $(COMPRESSED) -o "$(BINDIR)/unit_test" $(INCLUDEDIR) unit_test.c $(JOY_SRC) $(LIBRARYPATH) $(LIBS) 
	ln -sf "$(BINDIR)/unit_test" "$(TESTDIR)/unit_test"

str_match_test: str_match_test.c $(JOY_SRC)
	gcc $(CFLAGS) $(CDEFS) $(COMPDEF) -DCOMPRESSED_OUTPUT=0 $(INCLUDEDIR) -o "$(BINDIR)/str_match_test" str_match_test.c $(JOY_SRC) $(LIBRARYPATH) $(LIBS) 

$(LIBJOY_OBJ): $(LIBJOY_SRC)
	gcc $(CFLAGS) $(CDEFS) $(COMPDEF) -DJOY_LIB_API -DCOMPRESSED_OUTPUT=0 $(INCLUDEDIR) -c $(LIBJOY_SRC)
	
libjoy.a: $(LIBJOY_OBJ)
	ar rcs $(LIBDIR)/libjoy.a $(LIBJOY_OBJ)
	@rm $(LIBJOY_OBJ)

joy_api_test: $(LIBDIR)/libjoy.a joy_api_test.c
	gcc $(CFLAGS) $(CDEFS) $(COMPDEF) -DCOMPRESSED_OUTPUT=0 $(INCLUDEDIR) -o "$(BINDIR)/joy_api_test" joy_api_test.c -L $(LIBDIR) -ljoy  $(LIBRARYPATH) -lpcap -lm -lcrypto

joy_api_test2: $(LIBDIR)/libjoy.a joy_api_test2.c
	gcc $(CFLAGS) $(CDEFS) $(COMPDEF) -DCOMPRESSED_OUTPUT=0 $(INCLUDEDIR) -o "$(BINDIR)/joy_api_test2" joy_api_test2.c -L $(LIBDIR) -ljoy $(LIBRARYPATH) -lm -lcrypto 


##
# STATIC ANALYSIS
##
SPLINT_OPT =  -nestcomment -warnposixheaders -retvalother -retvalint -nullassign 
SPLINT_OPT += -initallelements -fullinitblock -type -boolops -predboolint -predboolothers
SPLINT_OPT += -globstate -mustfreeonly -nullstate -nullret +charindex -kepttrans -onlytrans
SPLINT_OPT += -unqualifiedtrans -fixedformalarray +charint
SPLINT_OPT += -I/usr/include/x86_64-linux-gnu # +posixlib 

splint: $(ALL_FILES)
	splint $(SPLINT_OPT) $(ALL_FILES) $(INCLUDEDIR) # $(CFLAGS) $(CDEFS)  $(LIBRARYPATH) $(LIBS) 

clean: 
	rm -rf *.o
	rm -rf "$(BINDIR)/"*
	rm -rf "$(LIBDIR)/"*
	@for a in * .*; do if [ -f "$$a~" ] ; then rm $$a~; fi; done;

# EOF
