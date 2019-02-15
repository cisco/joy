
bin_PROGRAMS = joy unit_test joy_api_test joy_api_test2 jfd-anon joy-anon str_match_test

joy_SOURCES = ../src/joy.c
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

if BUILD_WITH_SAFEC
 SAFEC_LIB= -lciscosafec
else
 SAFEC_LIB_STUBS=$(SAFEC_DIR)/lib/libstubsafec.a
endif

joy_CFLAGS = -I../src/include -I $(SSL_CFLAGS) $(AM_CFLAGS) -I $(SAFEC_DIR)/include  -I $(SAFEC_DIR)/include/safec
unit_test_CFLAGS = -I../src/include  -I $(SSL_CFLAGS) $(AM_CFLAGS) -I $(SAFEC_DIR)/include  -I $(SAFEC_DIR)/include/safec
jfd_anon_CFLAGS = -I../src/include  -DFORCED_COMPRESSED_OUTPUT_OFF=1 -I $(SSL_CFLAGS) $(AM_CFLAGS) -I $(SAFEC_DIR)/include  -I $(SAFEC_DIR)/include/safec 
joy_anon_CFLAGS = -I../src/include  -DFORCED_COMPRESSED_OUTPUT_OFF=1 -I $(SSL_CFLAGS) $(AM_CFLAGS) -I $(SAFEC_DIR)/include  -I $(SAFEC_DIR)/include/safec
joy_api_test_CFLAGS = -I../src/include -DFORCED_COMPRESSED_OUTPUT_OFF=1 -I $(SSL_CFLAGS) $(AM_CFLAGS) -I $(SAFEC_DIR)/include  -I $(SAFEC_DIR)/include/safec
joy_api_test2_CFLAGS = -I../src/include -DFORCED_COMPRESSED_OUTPUT_OFF=1 -I $(SSL_CFLAGS) $(AM_CFLAGS) -I $(SAFEC_DIR)/include  -I $(SAFEC_DIR)/include/safec
str_match_test_CFLAGS = -I../src/include -DFORCED_COMPRESSED_OUTPUT_OFF=1 -I $(SSL_CFLAGS) $(AM_CFLAGS) -I $(SAFEC_DIR)/include  -I $(SAFEC_DIR)/include/safec

if BUILD_MAC
joy_LDFLAGS= $(LDFLAGS) $(SSL_LDFLAGS) -lcrypto -lpthread -L../lib/.libs -ljoy -lm -lpcap -L$(SAFEC_DIR)/lib $(SAFEC_LIB) -Wl,-pie
unit_test_LDFLAGS = -lm -lpcap -L../lib/.libs -ljoy -L$(SAFEC_DIR)/lib $(SAFEC_LIB) -Wl,-pie
joy_anon_LDFLAGS = $(SSL_LDFLAGS) -lcrypto  -L$(SAFEC_DIR)/lib $(SAFEC_LIB) -Wl,-pie
jfd_anon_LDFLAGS = $(SSL_LDFLAGS) -lcrypto  -L$(SAFEC_DIR)/lib $(SAFEC_LIB) -Wl,-pie
str_match_test_LDFLAGS = $(SSL_LDFLAGS) -lcrypto  -L../lib/.libs -ljoy -lm -lpcap -L$(SAFEC_DIR)/lib $(SAFEC_LIB) -Wl,-pie
joy_api_test_LDFLAGS= $(LDFLAGS) $(SSL_LDFLAGS) -lcrypto -lpthread -L../lib/.libs -ljoy -lm -lpcap -L$(SAFEC_DIR)/lib $(SAFEC_LIB) -Wl,-pie
joy_api_test2_LDFLAGS= $(LDFLAGS) $(SSL_LDFLAGS) -lcrypto -L../lib/.libs -ljoy -lm -lpcap -L$(SAFEC_DIR)/lib $(SAFEC_LIB) -Wl,-pie


else
joy_LDFLAGS= $(LDFLAGS) $(SSL_LDFLAGS) -lcrypto -lpthread -L../lib/.libs -ljoy -lm -lpcap  -L$(SAFEC_DIR)/lib $(SAFEC_LIB) -pie
unit_test_LDFLAGS = $(LDFLAGS) -L../lib/.libs -ljoy -lm -lpcap -L$(SAFEC_DIR)/lib $(SAFEC_LIB) -pie
joy_anon_LDFLAGS = $(LDFLAGS) $(SSL_LDFLAGS) -lcrypto  -L$(SAFEC_DIR)/lib $(SAFEC_LIB) -pie
jfd_anon_LDFLAGS = $(LDFLAGS) $(SSL_LDFLAGS) -lcrypto  -L$(SAFEC_DIR)/lib $(SAFEC_LIB) -pie
str_match_test_LDFLAGS = $(LDFLAGS) $(SSL_LDFLAGS) -lcrypto  -L../lib/.libs -ljoy -lm -lpcap  -L$(SAFEC_DIR)/lib $(SAFEC_LIB) -pie
joy_api_test_LDFLAGS= $(LDFLAGS) $(SSL_LDFLAGS) -lcrypto -lpthread -L../lib/.libs -ljoy -lm -lpcap  -L$(SAFEC_DIR)/lib $(SAFEC_LIB) -pie
joy_api_test2_LDFLAGS= $(LDFLAGS) $(SSL_LDFLAGS) -lcrypto -L../lib/.libs -ljoy -lm -lpcap  -L$(SAFEC_DIR)/lib $(SAFEC_LIB) -pie

endif
joy_LDADD=$(SAFEC_LIB_STUBS)
unit_test_LDADD=$(SAFEC_LIB_STUBS)
joy_anon_LDADD=$(SAFEC_LIB_STUBS)
jfd_anon_LDADD=$(SAFEC_LIB_STUBS)
str_match_test_LDADD=$(SAFEC_LIB_STUBS)
joy_api_test_LDADD=$(SAFEC_LIB_STUBS)
joy_api_test2_LDADD=$(SAFEC_LIB_STUBS)

