
#
# Unfortunately the real safec library does not follow
# Linux convention having libraries start with lib.
# So here I'm forcing a non-standard build of 
# our safec stub to match the library names
# used with safec
#
#
noinst_LIBRARIES= libstubsafec.a

libstubsafec_a_SOURCES =  \
../src/safe_mem_stub.c \
../src/safe_str_stub.c

libstubsafec_a_CFLAGS=-I../include $(AM_CFLAGS)






