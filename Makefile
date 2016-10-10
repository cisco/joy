# Makefile
#
# Top Level Makefile for the joy open source binaries
#
# Copyright (c) 2016 Cisco Systems 

##
# variables 
##

##
# Figure out the path and directory of the top level Makefile
##
export ROOT_PATH = $(shell pwd)
export ROOT_DIR = $(shell basename $(ROOT_PATH))

##
# The joy version variable identifies the version number of the source
# code (and not the version of the protocol).
##
export JOY_VERSION = $(shell cat VERSION)

##
# The sysname variable identifies the system by kernel name, and is
# used to define a C preprocessor symbol (in the CFLAGS variable) that
# indicates the operating system type.  Note that it does *not* affect
# the endianness choice, which is picked up from <sys/types.h>.
##
export SYS_NAME = $(shell uname -s | tr "[:lower:]" "[:upper:]" )

##
# Include the variables defined from the config script to esnure our
# compile and linkage runs smoothly.
##
-include config.vars
ifndef LIBPATH
$(error error is "Please run ./config first.")
endif
ifndef SSLPATH
$(error error is "Please run ./config first.")
endif
ifndef CURLPATH
$(error error is "Please run ./config first.")
endif

export BINDIR = $(ROOT_PATH)/bin
export DOCDIR = $(ROOT_PATH)/doc

##
# main executable and unit test program
##
pcap2flow: FORCE
	@if [ ! -d "bin" ]; then mkdir bin; fi;
	@cd src; $(MAKE) $(MAKEFLAGS)

FORCE:

unit_test:
	@if [ ! -d "bin" ]; then mkdir bin; fi;
	@cd src; $(MAKE) $(MAKEFLAGS)

##
# testing
##
test: pcap2flow pcap2flow_test.sh
	$(BINDIR)/unit_test
	./pcap2flow_test.sh

##
# cscope
##
cscope:
	find . -name *.[ch] > cscope.files
	cscope -b

##
# DOCUMENTATION
##
man: $(DOCDIR)/pcap2flow.1
	man $(DOCDIR)/pcap2flow.1 > $(DOCDIR)/pcap2flow.txt 
#	man -Tdvi $(DOCDIR)/pcap2flow.1 > $(DOCDIR)/pcap2flow.dvi 
#	dvipdf $(DOCDIR)/pcap2flow.dvi
#	rm -f $(DOCDIR)/pcap2flow.dvi

##
# housekeeping
##
clean: 
	rm -f cscope.out cscope.files
	rm -f "$(DOCDIR)/pcap2flow.txt"
	@cd src; $(MAKE) clean
	@for a in * .*; do if [ -f "$$a~" ] ; then rm $$a~; fi; done;

##
# installation via shell script
##
install: $(BINDIR)/pcap2flow $(BINDIR)/unit_test test
	./install-sh

# EOF
