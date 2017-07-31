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
all: 
	@if [ ! -d "bin" ]; then mkdir bin; fi;
	@cd src; $(MAKE) $(MAKEFLAGS)

joy:
	@if [ ! -d "bin" ]; then mkdir bin; fi;
	@cd src; $(MAKE) $(MAKEFLAGS) joy

unit_test:
	@if [ ! -d "bin" ]; then mkdir bin; fi;
	@cd src; $(MAKE) $(MAKEFLAGS) unit_test

jfd-anon:
	@if [ ! -d "bin" ]; then mkdir bin; fi;
	@cd src; $(MAKE) $(MAKEFLAGS) jfd-anon

str_match_test:
	@if [ ! -d "bin" ]; then mkdir bin; fi;
	@cd src; $(MAKE) $(MAKEFLAGS) str_match_test

##
# testing
##
test: joy joy_test.py
	$(BINDIR)/unit_test
	./joy_test.py

##
# cscope
##
cscope:
	find . -name *.[ch] > cscope.files
	cscope -b

##
# DOCUMENTATION
##
man: $(DOCDIR)/joy.1
	man $(DOCDIR)/joy.1 > $(DOCDIR)/joy.txt 
#	man -Tdvi $(DOCDIR)/joy.1 > $(DOCDIR)/joy.dvi 
#	dvipdf $(DOCDIR)/joy.dvi
#	rm -f $(DOCDIR)/joy.dvi

##
# housekeeping
##
clean: 
	rm -f cscope.out cscope.files
	rm -f "$(DOCDIR)/joy.txt"
	@cd src; $(MAKE) clean
	@for a in * .*; do if [ -f "$$a~" ] ; then rm $$a~; fi; done;

##
# installation via shell script
##
install: $(BINDIR)/joy $(BINDIR)/unit_test test
	./install/install-sh

# EOF
