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

# Include the variables defined from the config script to esnure our
# compile and linkage runs smoothly.
include config.vars

# main executable and unit test program
#
pcap2flow: FORCE
	cd src; $(MAKE) $(MAKEFLAGS)
	cp src/pcap2flow .

FORCE:

unit_test:
	cd src; $(MAKE)
	cp src/unit_test .

# testing
#
test: unit_test pcap2flow pcap2flow_test.sh
	./unit_test
	./pcap2flow_test.sh

# cscope
#
cscope:
	find . -name *.[ch] > cscope.files
	cscope -b

# DOCUMENTATION
#
man: pcap2flow.1
	man ./pcap2flow.1 > pcap2flow.txt 
	man -Tdvi ./pcap2flow.1 > pcap2flow.dvi 
	dvipdf pcap2flow.dvi
	rm -f pcap2flow.dvi

# housekeeping
#
clean: 
	rm -f cscope.out cscope.files
	cd src; $(MAKE) clean
	rm -f pcap2flow unit_test 
	for a in * .*; do if [ -f "$$a~" ] ; then rm $$a~; fi; done;

distclean: clean
	if [ -f pcap2flow.bin ]; then echo "pcap2flow.bin is present; (re)move it before building distribution"; exit 1; fi
	if [ -f upload-key ]; then echo "upload-key is present; (re)move it before building distribution"; exit 1; fi
	if [ -f upload-key.pub ]; then echo "upload-key.pub is present; (re)move it before building distribution"; exit 1; fi

distname = joy_$(version)

# note: debian friendly tarball name
#
package: distclean
	cd ..; tar cvzf $(distname).orig.tar.gz joy/* 

debian: package
	cd ..; cp -R joy joy-$(version)
	cd ../joy-$(version); debuild -us -uc

# installation via shell script
#
install: pcap2flow unit_test test
	./install-sh

# EOF
