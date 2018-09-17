ACLOCAL_AMFLAGS = -I m4
AUTOMAKE_OPTIONS=foreign

SUBDIRS=safe_c_stub lib bin

doc:
	doxygen Doxyfile

cscope:
	rm -f cscope.out cscope.files
	find . -type f -follow -name "*.[ch]" -print > cscope.files
	cscope -b

test: 
	test/run_tests.py
	bin/unit_test
	test/run_tests.py

clean_make:
	rm lib/Makefile
	rm bin/Makefile
	echo "You must rerun configure"


#EXTRA_DIST=internal.net build_pkg install


#/install.sh install/jpy-accounting.conf install/joy.logrotate install/joy.plist install/joy-rc install/joy.service install/options.cfg
	   