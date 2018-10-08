ACLOCAL_AMFLAGS = -I m4
AUTOMAKE_OPTIONS=foreign

SUBDIRS=safe_c_stub lib bin

joy_api:
	(doxygen Doxyfile)

cscope:
	rm -f cscope.out cscope.files
	find . -type f -follow -name "*.[ch]" -print > cscope.files
	cscope -b

joy_test: 
	test/run_tests.py
	bin/unit_test
	test/run_tests.py

clean_make:
	rm lib/Makefile
	rm bin/Makefile
	echo "You must rerun configure"


EXTRA_DIST=internal.net build_pkg install_joy test sleuth_pkg rpm examples.sh config.sh compact_bd.txt Makefile.joy sleuth Makefile.joy src/Makefile.joy VERSION


