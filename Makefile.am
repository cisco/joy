ACLOCAL_AMFLAGS = -I m4
AUTOMAKE_OPTIONS=foreign

SUBDIRS=safe_c_stub lib bin

doc:
	doxygen Doxyfile

cscope:
	rm -f cscope.out cscope.files
	find . -type f -follow -name "*.[ch]" -print > cscope.files
	cscope -b

clean_make:
	rm lib/Makefile
	rm bin/Makefile
	echo "You must rerun configure"