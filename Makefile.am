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

install-exec-local:
	mkdir -p $(DESTDIR)/var/log
	mkdir -p $(DESTDIR)/var/joy
	mkdir -p $(DESTDIR)/etc/joy
	mkdir -p $(DESTDIR)/etc/logrotate.d/joy
	mkdir -p $(DESTDIR)/share/joy
	mkdir -p $(DESTDIR)/share/man
	mkdir -p $(DESTDIR)/share/man/man1
	cp doc/joy.1 $(DESTDIR)/share/man/man1
	cp install_joy/options.cfg $(DESTDIR)/etc/joy/options.cfg
	cp sleuth $(DESTDIR)/bin
	cp resources/tls_fingerprint.json $(DESTDIR)/etc/joy
	cp internal.net $(DESTDIR)/etc/joy
	cp install_joy/joy.logrotate $(DESTDIR)/etc/logrotate.d/joy
	mkdir -p  $(DESTDIR)/usr/lib/systemd/system
	mkdir -p  $(DESTDIR)/etc/systemd/system/joy.service
	mkdir -p  $(DESTDIR)/etc/systemd/system/joy.service.d
	cp install_joy/joy.service $(DESTDIR)/usr/lib/systemd/system
	cp install_joy/joy.service $(DESTDIR)/usr/lib/systemd/system

EXTRA_DIST=internal.net build_pkg install_joy test sleuth_pkg rpm examples.sh config.sh compact_bd.txt Makefile.joy sleuth Makefile.joy src/Makefile.joy doc resources VERSION


