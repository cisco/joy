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

install-data-hook:
#	mkdir -p $(DESTDIR)/etc/init.d
#	cp install_joy/joy.rc  $(DESTDIR)/etc/init.d/joy
	mkdir -p $(DESTDIR)/usr/lib/systemd/system
	cp install_joy/joy.service $(DESTDIR)/usr/lib/systemd/system
	mkdir -p $(DESTDIR)/etc/systemd/system/joy.service.d
	cp install_joy/joy-accounting.conf $(DESTDIR)/etc/systemd/system/joy.service.d/20-accounting.conf
	mkdir -p $(DESTDIR)/$(prefix)/var/log
	mkdir -p $(DESTDIR)/$(prefix)/var/joy
	mkdir -p $(DESTDIR)/$(prefix)/etc/joy
	mkdir -p $(DESTDIR)/etc/logrotate.d
	cp install_joy/joy.logrotate $(DESTDIR)/etc/logrotate.d/joy
	mkdir -p $(DESTDIR)/$(prefix)/share/joy
	mkdir -p $(DESTDIR)/$(prefix)/share/man
	mkdir -p $(DESTDIR)/$(prefix)/share/man/man1
	cp doc/joy.1 $(DESTDIR)/$(prefix)/share/man/man1
	cp sleuth $(DESTDIR)/$(prefix)/bin
	cp resources/tls_fingerprint.json $(DESTDIR)/$(prefix)/etc/joy
	cp install_joy/options.cfg $(DESTDIR)/$(prefix)/etc/joy
	cp internal.net $(DESTDIR)/$(prefix)/etc/joy
	mkdir -p $(DESTDIR)/$(prefix)/include/joy
#	SLEUTHVER= grep version sleuth_pkg/setup.py | awk -F\' '{print $2}'
	python sleuth_pkg/setup.py bdist --format=gztar
#       SLEUTHFILE="dist/sleuth-${SLEUTHVER}.linux-${build_cpu}.tar.gz"
        SLEUTHFILE="dist/sleuth-1.0.linux-${build_cpu}.tar.gz"
	tar -xf $(SLEUTHFILE) -C $(DESTDIR)

EXTRA_DIST=internal.net build_pkg install_joy test sleuth_pkg rpm examples.sh config.sh compact_bd.txt Makefile.joy sleuth Makefile.joy src/Makefile.joy doc resources VERSION


