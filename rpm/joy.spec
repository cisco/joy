%define _enable_debug_packages 0
%define debug_package %{nil}
%global commit0 %{COMMIT_ID}
%global version %{GIT_VERSION}
%global gittag0 refs/heads/master
%global shortcommit0 %(c=%{commit0}; echo ${c:0:7})

Summary: Capture and analyze network flow data for research, forensics and monitoring.
Name: joy
Version: %{version}
Release: 0.%{shortcommit0}.1%{?dist}
License: GPLv2
Group: System Environment/Base
Source0:  joy-%{shortcommit0}.tar.gz
URL: https://github.com/cisco/joy/
Distribution: Red Hat Enterprise Linux
Packager: brilong@cisco.com
Vendor: Cisco Systems Inc.
BuildArch: x86_64
BuildRoot: %{_tmppath}/%{name}-%{version}-%{release}-buildroot-%(%{__id_u} -n)
BuildRequires: libcurl-devel, libpcap-devel, make, openssl-devel, zlib-devel
Requires: fileutils, initscripts, libcurl, libpcap, kernel => 3.10, openssl, python, zlib

%description
Joy is a libpcap-based software package for extracting data features from live
network traffic or packet capture (pcap) files, using a flow-oriented model
similar to that of IPFIX or Netflow, and then representing these data features
in JSON. It also contains analysis tools that can be applied to these data
files. Joy can be used to explore data at scale, especially security and
threat-relevant data.

%prep
%autosetup -n %{name}

%install
rm -rf $RPM_BUILD_ROOT
mkdir $RPM_BUILD_ROOT
./config -l /usr/lib64
echo "%{version}-%{shortcommit0}" > VERSION
make
make DESTDIR=${RPM_BUILD_ROOT}/usr/local RPM_BUILD_ROOT=${RPM_BUILD_ROOT} rpm

%clean
rm -rf $RPM_BUILD_ROOT

%files
%defattr(-,root,root)
%config(noreplace) /etc/systemd/system/joy.service.d/20-accounting.conf
/usr/lib/systemd/system/joy.service
/usr/local/bin/joy
/usr/local/bin/joyq
%attr(0700,root,root) %dir /usr/local/etc/joy
%config(noreplace) /usr/local/etc/joy/*
/usr/local/lib/python/sleuth*
/usr/local/share/joy
%doc /usr/local/share/man/man1/joy.1
%attr(0700,root,root) %dir /usr/local/var/joy
%attr(0700,root,root) %dir /usr/local/var/log

%post

systemctl daemon-reload >/dev/null 2>&1 || :
if [ $1 -eq 1 ] ; then
        # Initial installation
        systemctl preset joy.service >/dev/null 2>&1 || :
fi
if [ ! -f /usr/local/etc/joy/upload-key ]; then
        ssh-keygen -f /usr/local/etc/joy/upload-key -P "" -t rsa -b 2048
fi

%preun

if [ $1 -eq 0 ] ; then
        # Package removal, not upgrade
        systemctl --no-reload disable joy.service  >/dev/null 2>&1 || :
        systemctl stop joy.service >/dev/null 2>&1 || :
fi

%postun

systemctl daemon-reload >/dev/null 2>&1 || :
if [ $1 -ge 1 ] ; then
        # Package upgrade, not uninstall
        systemctl try-restart joy.service >/dev/null 2>&1 || :
fi
