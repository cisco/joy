%define _enable_debug_packages 0
%define debug_package %{nil}
%global commit0 %{COMMIT_ID}
%global gittag0 refs/heads/master
%global shortcommit0 %(c=%{commit0}; echo ${c:0:7})

Summary: Capture and analyze network flow data for research, forensics and monitoring.
Name: joy
Version: 1.71
Release: 0.%{shortcommit0}.1
License: GPLv2
Group: System Environment/Base
#Source0:  https://github.com/cisco/%{name}/archive/%{commit0}.tar.gz#/%{name}-%{shortcommit0}.tar.gz
Source0:  joy-%{shortcommit0}.tar.gz
URL: https://github.com/cisco/joy/
Distribution: Red Hat Enterprise Linux
Packager: brilong@cisco.com
Vendor: Cisco Systems Inc.
BuildArch: noarch
BuildRoot: %{_tmppath}/%{name}-%{version}-%{release}-buildroot-%(%{__id_u} -n)
BuildRequires: curl-devel, libpcap-devel, make, openssl-devel
Requires: fileutils, initscripts, python

%description
Joy is a libpcap-based software package for extracting data features from live
network traffic or packet capture (pcap) files, using a flow-oriented model
similar to that of IPFIX or Netflow, and then representing these data features
in JSON. It also contains analysis tools that can be applied to these data
files. Joy can be used to explore data at scale, especially security and
threat-relevant data.

%prep
%autosetup -n %{name}-%{commit0}

%install
rm -rf $RPM_BUILD_ROOT
mkdir $RPM_BUILD_ROOT

%clean
rm -rf $RPM_BUILD_ROOT

%files
%defattr(-,root,root)

%pre
if [ $1 -gt 1 ]; then
# Determine if someone modified sendmail.mc locally.
    if [ ! -h "/etc/postfix/main.cf" -a -f "/etc/postfix/main.cf.internal" ]; then
        DIFF=`diff /etc/postfix/main.cf /etc/postfix/main.cf.internal`
        if [ -n "$DIFF" ]; then
            touch /tmp/no-postfix-overwrite
            echo "Not overwriting /etc/postfix/main.cf"
        fi
    fi
fi

%post
rm -f /tmp/no-postfix-overwrite

%triggerin -- postfix
cp -p /etc/postfix/main.cf /etc/postfix/main.cf.BaK
if [ $1 = 1 -a $2 = 1 ]; then
   ln -sf /etc/postfix/main.cf.internal /etc/postfix/main.cf
   RESTART=true
else
   if [ ! -h "/etc/postfix/main.cf" -a ! -f "/tmp/no-postfix-overwrite" ]; then
      ln -sf /etc/postfix/main.cf.internal /etc/postfix/main.cf
      RESTART=true
   fi
fi
/usr/sbin/postmap /etc/postfix/virtual

if [ "$RESTART" = "true" ]; then
    # Remove sendmail.cf so it will be built automatically from our macro file.
#    /bin/rm /etc/mail/sendmail.cf /etc/mail/submit.cf
    /sbin/service postfix condrestart >/dev/null 2>&1
fi

%triggerun -- postfix
if [ $1 = 0 ]; then
    [ -h /etc/postfix/main.cf ] && rm -f /etc/postfix/main.cf
    cp -p /etc/postfix/main.cf.BaK /etc/postfix/main.cf
    /sbin/service postfix condrestart >/dev/null 2>&1
fi
