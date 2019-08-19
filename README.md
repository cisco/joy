                           _              
                          (_) ___  _   _
                          | |/ _ \| | | |
                          | | (_) | |_| |
                         _/ |\___/ \__, |
                        |__/       |___/

            A package for capturing and analyzing network
         flow data and intraflow data, for network research,
              forensics, and security monitoring.
[![Build Status](https://travis-ci.org/cisco/joy.svg?branch=master)](https://travis-ci.org/cisco/joy)

## Overview

Joy is a BSD-licensed libpcap-based software package for extracting
data features from live network traffic or packet capture (pcap)
files, using a flow-oriented model similar to that of IPFIX or
Netflow, and then representing these data features in JSON.  It
also contains analysis tools that can be applied to these data
files.  Joy can be used to explore data at scale, especially
security and threat-relevant data.

JSON is used in order to make the output easily consumable by data
analysis tools.  While the JSON output files are somewhat verbose,
they are reasonably small, and they respond well to compression.

Joy can be configured to obtain intraflow data, that is, data and
information about events that occur within a network flow,
including:

  * the sequence of lengths and arrival times of IP packets,
    up to some configurable number of packets.

  * the empirical probability distribution of the bytes within the
    data portion of a flow, and the entropy derived from that value,

  * the sequence of lengths and arrival times of TLS records,

  * other non-encrypted TLS data, such as the list of offered
    ciphersuites, the selected ciphersuite, the length of the
    clientKeyExchange field, and the server certificate strings,

  * DNS names, addresses, and TTLs,

  * HTTP header elements and the first eight bytes of the HTTP
    body, and

  * the name of the process associated with the flow, for flows
    originate or terminate on the host on which pcap is running.

Joy is intended for use in security research, forensics, and for
the monitoring of (small scale) networks to detect vulnerabilities,
threats and other unauthorized or unwanted behavior.  Researchers,
administrators, penetration testers, and security operations teams
can put this information to good use, for the protection of the
networks being monitored, and in the case of vulnerabilities, for
the benefit of the broader community through improved defensive
posture.  As with any network monitoring tool, Joy could
potentially be misused; do not use it on any network of which you
are not the owner or the administrator.  

Flow, in positive psychology, is a state in which a person
performing an activity is fully immersed in a feeling of energized
focus, deep involvement, and joy.  This second meaning inspired
the choice of name for this software package.

Joy is alpha/beta software; we hope that you use it and benefit
from it, but do understand that it is not suitable for production
use.

#### TLS Fingerprinting

We have recently released the largest and most informative open source [TLS fingerprint database](https://github.com/cisco/joy/blob/master/fingerprinting/resources/fingerprint_db.json.gz). Among other features, our approach builds on previous work by being fully automated and annotating TLS fingerprints with significantly more information.  We have built a set of python tools to enable the application of this database, as well as the generation of new databases with the help of Joy. For more information, please see the [TLS fingerprinting documentation](https://github.com/cisco/joy/blob/master/doc/using-joy-fingerprinting-00.pdf).

#### Relation to Cisco ETA

Joy has helped support the research that paved the way for Cisco’s Encrypted
Traffic Analytics (ETA), but it is not directly integrated into any of the
Cisco products or services that implement ETA. The classifiers in Joy were
trained on a small dataset several years ago, and do not represent the
classification methods or performance of ETA. The intent of this feature is
to allow network researchers to quickly train and deploy their own classifiers
on a subset of the data features that Joy produces. For more information on
training your own classifier, see saltUI/README or reach out to joy-users@cisco.com.

#### Credits

This package was written by David McGrew, Blake Anderson, Philip Perricone
and Bill Hudson {mcgrew,blaander,phperric,bhudson}@cisco.com of Cisco Systems
Advanced Security Research Group (ASRG) and Security and Trust Organization (STO).

### Release 4.5.0
* Added the ability to use AF_PACKET v3 and AF_FANOUT instead of libpcap
    use --enable-af_packet on the configure command for AF_PACKET
* minor bug fixes

### Release 4.4.0
* Fix SIGSEGV in DNS parsing (recursion depth bug)
* Fix bug in IPv6 payload calculation
* Fix bug in IPv6 IDP length
* Bump MAX library contexts to 64 (user request)

### Release 4.3.0
* Add IPv6 support to Joy and libjoy
* IPFix collection and export only support IPv4
* NFv9 only supports IPv4
* Anonymization only supports IPv4 addresses
* Subnet labeling only supports IPv4 addresses

### Release 4.2.0
* Re-write joy.c to use libjoy library
* Updated joy.c to utilize multi-threads for flow processing
* Updated unit tests and python tests to reflect new code changes
* Removed guts of the updater process to prepare for re-write
* Fixed bug in processing multiple files on the command line
* Other minor bug fixes

### Release 4.0.3
* Added support for make install for Centos

### Release 4.0.2
* Add support for fingerprinting

### Release 4.0.1
We are pleased to announce the 4.0.1 release of the package, which has these features:
* Add additional API's for parent application processing of Flow Records and data features
* Fixed TCP retransmission and out of order detection
* Better identification of IDP packet
* Fixed some memory usage issues
* Fixed minor bugs
* Removed dead code

### Release 4.0.0
We are pleased to announce the 4.0.0 release of the package, which has these features:
* Add support for building with autotools. ./configure;make clean;make

### Release 3.0.0
We are pleased to announce the 3.0.0 release of the package, which has these features:
* Modified JOY infrastructure code to be thread safe.
  * Allowed support multiple work threads for packet processing.
  * Each worker thread uses own output file.
  * Removed global variables for Config.
  * Modified code infrastructure to use Config Structure.
* Modified the Makefile system to build the JOY infrastructure as a static and shared library.
* Implemented an API for utilizing the JOY Library (joy_api.[hc]).
* Implemented a Vector Packet Processing integration scheme to utilize VPP native infrastructure when building that integration.
* Created 2 API test programs, joy_api_test.c and joy_api_test2.c.
* Modified existing test programs to link against static JOY library instead of re-compiling the infrastructure code.
* Modified versioning to use Common Security Module (CSM) conventions.
* Modified build_pkg to accept package version on the command line.
* Cleaned up coverity errors and warnings.
* Various bug fixes.

### Release 2.0

We are pleased to announce the 2.0 release of the package, which has these features:
* The JSON schema has been updated to be better organized, more readable, and more searchable (by putting searchable keywords as the JSON names),
* The new sleuth tool replaces query/joyq, and brings new functionality such as —fingerprint, 
* Much improved documentation, which covers the joy and sleuth tools, examples, and the JSON schema
(see [using-joy](https://github.com/cisco/joy/blob/master/doc/using-joy-05.pdf))

## Quick Start

Joy has been successfully run and tested on Linux (Debian, Ubuntu,
CentOS, and Raspbian), Mac OS X and Windows. The system has been built with
gcc and GNU make, but it should work with other development
environments as well.

Go to the Wiki for a guide on building:
[Build Instructions](https://github.com/cisco/joy/wiki/Building)

## License
See [License](https://github.com/cisco/joy/blob/master/LICENSE) of Joy

See [Copying](https://github.com/cisco/joy/blob/master/COPYING) for licenses of external libraries
