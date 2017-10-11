                           _              
                          (_) ___  _   _
                          | |/ _ \| | | |
                          | | (_) | |_| |
                         _/ |\___/ \__, |
                        |__/       |___/

            A package for capturing and analyzing network
         flow data and intraflow data, for network research,
              forensics, and security monitoring.

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

## Quick Start

#### Building

Joy has been successfully run and tested on Linux (Debian, Ubuntu,
CentOS, and Raspbian), Mac OS X and Windows. The system has been built with
gcc and GNU make, but it should work with other development
environments as well. For Windows builds, see the Windows section below.

First, obtain the package from github, and change to the joy
directory.

To configure the package, run "./config" in the main directory:

```
[joy]$ ./config
```

Resolve any dependencies that were not automatically found. Once
resolved, re-run "./config" to ensure all dependencies were discovered.

To build the package, run "make" in the main directory:

```
[joy]$ make
```

This will cause the programs to be compiled, linked, stripped, and
copied into the 'bin' directory as appropriate.

Set COMPRESSED_OUTPUT (in src/include/output.h) to 1 for gzip-compressed
JSON output. This compile-time option is on by default. If that
\#define is instead set to 0, then normal JSON will be output.
There are many tools that can be used to work with gzip-compressed
output, such as zless, gunzip, etc.  

The main program for extracting data features from pcap files or
live packet captures is the program joy, which occupies the
src/ subdirectory. It is copied into the bin/ directory after
a successful build. It can be run from that directory, or
installed so that it will automatically run as a daemon on Linux or
Mac OSX.

###### MacOS
Version 10.11 has more dependencies than 10.10; the OpenSSL header
files are needed to build this package. You can install these
header files via Mac Ports (https://www.macports.org/install.php)
using the command `sudo port install openssl`.

###### Windows
We have tried to make building on Windows as easy as possible. In the
joy/win-joy directory there is a Visual Studio solution file. Open the solution
file with Visual Studio 2015 (we have tested on VS 2013 as well) and it should
load up all the defaults and source files required. Currently, the project is
only setup to build 64-bit binaries. Once the project file loads, you can execute
a "clean" and "build" of the code. All of the dependent libraries and headers files
are in the joy/windows directory. Once you have the binary built, the required DLL
files that are necessary for program execution are located in the joy/windows/64/DLL
directory. You can place these DLL files alongside your binary in a directory to
produce a package that can be dropped onto a windows based machine and execute correctly.
If you want to run the binary directly within the Visual Studio IDE, then you may add this
value to the project Properties->Debugging->Environment: `PATH=%PATH%;$(ProjectDir)\..\..\windows\64\DLL`

Execution of win-joy.exe has been tested on Windows 7, Windows 10 and Windows Server 2012.

#### Testing

First, ensure both bin/joy and bin/unit_test exist by running either
`make` or `make unit_test`. Then you can manually run the unit tests:
```
./test/unit_test
```
Or the black box tests:
```
./test/run_tests.py
```
You may also automatically build the binaries and run the tests in
one swoop by executing:
```
make test
```
The test programs will indicate success or failure on the command line.
Please see [test/README.md](test/README.md) for more information
on blackbox testing.

###### Windows

Build the unit-test project. Make sure that unit-test.exe has access to the required DLL files either
by placing them together in the same directory, or modifying the debug environment as described
above in the "Building - Windows" section. Then you may run the unit-test.exe executable either
through the command line or the Visual Studio IDE.

#### Running and Configuration

To understand how joy is configured, read the
configuration file "options.cfg".  To process a pcap
file in offline mode, run

```
[joy]$ bin/joy [ OPTIONS ] filename [ filename2 ... ]
```

For instance,

```
[joy]$ bin/joy bidir=1 output=data.json filename
```

To run the packet capture in online mode, use the same command
form, but have OPTIONS include an interface=<value> command, and
omit the filename(s) from the command line.  For instance,

```
[joy]$ sudo bin/joy interface=eth0 bidir=1 output=data.json
```

There are many command line options, so instead of typing them all
onto the command line, you may want to have the program read a
configuration file.  Such a file comes with the distribution,
options.cfg.  If you want to change the program
defaults (and you probably do, in order to capture exactly the data
of interest to you), then make a copy of the configuration file.
By making a local copy that has a different name, your
configuration will not be clobbered if you update the joy package.


#### Analysis

Please see the file [analysis/README](analysis/README).

#### Installation

NOTE: THE DEFAULT CONFIGURATION USED BY THE INSTALL SCRIPT WILL
PERFORM ONGOING DATA CAPTURE, WHICH WILL RESTART UPON REBOOT.  If
you do not want an ongoing capture, we suggest that you do not use
the install script.

To install the package on your system, you will need to first build
it.  Run the script install-sh (as root, or using sudo) to install
the package.  

```
[joy]$ sudo ./install/install-sh
```

If you run the script with no arguments, then the default
configuration will be installed into the /usr/local/etc/joy directory. To have
a different configuration file installed, then use the -c option to
the install script:

```
[joy]$ sudo ./install/install-sh -c full-path-config-file.cfg
```

You can also configure anonymization of addresses, which requires a
file containing the internal subnets.  The default file for those
subnets is internal.net; you can change the configuration with the
-a option.  Similarly, you can change the watchfile of IP addresses
(using the -w option) or the SSH private key used to have files
uploaded via scp (using the -k option).  To see the full option
description for the installer, run that program with the -h option
to see the help or "usage" message.

#### Documentation

A man page will be built and installed automatically as part of the
package.  See the file joy.1, or after the install-sh script
has been run, access the man page through "man joy".
