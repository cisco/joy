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

Joy has been successfully run and tested on Linux (Debian, Ubuntu,
CentOS, and Raspbian), Mac OS X and Windows. The system has been built with
gcc and GNU make, but it should work with other development
environments as well.

Go to the Wiki for a guide on building:
[Build Instructions](https://github.com/cisco/joy/wiki/Building)

## License
See [License](https://github.com/cisco/joy/blob/master/LICENSE)
See [Copying](https://github.com/cisco/joy/blob/master/COPYING) for licenses of external libraries
