## 3.0.0

###### 07-20-2018

#### Changes

* Modified JOY infrastructure code to be thread safe.
  * Allowed support multiple work threads for packet processing.
  * Each worker thread uses own output file.
  * Removed global variables for Config.
  * Modified code infrastructure to use Config Structure.

* Modified the Makefile system to build the JOY infrastructure
  as a static and shared library.

* Implemented an API for utilizing the JOY Library (joy_api.[hc]).

* Implemented a Vector Packet Processing integration scheme to
  utilize VPP native infrastructure when building that integration.

* Created 2 API test programs, joy_api_test.c and joy_api_test2.c.

* Modified existing test programs to link against static JOY library
  instead of re-compiling the infrastructure code.

* Modified versioning to use Common Security Module (CSM) conventions.

* Modified build_pkg to accept package version on the command line.

#### Bugfixes

* Cleaned up coverity errors and warnings.

* Various bug fixes.

## 2.1

###### 07-20-2018

#### Changes

* Optimizations for "exe" option.
  (PR #171, #173)

* Robust application protocol identification.
  Provides the ability to identify L4 protocols
  using non-standard ports.
  (PR #180, #182, #190)

* Support for multiple HTTP messages.
  (PR #181)

* GUI and task scheduling for Windows Installer.
  (PR #185)

#### Bugfixes

* Fixed HTTP body printing off-by-one error.
  (PR #170)

* Using proper message length for IPFIX exporter.
  (PR #174)

* Fix memory leak when processing multiple files into a pipe.
  (PR #179)

* Fix TLS module realloc function usage.
  (PR #183)

* Remove extra JSON comma in DNS module when qdcount <= 0.
  (PR #192)

## 2.0

###### 01-28-2018

#### Changes

* Major JSON schema revision across the board,
  involving most protocol modules such as:
  http, dhcp, ike, tls, ppi, ip_id

* Improved documentation including:
  * Revision of `doc/workbench.pdf`
  * Revision of `doc/examples.sh`
  * New architecture document, `doc/using-joy-05.pdf`

* New features for the Sleuth package such as:
  * Fingerprinting capability
  * Linking DNS information

* Changed Sleuth option name `split` -> `groupby`

* By default, Sleuth now stiches flows together.

#### Bugfixes

* Fixed brokenpipe error that would occur when piping Sleuth output,
  and then quiting without scrolling through all of the output.

## 1.74

###### 01-22-2018

#### Changes
* Renamed `joyq` to `sleuth`.
  (PR #140)

* More robust TLS module that can now handle messages spread
  across multiple packets.
  (Issue #130, PR #141, #145)

* Hide configuration stderr output behind `show_config` option.
  By default this is turned off.
  (PR #146)

* Hide interfaces list stderr output behind `show_interfaces` option.
  By default this is turned off.
  (PR #156)

* Automatic filename generation now includes the interface mac address,
  and timestamp.
  (PR #156)

* Downgrade permission level after aquiring access to interface
  during "online" mode.
  (PR #152)

#### Bugfixes
* Check for bad sizes of TLS message length.
  (PR #148)


## 1.73
###### 11-30-2017

#### Changes
* Ability to create binaries for linux and macos.

* New runtime option, `preemptive_timeout`.
  (PR #110)

* Add Travis CI for continuous testing.
  (PR #133)

* Ability to choose compression at config.
  (PR #135, #136)

* Option to use bzip2 for compression.
  (PR #135)

#### Bugfixes
* Fix building with older versions of OpenSSL.
  (PR #132, Issue #121)

* Fix corner case when there is a single record in list.
  (PR #138)


## 1.72
###### 10-30-2017

#### Changes
* Support for Windows.
  (PR #64)

* New IKE protocol feature module.
  (PR #115)

* New SSH protocol feature module.
  (PR #79)

* New DHCP protocol feature module.
  (PR #74)

* Converted HTTP module into a feature.
  (PR #101)

* TLS crypto audit for Sleuth.
  (PR #92)

* Support building with OpenSSL 1.1.0
  (PR #122, Issue #121)

* Dynamic feature memory, to reduce footprint.
  (PR #98)

* Support for 802.1Q VLAN.
  (PR #83)

* New logging macros.
  (PR #67)

#### Bugfixes
* Fix unit test memory leaks.
  (PR #125)

* Fix salt iack and oack JSON.
  (PR #108)

* Allow fully qualified name for output directory.
  (PR #89)


## 1.71
###### 07-13-2017

#### Changes

* Created Sleuth python package consisting of
  generic functions/classes from Joyq.
  (PR #59)

#### Bugfixes
* Fix joyq pretty identation.
  (PR #61)

* Fix config ssl header path option.
  (PR #58)


## 1.7
###### 06-15-2017

#### Changes
* Updated nfv9 and ipfix numbers
  (Commit cfe94bf)

#### Bugfixes
None


## 1.6
###### 06-15-2017
#### Changes

* X509 certificate parsing for the TLS protocol module.
  (PR #44, #52)

* Ability for Joyq to consume pcap files directly.
  (PR #49)

#### Bugfixes
* Fix joyq ingestion of whitespace and floats
  for select option.
  (PR #55)


## 1.5
###### 02-16-2017
#### Changes

* New IPFIX collector.
  (PR #17)

* New IPFIX exporter.
  (PR #19)

* More robust file uploading.
  (PR #24)

* Use systemd for daemon install, if available.
  (PR #30)

* Blackbox testing framework for Joy.
  (PR #25, #35)

* Prototype TLS fingerprinting in Joy.
  (PR #23)

* Converted readme file to markdown format.
  (PR #22)

* Ability to update classifier parameters from url.
  (PR #20)

#### Bugfixes
* Use the correct flow end-time.
  (PR #26)

