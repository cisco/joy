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
  (Issue #130, PR #145)

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

###### 07-05-2017

#### Changes

#### Bugfixes

* Fix joyq pretty identation.
  (PR #61)

