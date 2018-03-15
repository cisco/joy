## 2.0 (01/28/2018)

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
  and then quiting without scrolling through all of the output
  (such piping to less)

