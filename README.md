# wassup.lua

A flexible wifi scanner with pretty results for the text console.


### Screenshot

![](https://i.imgur.com/dgY3aIW.png)


### Dependencies

The only dependencies are `Lua 5.1` and one of the following backends:

  * `iwlist(8)` - from `wireless-tools`, based on wext and pretty standard
  * `iw(8)` - `nl80211` based utility, common on modern systems
  * `wpa_cli(8)` - `wpa_supplicant` command-line interface
  * `libiwinfo` - nice abstraction library available in OpenWrt trunk
  * `airport` - standard OSX command line utility

It's intended to run as root - needed for active scanning.

Originally written on and for use with OpenWrt, but should run on any
platform that features the above tools. Tested on Debian and OSX 10.6.5.


### Usage

    wassup.lua <options>

    -i <iface>     interface to use [wlan0]
    -d <delay>     delay between scan cycles [0]
    -r <repeat>    number of scan cycles [0 = forever]
    -b <buffer>    number of scans in a cycle [1]
    -m <method>    scan method [iw, iwinfo, iwlist, wpacli or airport]
    -S <dir>       path to wpa_supplicant sockets [/var/run/wpa_supplicant]
    -p             force passive scanning (affects 'iw' backend only)

    -k <c1,c2,...> show columns [bssid,ch,s,essid,sig,min,avg,max,loss,enc]
    -s <c1,c2,...> sort by columns [sig,essid]
    -f <filter>    filter by string [none]
    -c <channel>   show only channel <num> [none]
    -l <leave>     show out-of-range APs for <leave> of cycles [f = forever]
    -g <c1,c2,...> highlight rows by field [enc,s]
    -o             obfuscate bssid and essid columns

    -C <cfgfile>   use settings from <cfgfile>
    -h             help yourself


### Valid columns

This is the list of columns available for use with `-k`, `-s` and cfgfile.
Note that some might be empty depending on the setup and scan method.

  * `auth` - authentication methods
  * `avg` - average signal strength
  * `bssid` - BSSID
  * `ciph` - cipher
  * `ch` - channel number
  * `enc` - encryption
  * `essid` - ESSID
  * `first_seen` - time since first seen
  * `graph` - a graph of signal change
  * `last_seen` - time since last seen
  * `loss` - % of cycles without seeing the AP (since first seen)
  * `max` - highest signal strength recorded
  * `min` - lowest signal strength recorded
  * `noise` - noise level in the last cycle
  * `s` - change in signal from the previous cycle (+, -, or =)
  * `sig` - signal strength in the last cycle
  * `snr` - signal-to-noise ratio
  * `tsf` - time sync counter, sometimes corresponding to uptime
  * `vendor` - manufacturer based on BSSID


### Configuration files

Nearly all options can be configured from the command line. For frequently
used combinations, changes in formatting and more, you can create config
files which override the defaults found at the top of `wassup.lua`.

Syntax is pure Lua. To use the files run `wassup.lua -C <configfile>`.

Example:

    keys = { "avg", "essid" }
    obscure = true
    method = "wpacli"
    column_order = {"bssid", "ch", "graph", "essid", "snr", "sig", "min", "avg", "max", "tsf"}
    columns.graph = { format = "%-45s" }

For more info see the _config_ section at the top of
[`wassup.lua`](https://github.com/koniu/wassup/blob/master/wassup.lua#L13..L73).


### Links

Repository: <https://github.com/koniu/wassup>

Forum: <https://forum.openwrt.org/viewtopic.php?pid=122861#p122861>


### Author

copyleft (¿) koniu at riseup dot net

