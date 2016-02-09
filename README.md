# wassup.lua

A flexible wifi scanner with pretty results for the text console.


### Screenshot

![](https://i.imgur.com/0hpIL.png)


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


### Links

Repository: <https://github.com/koniu/wassup>

Forum: <https://forum.openwrt.org/viewtopic.php?pid=122861#p122861>


### Author

copyleft (¿) koniu at riseup dot net

