#!/usr/bin/env lua
--{{{ config

-- constants
name = "wassup.lua"
version = "v0"

-- defaults
inf = 999999999
reps = inf
key = "sig"
iface = "wlan0"
delay = 0
leave = reps
manuf = "/etc/manuf"
row_highlight_field = "enc"

-- colors 
colors = {
    def         = "\27[0;0m",
    gone        = "\27[0;34m",
    sort        = "\27[1;37m",
    highlight = {
        s   = { ["n"] = "\27[1;37m", ["g"] = "\27[0;34m", ["r"] = "\27[0;33m",
                ["+"] = "\27[1;32m", ["="] = "", ["-"] = "\27[1;31m" },
        enc = { ["WEP"] = "\27[0;31m", ["OPN"] = "\27[0;32m", ["WPA2"] = "\27[0;0m", ["WPA$"] = "\27[0;0m" },
    },
}

-- columns
columns = {
    bssid   = { f = "%-17s "            },
    ch      = { f = "%2s "              },
    s       = { f = "%1s ",     t = ""  },
    essid   = { f = "%-20s  "           },
    sig     = { f = "%3s  ",    r = 1   },
    min     = { f = " %3s ",    r = 1   },
    avg     = { f = "%3s ",     r = 1   },
    max     = { f = "%3s  ",    r = 1   },
    loss    = { f = "%4s  "             },
    snr     = { f = "%3s ",     r = 1   },
    noise   = { f = "%5s  "             },
    enc     = { f = "%-4s "             },
    manuf   = { f = "%-10s "            },
    tsf     = { f = "%14s "             },
}
column_order = {"bssid", "ch", "s", "essid", "sig", "min", "avg", "max", "loss", "enc"}

--}}}
--{{{ functions
--{{{ getopt
function getopt( arg, options )
  local tab = {}
  for k, v in ipairs(arg) do
    if string.sub( v, 1, 2) == "--" then
      local x = string.find( v, "=", 1, true )
      if x then tab[ string.sub( v, 3, x-1 ) ] = string.sub( v, x+1 )
      else      tab[ string.sub( v, 3 ) ] = true
      end
    elseif string.sub( v, 1, 1 ) == "-" then
      local y = 2
      local l = string.len(v)
      local jopt
      while ( y <= l ) do
        jopt = string.sub( v, y, y )
        if string.find( options, jopt, 1, true ) then
          if y < l then
            tab[ jopt ] = string.sub( v, y+1 )
            y = l
          else
            tab[ jopt ] = arg[ k + 1 ]
          end
        else
          tab[ jopt ] = true
        end
        y = y + 1
      end
    end
  end
  return tab
end
--}}}
--{{{ sleep
function sleep(n)
    os.execute("sleep " .. n)
end
--}}}
--{{{ split
function split(str, pat)
   local t = {}  -- NOTE: use {n = 0} in Lua-5.0
   local fpat = "(.-)" .. pat
   local last_end = 1
   local s, e, cap = str:find(fpat, 1)
   while s do
      if s ~= 1 or cap ~= "" then
     table.insert(t,cap)
      end
      last_end = e+1
      s, e, cap = str:find(fpat, last_end)
   end
   if last_end <= #str then
      cap = str:sub(last_end)
      table.insert(t, cap)
   end
   return t
end
--}}}
--{{{ usage
help=name .. " " .. version .. " - WAyereless Site SUrveying Program \n\nUsage: "..arg[0].." <options>\
\
 -i <iface>     interface to use [wlan0]\
 -d <delay>     delay between scan cycles [0]\
 -r <repeat>    number of scan cycles [0 = forever]\
 -m <method>    scan method [iw, iwinfo or iwlist]\
\
 -k <c1,c2,...> show columns <c1,c2,...>\
 -s <col>       sort by column [sig]\
 -f <filter>    filter by string [none]\
 -c <channel>   show only channel <num> [none]\
 -l <leave>     show out-of-range APs for <leave> of cycles [f = forever]\
 -g <col>       highlight rows by field [enc]\
\
 -h             help yourself\
"

function usage()
    print(help)
    os.exit(0)
end
--}}}
--{{{ sec2time
function sec2time(s)
    local hh, mm, ss
    hh = string.format("%02.f", math.floor(s/3600));
    mm = string.format("%02.f", math.floor(s/60 - (hh*60)));
    ss = string.format("%02.f", math.floor(s - hh*3600 - mm*60));
    return string.format("%s:%s:%s", hh, mm, ss)
end
--}}}
--{{{ stats
function line_layout(left_fmt, left_list, right_fmt, right_list)
    local left = string.format(left_fmt, unpack(left_list))
    local right = string.format(right_fmt, unpack(right_list))
    local space = string.rep(" ", width - #left - #right)
    return left .. space .. right
end
function stats()
    local now = os.date("%s")
    local l1 = line_layout("%s %s", { name, version },
                           "iter %s%s, elapsed %s", { state.iter, (reps == inf and "") or "/"..reps, sec2time(now-start) })
    local l2 = line_layout("%s %s", { iface, state.action },
                           "showing: %s  scanned: %s  seen: %s", { len(state.filtered), len(state.results), len(state.seen) })
    io.stdout:write("\27[0;0f\27[K")
    io.stdout:write(l1.."\n"..l2)
    io.stdout:write("\27[0;0f")
end
--}}}
--{{{ parse
function parse(method, res, survey)
    -- get results by method
    local ap = parsers[method](res, survey)

    -- calculate snr
    if ap.noise and ap.sig then
        ap.snr = -(ap.noise - ap.sig)
    end

    return ap
end
--}}}
--{{{ parse_iw
parsers = {}
parsers.iw = function(res, survey)
    -- parse iw scan info
    local ap = {}
    ap.bssid = res:match("(..:..:..:..:..:..) ")
    ap.essid = res:match("SSID: (.-)\n")
    ap.ch = tonumber(res:match("channel (.-)\n"))
    ap.sig = tonumber(res:match("signal: (.-) dBm"))
    ap.freq = tonumber(res:match("freq: (.-)\n"))
    ap.tsf = res:match("TSF:.- usec %((.-)%)\n")

    -- parse encryption
    if not res:find("Privacy") then
        ap.enc = "OPN"
    elseif res:find("TKIP") or res:find("CCMP") then
        if res:find("RSN") then
            ap.enc = "WPA2"
        else
            ap.enc = "WPA"
        end
    else
        ap.enc = "WEP"
    end

    -- parse iw survey info
    for _, chan in ipairs(survey) do
        noise_stats = true
        if chan:match("frequency:.*" .. tostring(ap.freq) .. " MHz") then
            ap.noise = chan:match("noise:.-(...) dBm")
            break
        end
    end

    return ap
end
--}}}
--{{{ parse_iwlist
parsers.iwlist = function(res)
    -- parse iwlist scan info
    local ap = {}
    ap.bssid=res:match("Address: (.-)\n")
    ap.essid=res:match("ESSID:\"(.-)\"")
    ap.ch=tonumber(res:match("Channel:(.-)\n"))
    ap.sig=tonumber(res:match("Signal level[:=](.-) dBm"))
    ap.noise=tonumber(res:match("Noise level[:=](.-) dBm"))
    if ap.noise then noise_stats = true end

    -- parse encryption
    if not res:find("Encryption key:on") then
        ap.enc = "OPN"
    elseif res:find("WPA2 Version 1") then
        ap.enc = "WPA2"
    elseif res:find("WPA Version 1") then
        ap.enc = "WPA"
    else
        ap.enc = "WEP"
    end
    
    return ap
end
--}}}
--{{{ parse_iwinfo
parsers.iwinfo = function(res)
    -- parse iwinfo scan
    local ap = {}
    ap.bssid = res.bssid
    ap.essid = res.ssid
    ap.ch = res.channel
    ap.sig = res.signal
    noise_stats = false

    -- parse encryption
    if res.encryption.enabled then
        if res.encryption.wep then
            ap.enc = "WEP"
        elseif res.encryption.wpa == 1 then
            ap.enc = "WPA"
        elseif res.encryption.wpa > 1 then
            ap.enc = "WPA2"
        end
    else
        ap.enc = "OPN"
    end

    return ap
end
--}}}
--{{{ len
function len(t)
    local count = 0
    for k, v in pairs(t) do count = count + 1 end
    return count
end
--}}}
--{{{ file_readable
function readable(filename)
    local file = io.open(filename)
    if file then
        io.close(file)
        return true
    end
    return false
end
--}}}
--{{{ read 
function read(cmd, src)
    local f = io[src](cmd)
    local v = f:read("*a")
    f:close()
    return v
end
--}}}
--{{{ get_manuf
function get_manuf(mac)
    if not mac then return end
    if not readable(manuf) then return "" end
    str = read("grep -i ^"..mac:sub(1,8).." " .. manuf, "popen")
    return (str:sub(10,20)):match("[%w%p]*")
end
--}}}
--{{{ cls
function cls(x,y)
    io.stdout:write("\27[2J")
    io.stdout:write("\27["..x..";"..y.."f")
end
--}}}
--{{{ remove_item
function remove_item(t, item)
    for i, entry in pairs(t) do
        if item == entry then
            table.remove(t, i)
        end
    end
    return t
end
--}}}
--{{{ chomp
function chomp(str)
    return str:sub(1,#str-1)
end
--}}}
--{{{ scanners
scanners = {}
scanners.iw = function(iface)
    local res = split(read(iw_bin.." "..iface.." scan", "popen"), "\nBSS ")
    local survey = split(read(iw_bin.." "..iface.." survey dump", "popen"), "Survey data")
    return res, survey
end
scanners.iwlist = function(iface)
    local res = split(read(iwlist_bin.." "..iface.." scan", "popen"), "Cell")
    table.remove(res, 1)
    return res
end
scanners.iwinfo = function(iface)
    local type = iwinfo.type(iface)
    return iwinfo[type].scanlist(iface)
end
--}}}
--{{{ update_ap
function update_ap(bssid)
    local result = state.results[bssid]
    local record = state.seen[bssid]
    local ap = result or record
    -- first seen
    if not record and result then
        ap.s = "n"
        ap.seen = 1
        ap.sum = result.sig
        ap.first_seen = state.iter
        ap.last_seen = state.iter
        ap.manuf = get_manuf(bssid) or ""
        state.seen[bssid] = {}
    end
    -- gone
    if record and not result then
        ap.s = "g"
        ap.sig = false
        ap.snr = false
        ap.noise = false
    end
    -- update stats
    if result then
        if record then
            if record.s == "g" then ap.s = "r"
            elseif record.sig > result.sig then ap.s = "-"
            elseif record.sig < result.sig then ap.s = "+"
            elseif record.sig == result.sig then ap.s = "="
            end
        else
            record = {}
        end
        ap.last_seen = state.iter
        ap.seen = (record.seen or 0) + 1
        ap.sum = (record.sum or 0 ) + result.sig
        ap.avg = math.floor(ap.sum / ap.seen)
        ap.max = math.max((record.max or -100), result.sig)
        ap.min = math.min((record.min or 0), result.sig)
    end
    if record then
        local total = state.iter - (ap.first_seen or record.first_seen) + 1
        ap.loss = math.floor((total - ap.seen) * 100 / total) .. "%"
    end

    -- update seen table
    for k, v in pairs(ap) do
        state.seen[bssid][k] = v
    end
end
--}}}
--}}}
--{{{ init
-- initialize data structure
state = {
    action = "",
    seen = {},
    results = {},
    filtered = {},
    iter = 0,
}

-- parse options
opts = getopt( arg, "dfirslckmg" )
for k, v in pairs(opts) do
    if k == "h" then usage() end
    if k == "r" then reps = tonumber(v) end
    if k == "s" then key = v end
    if k == "i" then iface = v end
    if k == "d" then delay = tonumber(v) end
    if k == "f" then filter = v end
    if k == "c" then channel = v end
    if k == "l" then leave = tonumber(v) or reps end
    if k == "m" then method = v end
    if k == "g" then row_highlight_field = v end
    if k == "k" then 
        column_order = {}
        for _, col in ipairs(split(v, ",")) do
            table.insert(column_order, col)
        end
    end
            
end

-- get environment
start = os.date("%s")
width = os.getenv("COLUMNS") or 80
iw_bin = chomp(read("which iw", "popen"))
iwlist_bin = chomp(read("which iwlist", "popen"))

-- select scanning method
local res, err = pcall(require, "iwinfo")
if not method then
    if res then
        method = "iwinfo"
    elseif #iw_bin > 0 then
        method = "iw"
    elseif #iwlist_bin > 0 then
        method = "iwlist"
    else
        io.stderr:write("No scanning method available")
        os.exit(1)
    end
end

-- clear screen
cls(0,0)
--}}}
--{{{ main loop
while state.iter < reps do
--{{{ scan and parse
    -- read iw scan
    state.action = "scan"
    stats()
    local res, survey = scanners[method](iface)
    if #res == 0 then sleep(1) else state.iter = state.iter + 1 end

    -- parse iw results/survey outputs
    state.results = {}
    for i = 1, #res do
        local ap = parse(method, res[i], survey)
        if ap.bssid then
            state.results[ap.bssid] = ap
            update_ap(ap.bssid)
        end
    end
--}}}
--{{{ update gone
    for _, ap in pairs(state.seen) do
        if not state.results[ap.bssid] then update_ap(ap.bssid) end
    end
--}}}
--{{{ filter for display
    state.filtered = {}
    for _, ap in pairs(state.seen) do
        -- filter APs for display
        if ((not channel) or (channel and ap.ch == tonumber(channel))) and
            state.iter - ap.last_seen < leave and
            ((not filter) or
            string.lower(ap.essid):find(string.lower(filter)) or
            string.lower(ap.bssid):find(string.lower(filter)) or
            string.lower(ap.enc):find(string.lower(filter)) or
            string.lower(ap.manuf):find(string.lower(filter)))
        then
            state.filtered[ap.bssid] = ap
        end
    end
--}}}
--{{{ prepare and sort list for display
    local list = {}
    for _, ap in pairs(state.filtered) do table.insert(list, ap) end
    
    local sortf
    if columns[key].r then
        sortf = function(a,b) return (a[key] or -100) > (b[key] or -100) end
    else
        sortf = function(a,b) return (a[key] or -100) < (b[key] or -100) end
    end
    table.sort(list, sortf)
--}}}
--{{{ output
    -- clear screen + update 
    cls(0,0)
    stats()
    io.stdout:write("\27[4;0f\27[K")

    -- get column formats
    if (not cols) then
        cols = {}
        if not noise_stats then
            remove_item(column_order, "noise")
            remove_item(column_order, "snr")
        end
        if not readable(manuf) then
            remove_item(column_order, "manuf")
        end
    end

    -- print table headers
    local output = ""
    local color
    for i, cname in ipairs(column_order) do
        local c = columns[cname]
        if cname == key then color = colors.sort else color = colors.def end
        output = output .. color .. string.format(c.f, c.t or cname) .. colors.def
    end
    io.stdout:write(output .. "\n\n")
    
    -- print result table
    for i, r in ipairs(list) do

        -- set row color
        local color = colors.def
        local hcolors = colors.highlight[row_highlight_field] or {}
        for pattern, hcolor in pairs(hcolors) do
            if r[row_highlight_field]:match(pattern) then color = hcolor end
        end

        -- format row
        local output = color
        for i, cname in ipairs(column_order) do
            local c = columns[cname]
            local value = tostring(r[cname] or ""):sub(1, tonumber(c.f:match("%%%-?(%d-)s")) or 100)
            local hcolors = colors.highlight[cname] or {}
            for pattern, hcolor in pairs(hcolors) do
                value = value:gsub("("..pattern..")", hcolor.."%1"..color)
            end
            output = output .. string.format(c.f, value)
        end
        output = output .. colors.def .. "\n"

        -- print
        io.stdout:write(output)
    end
--}}}
--{{{ sleep
    if delay > 0 then
        state.action = "sleep"
        stats()
        sleep(delay)
    end
--}}}    
end
--}}}
-- vim: foldmethod=marker:filetype=lua:expandtab:shiftwidth=4:tabstop=4:softtabstop=4
