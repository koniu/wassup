#!/usr/bin/env lua
--{{{ constants
name = "wassup.lua"
version = "v0"

text_attributes = {
    none=0, bold=1, underline=4, blink=5, reverse=7, conceal=8,
    black=30, red=31, green=32, yellow=33, blue=34, magenta=35, cyan=36, white=37,
    bblack=40, bred=41, bgreen=42, byellow=43, bblue=44, bmagenta=45, bcyan=46, bwhite=47
}
--}}}
--{{{ config
-- defaults
inf = 999999999
reps = inf
keys = { "sig", "essid" }
iface = "wlan0"
delay = 0
leave = reps
obscure = false
row_highlights = { "enc", "s" }
column_spacing = 1
buff = 1

-- colors 
colors = {
    def         = "none",
    sort        = "bold,white",
    highlight = {
        enc =   { ["WEP"] = "red", ["OPN"] = "green" },
        s =     { ["g"] = "blue" },
        graph = { ["n"] = "yellow,byellow", ["g"] = "black,bblack", ["r"] = "green,bgreen",
                  ["+"] = "green,bgreen", ["-"] = "red,bred", ["="] = "blue,bblue" },
    },
}

-- columns
column_order = {"bssid", "ch", "s", "essid", "sig", "min", "avg", "max", "loss", "enc"}
columns = {
    bssid   = { format = "%-17s",               },
    ch      = { format = "%2s",                 },
    s       = { format = "%1s",                 },
    essid   = { format = "%-20s",               },
    sig     = { format = "%3s",    reverse = 1  },
    noise   = { format = "%5s",                 },
    snr     = { format = "%3s",    reverse = 1  },
    min     = { format = " %3s",   reverse = 1  },
    avg     = { format = "%3s",    reverse = 1  },
    max     = { format = "%3s",    reverse = 1  },
    loss    = { format = "%5s%%",               },
    enc     = { format = "%-4s",                },
    vendor  = { format = "%-10s",               },
    tsf     = { format = "%14s",                },
    graph   = { format = "%-25s",               },
    ciph    = { format = "%-10s",               },
    auth    = { format = "%-4s",                },
    last_seen = { format = "%13s",              },
    first_seen = { format = "%13s",             },
}

-- vendor lists
vendors = {
    { files = { "/etc/manuf", "/usr/share/wireshark/manuf" },
      pattern = "# (.*)\n", sep = ":" },
    { files = { "/etc/manuf", "/usr/share/wireshark/manuf" },
      pattern = "%w%w:%w%w:%w%w%s-([%w%p]+)", sep = ":" },
    { files = { "oui.txt" }, pattern = "%(hex%)[\t%s]+(.*)\n", sep = "-" },
    { files = { "/usr/share/macchanger/wireless.list", "/usr/share/macchanger/OUI.list" },
      pattern = "%w%w %w%w %w%w (.*)\n", sep = " " },
}
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
    if posix then posix.sleep(n)
    elseif socket then socket.select(nil, nil, n)
    else os.execute("sleep " .. n) end
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
 -b <buffer>    number of scans in a cycle [1]\
 -m <method>    scan method [iw, iwinfo, iwlist or airport]\
\
 -k <c1,c2,...> show columns [bssid,ch,s,essid,sig,min,avg,max,loss,enc]\
 -s <c1,c2,...> sort by columns [sig,essid]\
 -f <filter>    filter by string [none]\
 -c <channel>   show only channel <num> [none]\
 -l <leave>     show out-of-range APs for <leave> of cycles [f = forever]\
 -g <c1,c2,...> highlight rows by field [enc,s]\
 -o             obfuscate bssid and essid columns\
\
 -C <cfgfile>   use settings from <cfgfile>\
 -h             help yourself\
"

function usage()
    print(help)
    os.exit(0)
end
--}}}
--{{{ sec2time
function sec2time(s, fmt)
    local dd, hh, mm, ss
    dd = math.floor(s / (3600*24))
    hh = math.floor((s - dd*24*3600) / 3600)
    mm = math.floor((s - dd*24*3600 - hh*3600) / 60)
    ss = math.floor((s - dd*24*3600 - hh*3600 - mm*60))
    return string.format(fmt, dd, hh, mm, ss)
end
--}}}
--{{{ header
function line_layout(left_fmt, left_list, right_fmt, right_list)
    local left = string.format(left_fmt, unpack(left_list))
    local right = string.format(right_fmt, unpack(right_list))
    local space = string.rep(" ", width - #left - #right)
    return left .. space .. right
end
function header()
    local l1 = line_layout("[ %s @ %s/%s ]", { name, iface, method},
                           "[ iter: %s%s  elapsed: %s ]", { state.iter, (reps == inf and "") or "/"..reps, sec2time(now-start, "%dd %02d:%02d:%02d") })
    local l2 = line_layout("[ %-"..(#tostring(buff) * 2 + 6).."s ][ results: %2s  avg: %2s ]", { state.action, last_result_num, avg_result_num },
                           "[ showing: %s  seen: %s ]", { len(state.filtered), len(state.seen) })
    io.stdout:write("\27[0;0f")
    io.stdout:write("\27[K"..l1.."\n")
    io.stdout:write("\27[K"..l2.."\n")
    io.stdout:write("\27[K")
end
--}}}
--{{{ parse
function parse(method, res, survey)
    -- get results by method
    local ap = parsers[method](res, survey)

    -- calculate snr
    if ap.noise and ap.sig then
        ap.snr = math.abs(ap.sig - ap.noise)
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
    ap.sig = tonumber(res:match("signal: ([%w%p]-)[ /]"))
    ap.freq = tonumber(res:match("freq: (.-)\n"))
    ap.tsf = tonumber(res:match("TSF: (%d-) usec"))
    ap.tsf = ap.tsf and sec2time(ap.tsf/(1000*1000),"%3dd %02d:%02d:%02d")
    ap.auth = res:match("Authentication suites: (.-)\n")
    ap.ciph = res:match("Pairwise ciphers: (.-)\n")

    -- parse encryption
    if not res:find("Privacy") then
        ap.enc = "OPN"
    else
        local wpa = res:find("WPA")
        local rsn = res:find("RSN")
        if wpa and rsn then ap.enc = "WPA*"
        elseif rsn then ap.enc = "WPA2"
        elseif wpa then ap.enc = "WPA"
        else ap.enc = "WEP" end
    end

    -- parse iw survey info
    for _, chan in ipairs(survey) do
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
    ap.sig=tonumber(res:match("Signal level[:=](.-)[ /]"))
    ap.noise=tonumber(res:match("Noise level[:=](.-) dBm"))
    ap.tsf=res:match("tsf=(%w-)\n")
    ap.tsf=ap.tsf and sec2time(tonumber('0x'..ap.tsf)/(1000*1000), "%3dd %02d:%02d:%02d")
    ap.auth = res:match("Authentication Suites.- : (.-)\n")
    ap.ciph = res:match("Pairwise Ciphers.- : (.-)\n")

    -- parse encryption
    if not res:find("Encryption key:on") then
        ap.enc = "OPN"
    else
        local wpa = res:find("WPA Version 1")
        local rsn = res:find("WPA2 Version 1")
        if wpa and rsn then ap.enc = "WPA*"
        elseif rsn then ap.enc = "WPA2"
        elseif wpa then ap.enc = "WPA"
        else ap.enc = "WEP" end
    end
    
    return ap
end
--}}}
--{{{ parse_iwinfo
parsers.iwinfo = function(res)
    -- parse iwinfo scan
    local ap = {}
    ap.bssid = res.bssid
    ap.essid = res.ssid or ""
    ap.ch = res.channel
    ap.sig = res.signal
    ap.auth = table.concat(res.encryption.auth_suites, " ")
    ap.ciph = table.concat(res.encryption.pair_ciphers, " ")

    -- parse encryption
    if res.encryption.enabled then
        if res.encryption.wep then
            ap.enc = "WEP"
        elseif res.encryption.wpa == 1 then
            ap.enc = "WPA"
        elseif res.encryption.wpa == 2 then
            ap.enc = "WPA2"
        elseif res.encryption.wpa == 3 then
            ap.enc = "WPA*"
        end
    else
        ap.enc = "OPN"
    end

    return ap
end
--}}}
--{{{ parse_airport
parsers.airport = function(res)
    -- parse airport scan info
    local ap = {}
    ap.essid = (res:sub(1,32)):match("^%s-(%w[%w%p%s]+)")
    ap.bssid = res:sub(34,50)
    ap.sig = tonumber(res:sub(52,55))
    ap.ch = tonumber(res:sub(57,58))
    -- parse encryption
    local sec = res:sub(70,#res)
    if sec:find("NONE") then
        ap.enc = "OPN"
    elseif sec:find("WEP") then
        ap.enc = "WEP"
    else
        local wpa = sec:find("WPA%(")
        local rsn = sec:find("WPA2%(")
        if wpa and rsn then ap.enc = "WPA*"
        elseif rsn then ap.enc = "WPA2"
        elseif wpa then ap.enc = "WPA" end
        ap.ciph = sec:match("%(([%w%p]-)/")
        ap.auth = sec:match("/([%w%p]-)/")
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
--{{{ get_vendor
function get_vendor(mac)
    if not mac then return end
    for i, list in ipairs(vendors) do
        for j, file in ipairs(list.files) do
            if readable(file) then
                local fmac = string.gsub(mac:sub(1,8),":",list.sep)
                local str = read(string.format("grep -i ^'%s' %s", fmac, file), "popen")
                if #str > 0 then return str:match(list.pattern) end
            end
        end
    end
    return ""
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
    local res = split(read(iwlist_bin.." "..iface.." scan", "popen"), "Cell %d%d")
    table.remove(res, 1)
    return res
end
scanners.iwinfo = function(iface)
    local type = iwinfo.type(iface)
    return iwinfo[type].scanlist(iface)
end
scanners.airport = function(iface)
    local res = split(read(airport_bin.." "..iface.." scan", "popen"), "\n")
    table.remove(res, 1)
    return res
end
--}}}
--{{{ update_graph
function update_graph(g, s)
    return g:sub(2,#g) .. s
end
--}}}
--{{{ update_buffer
function update_buffer(bssid)
    local result = state.results[bssid]
    local buffer = state.buffer[bssid] or {}
    local ap = result
    ap.sig_sum = (buffer.sig_sum or 0) + result.sig
    ap.noise_sum = result.noise and (buffer.noise_sum or 0) + result.noise
    ap.seen = (buffer.seen or 0) + 1
    ap.sig = math.floor(ap.sig_sum / ap.seen)
    ap.noise = ap.noise_sum and math.floor(ap.noise_sum / ap.seen)
    state.buffer[bssid] = ap
end

--}}}
--{{{ update_ap
function update_ap(bssid)
    local result = state.buffer[bssid]
    local record = state.seen[bssid]
    local ap = result or record
    -- first seen
    if not record and result then
        ap.s = "n"
        ap.graph = string.rep(" ", column_width(columns.graph.format))
        ap.seen = 1
        ap.sum = result.sig
        ap.first_seen_i = state.iter
        ap.first_seen_t = now
        ap.last_seen_i = state.iter
        ap.vendor = get_vendor(bssid) or ""
        state.seen[bssid] = {}
    end
    -- gone
    if record and not result then
        ap.s = "g"
        ap.sig = false
        ap.snr = false
        ap.noise = false
        ap.last_seen = os.date("!%H:%M:%S ago", now - (ap.last_seen_t or record.last_seen_t))
    end
    -- update stats
    if result then
        record = record or {}
        ap.last_seen_i = state.iter
        ap.last_seen_t = now
        ap.seen = (record.seen or 0) + 1
        ap.sum = (record.sum or 0 ) + result.sig
        ap.avg = math.floor(ap.sum / ap.seen)
        ap.max = math.max((record.max or -100), result.sig)
        ap.min = math.min((record.min or 0), result.sig)
        ap.last_seen = "now"
        ap.dev_sum = (record.dev_sum or 0) + math.abs(ap.avg - result.sig)
        ap.mdev = ap.dev_sum / ap.seen
        if record.bssid then
            if record.tsf and result.tsf and record.tsf > result.tsf then ap.s = "R"
            elseif record.s == "g" then ap.s = "r"
            elseif result.sig > ap.avg + math.ceil(ap.mdev) then ap.s = "+"
            elseif result.sig < ap.avg - math.ceil(ap.mdev) then ap.s = "-"
            else ap.s = "=" end
        end
    end
    if record then
        local total = state.iter - (ap.first_seen_i or record.first_seen_i) + 1
        ap.loss = math.floor((total - ap.seen) * 100 / total)
        ap.graph = update_graph(record.graph or ap.graph, ap.s)
        ap.first_seen = os.date("!%H:%M:%S ago", now - (ap.first_seen_t or record.first_seen_t))
    end

    -- update seen table
    for k, v in pairs(ap) do
        state.seen[bssid][k] = v
    end
end
--}}}
--{{{ sortf
function sortf(a,b)
    for i, key in ipairs(keys) do
        local ta, tb = type(a[key]), type(b[key])
        if ta ~= tb then return ta < tb end
        if a[key] ~= b[key] then
            if columns[key].reverse then
                return (a[key] or -100) > (b[key] or -100)
            else
                return (a[key] or -100) < (b[key] or -100)
            end
        end
    end
end
--}}}
--{{{ obfuscate
function obfuscate(ap)
    if not obscure then return ap end
    local obf_ap = {}; for k,v in pairs(ap) do obf_ap[k] = v end
    obf_ap.bssid = ap.bssid:gsub("%w%w:%w%w:%w%w$","xx:xx:xx")
    obf_ap.essid = string.rep('x', #(ap.essid or ""))
    return obf_ap
end
--}}}
--{{{ column_width
function column_width(fmt)
    return #string.format(fmt,"")
end
--}}}
--{{{ column_fmt
function column_fmt(cname, old_attr, ap)
    local column = columns[cname]
    local width = column_width(column.format)
    -- get value and highlight table
    local value
    local highlights = {}
    if ap then
        value = tostring(ap[cname] or ""):sub(1, width)
        highlights = colors.highlight[cname] or {}
    else
        value = (column.title or cname):sub(1, width)
        for i, key in ipairs(keys) do
            if key == cname then highlights[cname] = colors.sort end
        end
    end
    -- format, highlight and return content
    value = string.format(column.format, value)
    for pattern, color in pairs(highlights) do
        value = value:gsub(pattern, attr(color) .. "%1" .. old_attr)
    end
    return value .. string.rep(" ", column_spacing)
end
--}}}
--{{{ row_attr
function row_attr(ap)
    local a = ""
    for i, highlight in ipairs(row_highlights) do
        local hcolors = colors.highlight[highlight] or {}
        for pattern, hcolor in pairs(hcolors) do
            if ap[highlight]:match(pattern) then
                a = attr(hcolor)
                break
            end
        end
    end
    return a
end
--}}}
--{{{ attr
function attr(def)
    local r = ""
    for i, s in ipairs(split(def,",")) do
        r = r .. string.format("\27[%sm", text_attributes[s] or "")
    end
    return r
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
    buffer = {},
    iter = 0,
}

-- parse options
opts = getopt( arg, "dfirslckmgbC" )
for k, v in pairs(opts) do
    if k == "C" then if readable(v) then dofile(v) end end
    if k == "h" then usage() end
    if k == "r" then reps = tonumber(v) end
    if k == "s" then keys = split(v,",") end
    if k == "i" then iface = v end
    if k == "d" then delay = tonumber(v) end
    if k == "f" then filter = v end
    if k == "c" then channel = v end
    if k == "l" then leave = tonumber(v) or reps end
    if k == "m" then method = v end
    if k == "g" then row_highlights = split(v,",") end
    if k == "k" then column_order = split(v,",") end
    if k == "o" then obscure = true end
    if k == "b" then buff = tonumber(v) end
end

-- get environment
start = os.date("%s")
iw_bin = chomp(read("which iw", "popen"))
iwlist_bin = chomp(read("which iwlist", "popen"))
airport_bin = chomp(read("which airport", "popen"))
local res, err = pcall(require, "socket")
local res, err = pcall(require, "posix")

-- calculate screen width
width = -column_spacing
for i, c in ipairs(column_order) do
    if columns[c] then
        width = width + column_width(columns[c].format) + column_spacing
    end
end

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
io.stdout:write("\27[2J")
--}}}
--{{{ main loop
avg_result_num = 0
last_result_num = 0
while state.iter < reps do
--{{{ scan and parse
    now = os.date("%s")
    counter = (counter or 0) + 1
    if buff > 1 then
        state.action = string.format("scan %s/%s", counter, buff)
    else
        state.action = "scan"
    end
    header()

    local res, survey = scanners[method](iface)
    state.results = {}
    for i = 1, #res do
        local ap = parse(method, res[i], survey)
        if ap.bssid and ap.sig then
            state.results[ap.bssid] = ap
            update_buffer(ap.bssid)
        end
    end
    last_result_num = len(state.buffer)
--}}}
    if counter == buff then
    --{{{ update APs
        if len(state.buffer) == 0 then sleep(1) else state.iter = state.iter + 1 end
        sum_result_num = (sum_result_num or 0) + len(state.buffer)
        avg_result_num = math.floor(sum_result_num / state.iter)
        -- update buffered
        for _, ap in pairs(state.buffer) do
            update_ap(ap.bssid)
        end
        -- update gone
        for _, ap in pairs(state.seen) do
            if not state.buffer[ap.bssid] then update_ap(ap.bssid) end
        end
        state.buffer = {}
        counter = 0
    --}}}
    --{{{ filter for display
        state.filtered = {}
        for _, ap in pairs(state.seen) do
            -- filter APs for display
            if ((not channel) or (channel and ap.ch == tonumber(channel))) and
                state.iter - ap.last_seen_i < leave and
                ((not filter) or
                string.lower(ap.essid):find(string.lower(filter)) or
                string.lower(ap.bssid):find(string.lower(filter)) or
                string.lower(ap.enc):find(string.lower(filter)) or
                string.lower(ap.vendor):find(string.lower(filter)))
            then
                state.filtered[ap.bssid] = ap
            end
        end
    --}}}
    --{{{ prepare and sort list for display
        local list = {}
        for _, ap in pairs(state.filtered) do table.insert(list, obfuscate(ap)) end
        table.sort(list, sortf)
    --}}}
    --{{{ output
        -- update header
        header()
        -- print table headers
        local output = ""
        io.stdout:write("\27[4;0f\27[K")
        for i, cname in ipairs(column_order) do
            output = output .. column_fmt(cname, attr(colors.def))
        end
        io.stdout:write(output .. "\n\27[K\n")
        -- print result table
        for i, ap in ipairs(list) do
            -- set row text attributes
            local rattr = attr(colors.def) .. row_attr(ap)
            -- format columns
            local cols = ""
            for i, cname in ipairs(column_order) do
                cols = cols .. column_fmt(cname, rattr, ap)
            end
            -- output row
            local output = "\27[K" .. rattr .. cols .. attr(colors.def) .. "\n"
            io.stdout:write(output)
        end
        -- clear remaining lines
        for i=1,1000 do io.stdout:write("\27[K\27[1B") end
    --}}}
    end
--{{{ sleep
    if delay > 0 then
        state.action = "sleep"
        header()
        sleep(delay)
    end
    if not (buff == 1 and delay == 0) and counter == 0 then
        last_result_num = 0
    end
--}}}    
end
--}}}
-- vim: foldmethod=marker:filetype=lua:expandtab:shiftwidth=4:tabstop=4:softtabstop=4
