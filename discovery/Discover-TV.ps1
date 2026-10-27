<#
.SYNOPSIS
    Read-only smart TV discovery and identification for the local network.

.DESCRIPTION
    Finds TVs and streaming devices on your LAN and identifies make, model,
    OS and firmware without changing anything on any device.

    What it does (all read-only):
      1. Detects your PC's active LAN interface and subnet.
      2. Ping sweep of the subnet (fills the ARP table so MACs are visible).
      3. Reads the ARP table (IP -> MAC) and optional IEEE OUI vendor lookup.
      4. SSDP / UPnP M-SEARCH, then fetches each device description XML
         (manufacturer, modelName, modelNumber, friendlyName).
      5. mDNS / DNS-SD queries (Google Cast, Android TV Remote, AirPlay,
         Amazon Fire TV, Spotify Connect, Roku, etc.) and reads TXT records.
      6. TCP port fingerprinting for known TV control ports.
      7. Vendor info endpoints that answer without pairing or login:
           Samsung Tizen  GET  :8001/api/v2/
           Roku           GET  :8060/query/device-info
           Google Cast    GET  :8008 or :8443 /setup/eureka_info
           Vizio          GET  :7345 or :9000 /state/device/deviceinfo
           Philips        GET  :1925 or :1926 /6/system (and /1/system)
           Panasonic      GET  :55000/nrc/ddd.xml
           Sony Bravia    POST /sony/system getInterfaceInformation (a getter)
      8. Optional (-TryAdb): ADB connect + getprop on Android/Google/Fire TV.
         This makes the TV show an "Allow USB debugging?" prompt, so it is
         off by default.

    Nothing is written to any device. No pairing, no login attempts, no
    settings changes. Results are saved to a local folder only.

.PARAMETER Subnet
    CIDR to scan, e.g. 192.168.1.0/24. Default: auto-detected (capped at /22).

.PARAMETER TimeoutMs
    Per-probe timeout in milliseconds. Default 800.

.PARAMETER Offline
    Skip downloading the public IEEE OUI vendor list.

.PARAMETER TryAdb
    If a device has ADB (port 5555) open and adb.exe is available, connect
    and read device properties. The TV will ask you to allow the connection.

.PARAMETER OutDir
    Where to write results. Default: .\tv-discovery-<timestamp>

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File .\Discover-TV.ps1
.EXAMPLE
    .\Discover-TV.ps1 -Subnet 192.168.0.0/24 -TryAdb
#>
#Requires -Version 5.1
[CmdletBinding()]
param(
    [string]$Subnet,
    [int]$TimeoutMs = 800,
    [switch]$Offline,
    [switch]$TryAdb,
    [string]$OutDir
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

$ScriptVersion = '1.0.0'
$StartTime = Get-Date
if (-not $OutDir) {
    $OutDir = Join-Path (Get-Location) ('tv-discovery-' + $StartTime.ToString('yyyyMMdd-HHmmss'))
}
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
$LogFile = Join-Path $OutDir 'discovery.log'

function Write-Log {
    param([string]$Message, [string]$Level = 'INFO')
    $line = '{0} [{1}] {2}' -f (Get-Date).ToString('HH:mm:ss'), $Level, $Message
    Add-Content -Path $LogFile -Value $line
    switch ($Level) {
        'WARN'  { Write-Host $line -ForegroundColor Yellow }
        'ERROR' { Write-Host $line -ForegroundColor Red }
        'STEP'  { Write-Host ''; Write-Host "== $Message" -ForegroundColor Cyan }
        default { Write-Verbose $line }
    }
}

# ---------------------------------------------------------------------------
# TLS helper: TVs use self-signed certificates on their local HTTPS ports.
# A compiled callback is used (PowerShell scriptblocks can't run on .NET
# worker threads). It is applied per request, only to the LAN probes below.
# ---------------------------------------------------------------------------
if (-not ('TvDiscovery.Tls' -as [type])) {
    Add-Type -TypeDefinition @'
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;
namespace TvDiscovery {
    public static class Tls {
        public static bool AcceptAny(object s, X509Certificate c, X509Chain ch, SslPolicyErrors e) { return true; }
        public static RemoteCertificateValidationCallback Callback { get { return new RemoteCertificateValidationCallback(AcceptAny); } }
    }
}
'@
}
try {
    [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
} catch { }

function Invoke-LanHttp {
    <# Minimal HTTP client with a hard timeout. Returns $null on any failure. #>
    param(
        [Parameter(Mandatory)][string]$Url,
        [string]$Method = 'GET',
        [string]$Body,
        [string]$ContentType = 'application/json',
        [int]$Timeout = $TimeoutMs * 3
    )
    try {
        $req = [Net.HttpWebRequest]::Create($Url)
        $req.Method = $Method
        $req.Timeout = $Timeout
        $req.ReadWriteTimeout = $Timeout
        $req.AllowAutoRedirect = ($Method -eq 'GET')
        $req.UserAgent = "TvDiscovery/$ScriptVersion (read-only)"
        $req.Proxy = $null
        if ($Url.StartsWith('https', [StringComparison]::OrdinalIgnoreCase)) {
            $req.ServerCertificateValidationCallback = [TvDiscovery.Tls]::Callback
        }
        if ($Body) {
            $bytes = [Text.Encoding]::UTF8.GetBytes($Body)
            $req.ContentType = $ContentType
            $req.ContentLength = $bytes.Length
            $s = $req.GetRequestStream(); $s.Write($bytes, 0, $bytes.Length); $s.Close()
        }
        $resp = $req.GetResponse()
        try {
            $reader = New-Object IO.StreamReader($resp.GetResponseStream())
            $text = $reader.ReadToEnd()
            return [pscustomobject]@{
                Status = [int]$resp.StatusCode
                Server = $resp.Headers['Server']
                Body   = $text
            }
        } finally { $resp.Close() }
    } catch [Net.WebException] {
        $r = $_.Exception.Response
        if ($r) {
            $code = [int]$r.StatusCode
            $r.Close()
            return [pscustomobject]@{ Status = $code; Server = $null; Body = $null }
        }
        return $null
    } catch {
        return $null
    }
}

function ConvertFrom-JsonSafe { param([string]$Text) try { if ($Text) { return $Text | ConvertFrom-Json } } catch { } ; return $null }
function ConvertTo-XmlSafe    { param([string]$Text) try { if ($Text) { return [xml]$Text } } catch { } ; return $null }
function Get-Prop {
    <# StrictMode-safe property read on parsed JSON/XML. #>
    param($Obj, [string]$Name)
    if ($null -eq $Obj) { return $null }
    $p = $Obj.PSObject.Properties[$Name]
    if ($p) { return $p.Value }
    return $null
}

# ---------------------------------------------------------------------------
# IP helpers
# ---------------------------------------------------------------------------
function ConvertTo-UInt32Ip { param([string]$Ip)
    $b = ([Net.IPAddress]::Parse($Ip)).GetAddressBytes(); [Array]::Reverse($b); [BitConverter]::ToUInt32($b, 0) }
function ConvertFrom-UInt32Ip { param([uint32]$N)
    $b = [BitConverter]::GetBytes($N); [Array]::Reverse($b); (New-Object Net.IPAddress -ArgumentList (,[byte[]]$b)).ToString() }

function Get-HostRange {
    param([string]$Ip, [int]$Prefix)
    if ($Prefix -lt 22) {
        Write-Log "Subnet /$Prefix is large; scanning the /24 around $Ip instead. Use -Subnet to override." 'WARN'
        $Prefix = 24
    }
    $mask = [uint32]([math]::Pow(2, 32) - [math]::Pow(2, 32 - $Prefix))
    $net = (ConvertTo-UInt32Ip $Ip) -band $mask
    $count = [uint32][math]::Pow(2, 32 - $Prefix)
    $list = New-Object System.Collections.Generic.List[string]
    for ($i = [uint32]1; $i -lt ($count - 1); $i++) { $list.Add((ConvertFrom-UInt32Ip ([uint32]($net + $i)))) }
    return $list.ToArray()
}

# ---------------------------------------------------------------------------
# Step 1: network context
# ---------------------------------------------------------------------------
Write-Log "Network context" 'STEP'
$route = Get-NetRoute -DestinationPrefix '0.0.0.0/0' -PolicyStore ActiveStore -ErrorAction SilentlyContinue |
    Sort-Object { [int](Get-Prop $_ 'RouteMetric') + [int](Get-Prop $_ 'InterfaceMetric') } | Select-Object -First 1
if (-not $route) { Write-Log 'No IPv4 default route found. Are you connected to your home network?' 'ERROR'; exit 1 }

$ifIndex = $route.InterfaceIndex
$adapter = Get-NetAdapter -InterfaceIndex $ifIndex -ErrorAction SilentlyContinue
$ipInfo = Get-NetIPAddress -InterfaceIndex $ifIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue |
    Where-Object { $_.IPAddress -notlike '169.254.*' } | Select-Object -First 1
if (-not $ipInfo) { Write-Log 'Active interface has no usable IPv4 address.' 'ERROR'; exit 1 }

$LocalIp = $ipInfo.IPAddress
$Gateway = $route.NextHop
$adapterDesc = if ($adapter) { $adapter.InterfaceDescription } else { 'unknown' }
Write-Host ("Interface : {0} ({1})" -f $route.InterfaceAlias, $adapterDesc)
Write-Host ("Local IP  : {0}/{1}   Gateway: {2}" -f $LocalIp, $ipInfo.PrefixLength, $Gateway)

$netProfile = Get-NetConnectionProfile -InterfaceIndex $ifIndex -ErrorAction SilentlyContinue
if ($netProfile -and "$($netProfile.NetworkCategory)" -eq 'Public') {
    Write-Log "Windows treats this network as 'Public'. Discovery replies may be blocked by the firewall. If this is your home network, set it to Private (Settings > Network > Properties) and re-run." 'WARN'
}
if ($adapterDesc -match 'VPN|TAP|WireGuard|Tunnel|Hyper-V|VirtualBox|VMware') {
    Write-Log "The default route uses '$adapterDesc'. Disconnect VPN/virtual adapters, or the TV may be invisible." 'WARN'
}

if ($Subnet) {
    if ($Subnet -notmatch '^\d{1,3}(\.\d{1,3}){3}/\d{1,2}$') { Write-Log "Subnet must look like 192.168.1.0/24" 'ERROR'; exit 1 }
    $parts = $Subnet.Split('/')
    $Hosts = @(Get-HostRange -Ip $parts[0] -Prefix ([int]$parts[1]))
} else {
    $Hosts = @(Get-HostRange -Ip $LocalIp -Prefix $ipInfo.PrefixLength)
}
Write-Host ("Scanning  : {0} addresses" -f $Hosts.Count)

# Per-device record store, keyed by IP.
$Devices = @{}
function Get-Device {
    param([string]$Ip)
    if (-not $Devices.ContainsKey($Ip)) {
        $Devices[$Ip] = [ordered]@{
            IP = $Ip; MAC = $null; MacRandomized = $false; OuiVendor = $null; Hostname = $null
            OpenPorts = @(); Ssdp = @(); Upnp = @(); Mdns = @(); Api = [ordered]@{}; Adb = $null
        }
    }
    return $Devices[$Ip]
}

# ---------------------------------------------------------------------------
# Step 2: ping sweep (async, parallel)
# ---------------------------------------------------------------------------
Write-Log "Ping sweep" 'STEP'
$alive = New-Object System.Collections.Generic.HashSet[string]
$batchSize = 128
for ($i = 0; $i -lt $Hosts.Count; $i += $batchSize) {
    $batch = $Hosts[$i..([math]::Min($i + $batchSize, $Hosts.Count) - 1)]
    $jobs = foreach ($h in $batch) {
        $p = New-Object Net.NetworkInformation.Ping
        [pscustomobject]@{ Ip = $h; Ping = $p; Task = $p.SendPingAsync($h, $TimeoutMs) }
    }
    try { [Threading.Tasks.Task]::WaitAll([Threading.Tasks.Task[]]($jobs | ForEach-Object { $_.Task }), $TimeoutMs + 1500) | Out-Null } catch { }
    foreach ($j in $jobs) {
        if ($j.Task.Status -eq 'RanToCompletion' -and $j.Task.Result.Status -eq 'Success') { [void]$alive.Add($j.Ip) }
        $j.Ping.Dispose()
    }
}
Write-Host ("Replied to ping: {0}" -f $alive.Count)

# ---------------------------------------------------------------------------
# Step 3: ARP table + OUI vendor
# ---------------------------------------------------------------------------
Write-Log "ARP table / MAC vendors" 'STEP'
$neighbors = Get-NetNeighbor -AddressFamily IPv4 -InterfaceIndex $ifIndex -ErrorAction SilentlyContinue |
    Where-Object {
        $_.State -ne 'Unreachable' -and $_.LinkLayerAddress -and
        $_.LinkLayerAddress -notmatch '^(00-00-00-00-00-00|FF-FF-FF-FF-FF-FF|01-00-5E)' -and
        $_.IPAddress -notmatch '^(22[4-9]|23\d|255)\.'
    }
foreach ($n in $neighbors) {
    $d = Get-Device $n.IPAddress
    $d.MAC = $n.LinkLayerAddress.ToUpper()
    $firstOctet = [Convert]::ToInt32($d.MAC.Substring(0, 2), 16)
    $d.MacRandomized = [bool]($firstOctet -band 0x02)
}
foreach ($ip in $alive) { [void](Get-Device $ip) }

$OuiMap = @{}
if (-not $Offline) {
    $cache = Join-Path $env:LOCALAPPDATA 'TvDiscovery\oui.csv'
    try {
        if (-not (Test-Path $cache) -or ((Get-Date) - (Get-Item $cache).LastWriteTime).TotalDays -gt 30) {
            New-Item -ItemType Directory -Force -Path (Split-Path $cache) | Out-Null
            Write-Host 'Downloading public IEEE OUI vendor list (one-time, ~5 MB; sends no device data)...'
            $wc = New-Object Net.WebClient
            $wc.Headers['User-Agent'] = 'Mozilla/5.0 TvDiscovery'
            $wc.DownloadFile('https://standards-oui.ieee.org/oui/oui.csv', $cache)
        }
        # Only look up the prefixes we actually saw (fast; the file has ~40k rows).
        $needed = New-Object System.Collections.Generic.HashSet[string]
        foreach ($d in $Devices.Values) { if ($d.MAC -and -not $d.MacRandomized) { [void]$needed.Add($d.MAC.Replace('-', '').Substring(0, 6)) } }
        foreach ($line in [IO.File]::ReadLines($cache)) {
            if ($line.Length -lt 13 -or -not $line.StartsWith('MA-L,')) { continue }
            $key = $line.Substring(5, 6).ToUpper()
            if (-not $needed.Contains($key)) { continue }
            $rest = $line.Substring(12)
            $org = if ($rest.StartsWith('"')) { $rest.Substring(1).Split('"')[0] } else { $rest.Split(',')[0] }
            $OuiMap[$key] = $org.Trim()
        }
    } catch {
        Write-Log "OUI vendor lookup unavailable: $($_.Exception.Message)" 'WARN'
    }
}
foreach ($d in $Devices.Values) {
    if ($d.MAC) {
        if ($d.MacRandomized) { $d.OuiVendor = '(randomized/private MAC)' }
        elseif ($OuiMap.Count) {
            $key = $d.MAC.Replace('-', '').Substring(0, 6)
            if ($OuiMap.ContainsKey($key)) { $d.OuiVendor = $OuiMap[$key] }
        }
    }
}
Write-Host ("Devices in ARP table: {0}" -f @($neighbors).Count)

# Reverse DNS (router-provided hostnames often contain the brand/model)
$dnsJobs = foreach ($ip in @($Devices.Keys)) { [pscustomobject]@{ Ip = $ip; Task = [Net.Dns]::GetHostEntryAsync($ip) } }
try { [Threading.Tasks.Task]::WaitAll([Threading.Tasks.Task[]]($dnsJobs | ForEach-Object { $_.Task }), 4000) | Out-Null } catch { }
foreach ($j in $dnsJobs) {
    if ($j.Task.Status -eq 'RanToCompletion' -and $j.Task.Result.HostName -ne $j.Ip) { $Devices[$j.Ip].Hostname = $j.Task.Result.HostName }
}

# ---------------------------------------------------------------------------
# Step 4: SSDP / UPnP
# ---------------------------------------------------------------------------
Write-Log "SSDP / UPnP discovery" 'STEP'
$ssdpTargets = @(
    'ssdp:all',
    'upnp:rootdevice',
    'urn:dial-multiscreen-org:service:dial:1',
    'roku:ecp',
    'urn:samsung.com:device:RemoteControlReceiver:1',
    'urn:lge-com:service:webos-second-screen:1',
    'urn:schemas-upnp-org:device:MediaRenderer:1',
    'urn:schemas-sony-com:service:ScalarWebAPI:1'
)
function New-MulticastSocket { param([int]$Ttl)
    # Bind to the LAN interface on an ephemeral port and send multicast out of that interface.
    $ipObj = [Net.IPAddress]::Parse($LocalIp)
    $u = [Net.Sockets.UdpClient]::new([Net.IPEndPoint]::new($ipObj, 0))
    $u.Client.SetSocketOption([Net.Sockets.SocketOptionLevel]::IP, [Net.Sockets.SocketOptionName]::MulticastInterface, $ipObj.GetAddressBytes())
    $u.Client.SetSocketOption([Net.Sockets.SocketOptionLevel]::IP, [Net.Sockets.SocketOptionName]::MulticastTimeToLive, $Ttl)
    return $u
}
$ssdpReplies = New-Object System.Collections.Generic.List[object]
$udp = $null
try {
    $udp = New-MulticastSocket -Ttl 2
    $dest = [Net.IPEndPoint]::new([Net.IPAddress]::Parse('239.255.255.250'), 1900)
    foreach ($round in 1..2) {
        foreach ($st in $ssdpTargets) {
            $msg = "M-SEARCH * HTTP/1.1`r`nHOST: 239.255.255.250:1900`r`nMAN: `"ssdp:discover`"`r`nMX: 2`r`nST: $st`r`nUSER-AGENT: Windows/10 UPnP/1.1 TvDiscovery/$ScriptVersion`r`n`r`n"
            $bytes = [Text.Encoding]::ASCII.GetBytes($msg)
            [void]$udp.Send($bytes, $bytes.Length, $dest)
        }
        Start-Sleep -Milliseconds 150
    }
    $deadline = (Get-Date).AddSeconds(3.5)
    while ((Get-Date) -lt $deadline) {
        if ($udp.Client.Poll(200000, [Net.Sockets.SelectMode]::SelectRead)) {
            $remote = [Net.IPEndPoint]::new([Net.IPAddress]::Any, 0)
            try { $data = $udp.Receive([ref]$remote) } catch { continue }
            $text = [Text.Encoding]::UTF8.GetString($data)
            $hdr = @{}
            foreach ($line in ($text -split "`r?`n")) {
                $k = $line.IndexOf(':')
                if ($k -gt 0) { $hdr[$line.Substring(0, $k).Trim().ToUpper()] = $line.Substring($k + 1).Trim() }
            }
            $ssdpReplies.Add([pscustomobject]@{
                IP = $remote.Address.ToString(); ST = $hdr['ST']; USN = $hdr['USN']
                Server = $hdr['SERVER']; Location = $hdr['LOCATION']
            })
        }
    }
} catch {
    Write-Log "SSDP failed: $($_.Exception.Message)" 'WARN'
} finally { if ($udp) { $udp.Close() } }

$seenLoc = @{}
foreach ($r in $ssdpReplies) {
    $d = Get-Device $r.IP
    if (-not ($d.Ssdp | Where-Object { $_.ST -eq $r.ST })) { $d.Ssdp += $r }
    if ($r.Location -and -not $seenLoc.ContainsKey($r.Location)) { $seenLoc[$r.Location] = $r.IP }
}
Write-Host ("SSDP replies: {0} from {1} devices; fetching {2} device descriptions" -f $ssdpReplies.Count, @($ssdpReplies | Select-Object -ExpandProperty IP -Unique).Count, $seenLoc.Count)

foreach ($loc in $seenLoc.Keys) {
    $resp = Invoke-LanHttp -Url $loc
    if (-not $resp -or -not $resp.Body) { continue }
    $x = ConvertTo-XmlSafe $resp.Body
    if (-not $x) { continue }
    $dev = $x.SelectSingleNode("//*[local-name()='device']")
    if (-not $dev) { continue }
    $pick = { param($n) $node = $dev.SelectSingleNode("*[local-name()='$n']"); if ($node) { $node.InnerText.Trim() } else { $null } }
    $entry = [pscustomobject]@{
        Location     = $loc
        DeviceType   = & $pick 'deviceType'
        FriendlyName = & $pick 'friendlyName'
        Manufacturer = & $pick 'manufacturer'
        ModelName    = & $pick 'modelName'
        ModelNumber  = & $pick 'modelNumber'
        ModelDesc    = & $pick 'modelDescription'
        Serial       = & $pick 'serialNumber'
        UDN          = & $pick 'UDN'
        HttpServer   = $resp.Server
    }
    $d = Get-Device $seenLoc[$loc]
    $d.Upnp += $entry
}

# ---------------------------------------------------------------------------
# Step 5: mDNS / DNS-SD
# ---------------------------------------------------------------------------
Write-Log "mDNS / DNS-SD discovery" 'STEP'
$mdnsServices = @(
    '_services._dns-sd._udp.local',
    '_googlecast._tcp.local',          # Google TV, Android TV, Chromecast, many TVs
    '_androidtvremote2._tcp.local',    # Android TV / Google TV remote protocol
    '_androidtvremote._tcp.local',
    '_airplay._tcp.local',             # AirPlay 2 receivers (Samsung, LG, Sony, Vizio, Roku TVs)
    '_raop._tcp.local',
    '_amzn-wplay._tcp.local',          # Amazon Fire TV
    '_amzn-alexa._tcp.local',
    '_spotify-connect._tcp.local',
    '_roku-rcp._tcp.local',
    '_hap._tcp.local',                 # HomeKit
    '_matter._tcp.local',
    '_lgtvremote._tcp.local',
    '_display._tcp.local',
    '_viziocast._tcp.local',
    '_sonos._tcp.local',
    '_adb._tcp.local',
    '_adb-tls-connect._tcp.local'
)

function Write-DnsName { param([System.Collections.Generic.List[byte]]$Buf, [string]$Name)
    foreach ($label in $Name.TrimEnd('.').Split('.')) {
        $lb = [Text.Encoding]::UTF8.GetBytes($label); $Buf.Add([byte]$lb.Length); $Buf.AddRange($lb)
    }
    $Buf.Add(0)
}
function New-MdnsQuery { param([string[]]$Names)
    $buf = New-Object System.Collections.Generic.List[byte]
    $buf.AddRange([byte[]](0,0, 0,0, 0,[byte]$Names.Count, 0,0, 0,0, 0,0))
    foreach ($n in $Names) {
        Write-DnsName $buf $n
        $buf.AddRange([byte[]](0,12, 0x80,1))   # type PTR, class IN, QU (unicast response) bit
    }
    return ,$buf.ToArray()
}
function Read-DnsName { param([byte[]]$B, [ref]$Off)
    $labels = New-Object System.Collections.Generic.List[string]
    $pos = $Off.Value; $jumped = $false; $guard = 0
    while ($pos -lt $B.Length -and $guard++ -lt 128) {
        $len = $B[$pos]
        if ($len -eq 0) { $pos++; break }
        if (($len -band 0xC0) -eq 0xC0) {
            if (-not $jumped) { $Off.Value = $pos + 2 }
            $jumped = $true
            $pos = (($len -band 0x3F) -shl 8) -bor $B[$pos + 1]
            continue
        }
        $pos++
        if ($pos + $len -gt $B.Length) { break }
        $labels.Add([Text.Encoding]::UTF8.GetString($B, $pos, $len)); $pos += $len
    }
    if (-not $jumped) { $Off.Value = $pos }
    return ($labels -join '.')
}
function Read-U16 { param([byte[]]$B, [int]$I) return (([int]$B[$I] -shl 8) -bor $B[$I + 1]) }

function ConvertFrom-MdnsPacket { param([byte[]]$B)
    $records = New-Object System.Collections.Generic.List[object]
    if ($B.Length -lt 12) { return ,$records }
    $qd = Read-U16 $B 4; $an = Read-U16 $B 6; $ns = Read-U16 $B 8; $ar = Read-U16 $B 10
    $off = 12
    for ($q = 0; $q -lt $qd; $q++) { [void](Read-DnsName $B ([ref]$off)); $off += 4 }
    for ($r = 0; $r -lt ($an + $ns + $ar); $r++) {
        if ($off + 10 -gt $B.Length) { break }
        $name = Read-DnsName $B ([ref]$off)
        $type = Read-U16 $B $off; $rdLen = Read-U16 $B ($off + 8); $off += 10
        $rdStart = $off
        if ($rdStart + $rdLen -gt $B.Length) { break }
        $value = $null
        switch ($type) {
            1  { if ($rdLen -eq 4) { $value = '{0}.{1}.{2}.{3}' -f $B[$off], $B[$off+1], $B[$off+2], $B[$off+3] } }
            12 { $o = $off; $value = Read-DnsName $B ([ref]$o) }
            33 { $o = $off + 6; $value = '{0}:{1}' -f (Read-DnsName $B ([ref]$o)), (Read-U16 $B ($off + 4)) }
            16 {
                $txt = @(); $o = $off
                while ($o -lt $rdStart + $rdLen) {
                    $l = $B[$o]; $o++
                    if ($l -gt 0 -and $o + $l -le $B.Length) { $txt += [Text.Encoding]::UTF8.GetString($B, $o, $l) }
                    $o += $l
                }
                $value = $txt
            }
        }
        if ($null -ne $value) { $records.Add([pscustomobject]@{ Name = $name; Type = $type; Value = $value }) }
        $off = $rdStart + $rdLen
    }
    return ,$records
}

$mdnsRecords = New-Object System.Collections.Generic.List[object]
$udp = $null
try {
    $udp = New-MulticastSocket -Ttl 255
    $dest = [Net.IPEndPoint]::new([Net.IPAddress]::Parse('224.0.0.251'), 5353)
    $discoveredTypes = New-Object System.Collections.Generic.HashSet[string]
    foreach ($s in $mdnsServices) { [void]$discoveredTypes.Add($s) }

    $sendQueries = {
        param([string[]]$names)
        foreach ($n in $names) { $pkt = New-MdnsQuery @($n); [void]$udp.Send($pkt, $pkt.Length, $dest) }
    }
    & $sendQueries $mdnsServices
    $deadline = (Get-Date).AddSeconds(3)
    $secondRoundDone = $false
    while ((Get-Date) -lt $deadline) {
        if ($udp.Client.Poll(200000, [Net.Sockets.SelectMode]::SelectRead)) {
            $remote = [Net.IPEndPoint]::new([Net.IPAddress]::Any, 0)
            try { $data = $udp.Receive([ref]$remote) } catch { continue }
            foreach ($rec in (ConvertFrom-MdnsPacket $data)) {
                $rec | Add-Member -NotePropertyName SourceIP -NotePropertyValue $remote.Address.ToString()
                $mdnsRecords.Add($rec)
            }
        }
        # After 1.5 s, also query service types advertised via _services._dns-sd._udp
        if (-not $secondRoundDone -and ((Get-Date) -gt $deadline.AddSeconds(-1.5))) {
            $secondRoundDone = $true
            $extra = @($mdnsRecords | Where-Object { $_.Name -eq '_services._dns-sd._udp.local' -and $_.Type -eq 12 } |
                ForEach-Object { $_.Value } | Where-Object { $discoveredTypes.Add($_) })
            if ($extra.Count) { & $sendQueries $extra; $deadline = $deadline.AddSeconds(1.5) }
        }
    }
} catch {
    Write-Log "mDNS failed: $($_.Exception.Message)" 'WARN'
} finally { if ($udp) { $udp.Close() } }

# Attribute records to device IPs. Responders send from their own IP.
foreach ($grp in ($mdnsRecords | Group-Object SourceIP)) {
    if ($grp.Name -eq $LocalIp) { continue }
    $d = Get-Device $grp.Name
    $instances = @($grp.Group | Where-Object { $_.Type -eq 12 -and $_.Name -like '_*' -and $_.Name -ne '_services._dns-sd._udp.local' })
    foreach ($inst in $instances) {
        $txt = @($grp.Group | Where-Object { $_.Type -eq 16 -and $_.Name -eq $inst.Value } | ForEach-Object { $_.Value })
        $srv = @($grp.Group | Where-Object { $_.Type -eq 33 -and $_.Name -eq $inst.Value } | ForEach-Object { $_.Value }) | Select-Object -First 1
        $kv = [ordered]@{}
        foreach ($t in $txt) { $e = $t.IndexOf('='); if ($e -gt 0) { $kv[$t.Substring(0, $e)] = $t.Substring($e + 1) } }
        $svc = ($inst.Name -replace '\.local$', '')
        if (-not ($d.Mdns | Where-Object { $_.Instance -eq $inst.Value })) {
            $d.Mdns += [pscustomobject]@{ Service = $svc; Instance = $inst.Value; Srv = $srv; Txt = $kv }
        }
    }
}
Write-Host ("mDNS records: {0} from {1} devices" -f $mdnsRecords.Count, @($mdnsRecords | Select-Object -ExpandProperty SourceIP -Unique).Count)

# This PC answers its own SSDP/mDNS queries; drop it from the results.
if ($Devices.ContainsKey($LocalIp)) { $Devices.Remove($LocalIp) }

# ---------------------------------------------------------------------------
# Step 6: TCP port fingerprinting
# ---------------------------------------------------------------------------
Write-Log "TV control-port fingerprinting" 'STEP'
# Plain hashtable on purpose: [ordered] dictionaries treat an [int] index as a position.
$PortMeaning = @{
    1925  = 'Philips JointSpace (HTTP)'
    1926  = 'Philips JointSpace (HTTPS)'
    3000  = 'LG webOS SSAP'
    3001  = 'LG webOS SSAP (TLS)'
    5555  = 'ADB over network (Android / Google / Fire TV)'
    6466  = 'Android TV Remote v2'
    6467  = 'Android TV Remote v2 pairing'
    7000  = 'AirPlay'
    7345  = 'Vizio SmartCast'
    8001  = 'Samsung Tizen remote API'
    8002  = 'Samsung Tizen remote API (TLS)'
    8008  = 'Google Cast setup (HTTP)'
    8009  = 'Google Cast'
    8060  = 'Roku ECP'
    8443  = 'Google Cast setup (HTTPS)'
    9000  = 'Vizio SmartCast (older)'
    36669 = 'Hisense VIDAA MQTT'
    55000 = 'Panasonic Viera'
    52323 = 'Sony UPnP'
    1400  = 'Sonos (speaker, not a TV)'
    80    = 'HTTP'
}
$targets = @($Devices.Keys)
$pairs = @(foreach ($ip in $targets) { foreach ($port in $PortMeaning.Keys) { ,@($ip, [int]$port) } })
$batchSize = 256
for ($i = 0; $i -lt $pairs.Count; $i += $batchSize) {
    $chunk = $pairs[$i..([math]::Min($i + $batchSize, $pairs.Count) - 1)]
    $jobs = foreach ($p in $chunk) {
        $c = New-Object Net.Sockets.TcpClient
        [pscustomobject]@{ Ip = $p[0]; Port = $p[1]; Client = $c; Task = $c.ConnectAsync($p[0], $p[1]) }
    }
    try { [Threading.Tasks.Task]::WaitAll([Threading.Tasks.Task[]]($jobs | ForEach-Object { $_.Task }), $TimeoutMs) | Out-Null } catch { }
    foreach ($j in $jobs) {
        if ($j.Task.Status -eq 'RanToCompletion' -and $j.Client.Connected) { $Devices[$j.Ip].OpenPorts += $j.Port }
        try { $j.Client.Close() } catch { }
    }
}

# ---------------------------------------------------------------------------
# Step 7: vendor information endpoints (read-only, no pairing)
# ---------------------------------------------------------------------------
Write-Log "Vendor info endpoints" 'STEP'
foreach ($d in $Devices.Values) {
    $ip = $d.IP; $ports = $d.OpenPorts
    $upnpText = ((@($d.Upnp | ForEach-Object { "$($_.Manufacturer) $($_.ModelName) $($_.HttpServer)" }) +
                  @($d.Ssdp | ForEach-Object { "$($_.Server)" }) +
                  @($d.Mdns | ForEach-Object { if ($_.Txt.Contains('md')) { $_.Txt['md'] } })) -join ' ')

    if ($ports -contains 8001) {
        $r = Invoke-LanHttp "http://${ip}:8001/api/v2/"
        $j = if ($r) { ConvertFrom-JsonSafe $r.Body } else { $null }
        $dv = Get-Prop $j 'device'
        if ($dv) { $d.Api['Samsung'] = $dv }
    }
    if ($ports -contains 8060) {
        $r = Invoke-LanHttp "http://${ip}:8060/query/device-info"
        $x = if ($r) { ConvertTo-XmlSafe $r.Body } else { $null }
        $root = if ($x) { $x.SelectSingleNode("/*[local-name()='device-info']") } else { $null }
        if ($root) {
            $info = [ordered]@{}
            foreach ($n in $root.ChildNodes) { $info[$n.Name] = $n.InnerText }
            $d.Api['Roku'] = [pscustomobject]$info
        } elseif ($r -and $r.Status -eq 403) {
            $d.Api['Roku'] = 'ECP present but restricted (Settings > System > Advanced > Control by mobile apps)'
        }
    }
    if ($ports -contains 8008 -or $ports -contains 8443) {
        $q = '/setup/eureka_info?params=name,device_info,build_info&options=detail'
        $r = $null
        if ($ports -contains 8443) { $r = Invoke-LanHttp "https://${ip}:8443$q" }
        if ((-not $r -or $r.Status -ne 200) -and $ports -contains 8008) { $r = Invoke-LanHttp "http://${ip}:8008$q" }
        $j = if ($r) { ConvertFrom-JsonSafe $r.Body } else { $null }
        if ($j) { $d.Api['GoogleCast'] = $j }
    }
    foreach ($vp in @(7345, 9000)) {
        if ($ports -contains $vp -and -not $d.Api.Contains('Vizio')) {
            $r = Invoke-LanHttp "https://${ip}:$vp/state/device/deviceinfo"
            $j = if ($r) { ConvertFrom-JsonSafe $r.Body } else { $null }
            if ($j) { $d.Api['Vizio'] = $j }
        }
    }
    if ($ports -contains 1925 -or $ports -contains 1926) {
        $urls = @()
        if ($ports -contains 1926) { $urls += "https://${ip}:1926/6/system" }
        if ($ports -contains 1925) { $urls += "http://${ip}:1925/6/system", "http://${ip}:1925/1/system" }
        foreach ($u in $urls) {
            $r = Invoke-LanHttp $u
            $j = if ($r) { ConvertFrom-JsonSafe $r.Body } else { $null }
            if ($j) { $d.Api['Philips'] = $j; break }
        }
    }
    if ($ports -contains 55000) {
        $r = Invoke-LanHttp "http://${ip}:55000/nrc/ddd.xml"
        $x = if ($r) { ConvertTo-XmlSafe $r.Body } else { $null }
        if ($x) {
            $m = $x.SelectSingleNode("//*[local-name()='modelName']"); $mn = $x.SelectSingleNode("//*[local-name()='modelNumber']")
            $d.Api['Panasonic'] = [pscustomobject]@{ modelName = $(if ($m) { $m.InnerText }); modelNumber = $(if ($mn) { $mn.InnerText }) }
        }
    }
    if ($ports -contains 80 -and ($upnpText -match 'Sony|BRAVIA' -or $ports -contains 52323)) {
        $body = '{"method":"getInterfaceInformation","id":33,"params":[],"version":"1.0"}'
        $r = Invoke-LanHttp "http://${ip}/sony/system" -Method POST -Body $body
        $j = if ($r) { ConvertFrom-JsonSafe $r.Body } else { $null }
        $res = Get-Prop $j 'result'
        if ($res) { $d.Api['Sony'] = @($res)[0] }
    }
}

# ---------------------------------------------------------------------------
# Step 8 (opt-in): ADB read-only properties
# ---------------------------------------------------------------------------
function Invoke-Adb {
    # Windows PowerShell 5.1 turns native stderr into terminating errors when
    # ErrorActionPreference is Stop, so relax it locally for adb calls.
    $ErrorActionPreference = 'Continue'
    $out = & $script:adbExe @args 2>&1 | ForEach-Object { "$_" }
    return (($out -join "`n").Trim())
}
$adbCandidates = @($Devices.Values | Where-Object { $_.OpenPorts -contains 5555 })
if ($adbCandidates.Count) {
    $script:adbExe = (Get-Command adb.exe -ErrorAction SilentlyContinue | Select-Object -First 1 -ExpandProperty Source)
    if (-not $adbExe) {
        foreach ($c in @("$env:LOCALAPPDATA\Android\Sdk\platform-tools\adb.exe", "$PSScriptRoot\platform-tools\adb.exe", "$env:USERPROFILE\platform-tools\adb.exe")) {
            if (Test-Path $c) { $script:adbExe = $c; break }
        }
    }
    if ($TryAdb -and $adbExe) {
        Write-Log "ADB (read-only getprop)" 'STEP'
        Write-Host 'Look at the TV now: accept "Allow USB debugging?" if it appears (tick "Always allow" only if you trust this PC).' -ForegroundColor Yellow
        $props = 'ro.product.manufacturer','ro.product.brand','ro.product.model','ro.product.device','ro.product.name',
                 'ro.build.version.release','ro.build.version.sdk','ro.build.version.security_patch','ro.build.fingerprint',
                 'ro.build.display.id','ro.product.cpu.abi','ro.board.platform','ro.hardware','ro.oem.key1',
                 'ro.boot.verifiedbootstate','ro.boot.flash.locked','ro.build.type','ro.build.tags','ro.debuggable'
        foreach ($d in $adbCandidates) {
            $serial = "$($d.IP):5555"
            [void](Invoke-Adb connect $serial)
            $state = Invoke-Adb -s $serial get-state
            for ($w = 0; $w -lt 6 -and $state -ne 'device'; $w++) {
                Start-Sleep -Seconds 5
                $state = Invoke-Adb -s $serial get-state
            }
            if ($state -eq 'device') {
                $out = [ordered]@{}
                foreach ($p in $props) { $out[$p] = Invoke-Adb -s $serial shell getprop $p }
                $out['MemTotal'] = Invoke-Adb -s $serial shell 'grep MemTotal /proc/meminfo'
                $out['DataPartition'] = Invoke-Adb -s $serial shell 'df -h /data'
                $d.Adb = [pscustomobject]$out
            } else {
                $d.Adb = "ADB port open but not authorized ($state). Accept the prompt on the TV and re-run with -TryAdb."
            }
        }
    } elseif (-not $TryAdb) {
        foreach ($d in $adbCandidates) { $d.Adb = 'ADB port 5555 is open. Re-run with -TryAdb to read build properties (TV will ask for permission).' }
    } else {
        foreach ($d in $adbCandidates) { $d.Adb = 'ADB port open but adb.exe not found. Install Google platform-tools.' }
    }
}

# ---------------------------------------------------------------------------
# Identification: merge evidence into one verdict per device
# ---------------------------------------------------------------------------
function Set-IdField {
    <# Sets a field only if it is still empty. Returns $true when it set it. #>
    param($Id, [string]$Field, $Value)
    if ($null -eq $Value) { return $false }
    $v = "$Value".Trim()
    if (-not $v -or $v -in @('Unknown', 'unknown', 'N/A') -or $Id[$Field]) { return $false }
    $Id[$Field] = $v
    return $true
}

function Resolve-Identity { param($d)
    # Sources are applied in priority order; the first source to supply a
    # field wins. Confidence reflects where the model name came from.
    $id = [ordered]@{ Brand = $null; Model = $null; ModelCode = $null; Name = $null; Platform = $null; OS = $null
                      Firmware = $null; DeveloperMode = $null; Confidence = 'none'; Source = $null; IsTv = $false; TvScore = 0 }
    $score = 0; $modelFrom = $null; $modelConf = $null
    $api = $d.Api

    # 1. ADB build properties (authoritative for Android-based TVs)
    if ($d.Adb -and $d.Adb -isnot [string]) {
        $a = $d.Adb
        $mfr = Get-Prop $a 'ro.product.manufacturer'
        [void](Set-IdField $id 'Brand' $mfr)
        if (Set-IdField $id 'Model' (Get-Prop $a 'ro.product.model')) { $modelFrom = 'ADB getprop'; $modelConf = 'exact' }
        [void](Set-IdField $id 'ModelCode' (Get-Prop $a 'ro.product.device'))
        [void](Set-IdField $id 'OS' ('Android {0} (SDK {1}, patch {2})' -f (Get-Prop $a 'ro.build.version.release'), (Get-Prop $a 'ro.build.version.sdk'), (Get-Prop $a 'ro.build.version.security_patch')))
        [void](Set-IdField $id 'Firmware' (Get-Prop $a 'ro.build.fingerprint'))
        [void](Set-IdField $id 'Platform' $(if ($mfr -match 'Amazon') { 'Fire OS' } else { 'Android TV / Google TV' }))
        $score += 5
    }

    # 2. Vendor info endpoints
    if ($api.Contains('Samsung')) {
        $s = $api['Samsung']
        [void](Set-IdField $id 'Brand' 'Samsung')
        if (Set-IdField $id 'Model' (Get-Prop $s 'modelName')) { $modelFrom = 'Samsung :8001/api/v2'; $modelConf = 'exact' }
        [void](Set-IdField $id 'ModelCode' (Get-Prop $s 'model'))
        [void](Set-IdField $id 'Name' (Get-Prop $s 'name'))
        [void](Set-IdField $id 'Platform' 'Tizen')
        [void](Set-IdField $id 'OS' (Get-Prop $s 'OS'))
        [void](Set-IdField $id 'Firmware' (Get-Prop $s 'firmwareVersion'))
        $dm = Get-Prop $s 'developerMode'
        if ($null -ne $dm) { $id.DeveloperMode = $(if ("$dm" -eq '1') { 'on' } else { 'off' }) }
        $score += 10
    }
    if ($api.Contains('Roku') -and $api['Roku'] -isnot [string]) {
        $r = $api['Roku']
        [void](Set-IdField $id 'Brand' (Get-Prop $r 'vendor-name'))
        [void](Set-IdField $id 'Brand' 'Roku')
        if (Set-IdField $id 'Model' (Get-Prop $r 'model-name')) { $modelFrom = 'Roku ECP :8060'; $modelConf = 'exact' }
        [void](Set-IdField $id 'ModelCode' (Get-Prop $r 'model-number'))
        [void](Set-IdField $id 'Name' (Get-Prop $r 'friendly-device-name'))
        [void](Set-IdField $id 'Platform' 'Roku OS')
        [void](Set-IdField $id 'Firmware' ('{0} build {1}' -f (Get-Prop $r 'software-version'), (Get-Prop $r 'software-build')))
        $dev = Get-Prop $r 'developer-enabled'
        if ($null -ne $dev) { $id.DeveloperMode = $(if ($dev -eq 'true') { 'on' } else { 'off' }) }
        $score += $(if ((Get-Prop $r 'is-tv') -eq 'true') { 10 } else { 5 })
    } elseif ($api.Contains('Roku')) {
        [void](Set-IdField $id 'Platform' 'Roku OS'); $score += 6
    }
    if ($api.Contains('Sony')) {
        $so = $api['Sony']
        [void](Set-IdField $id 'Brand' 'Sony')
        if (Set-IdField $id 'Model' (Get-Prop $so 'modelName')) { $modelFrom = 'Sony ScalarWebAPI'; $modelConf = 'exact' }
        [void](Set-IdField $id 'Platform' ('{0} (Sony API {1})' -f (Get-Prop $so 'productName'), (Get-Prop $so 'interfaceVersion')))
        if ((Get-Prop $so 'productCategory') -eq 'tv') { $score += 10 }
    }
    if ($api.Contains('Vizio')) {
        $item = @(Get-Prop $api['Vizio'] 'ITEMS') | Select-Object -First 1
        $val = Get-Prop $item 'VALUE'
        [void](Set-IdField $id 'Brand' 'Vizio')
        if (Set-IdField $id 'Model' (Get-Prop $val 'MODEL_NAME')) { $modelFrom = 'Vizio deviceinfo'; $modelConf = 'exact' }
        [void](Set-IdField $id 'Name' (Get-Prop $val 'CAST_NAME'))
        [void](Set-IdField $id 'Platform' 'Vizio SmartCast')
        $score += 10
    }
    if ($api.Contains('Philips')) {
        $p = $api['Philips']
        [void](Set-IdField $id 'Brand' 'Philips')
        if (Set-IdField $id 'Model' (Get-Prop $p 'model')) { $modelFrom = 'Philips JointSpace'; $modelConf = 'exact' }
        [void](Set-IdField $id 'Name' (Get-Prop $p 'name'))
        [void](Set-IdField $id 'Firmware' (Get-Prop $p 'softwareversion'))
        [void](Set-IdField $id 'Platform' ('Philips JointSpace {0} {1}' -f (Get-Prop $p 'nettvversion'), (Get-Prop $p 'os_type')))
        $score += 10
    }
    if ($api.Contains('Panasonic')) {
        $pa = $api['Panasonic']
        [void](Set-IdField $id 'Brand' 'Panasonic')
        if (Set-IdField $id 'Model' ((@($pa.modelName, $pa.modelNumber) | Where-Object { $_ }) -join ' ')) { $modelFrom = 'Panasonic ddd.xml'; $modelConf = 'exact' }
        $score += 10
    }
    if ($api.Contains('GoogleCast')) {
        $g = $api['GoogleCast']; $di = Get-Prop $g 'device_info'; $bi = Get-Prop $g 'build_info'
        [void](Set-IdField $id 'Brand' (Get-Prop $di 'manufacturer'))
        if (Set-IdField $id 'Model' (Get-Prop $di 'model_name')) { $modelFrom = 'Google Cast eureka_info'; $modelConf = 'high' }
        [void](Set-IdField $id 'Name' (Get-Prop $g 'name'))
        if ($bi) { [void](Set-IdField $id 'Firmware' ('{0} (cast {1})' -f (Get-Prop $bi 'system_build_number'), (Get-Prop $bi 'cast_build_revision'))) }
        $score += 3
    }

    # 3. UPnP device description (manufacturer-reported; may be a family name)
    $u = @($d.Upnp | Where-Object { $_.Manufacturer -or $_.ModelName } |
        Sort-Object { if ($_.DeviceType -match 'MediaRenderer|tvdevice|RemoteControlReceiver|dial') { 0 } else { 1 } }) | Select-Object -First 1
    if ($u) {
        [void](Set-IdField $id 'Brand' $u.Manufacturer)
        $m = (@($u.ModelName, $u.ModelNumber) | Where-Object { $_ -and $_ -notmatch '^[\d\.]+$|AllShare' } | Select-Object -Unique) -join ' / '
        if (Set-IdField $id 'Model' $m) { $modelFrom = 'UPnP device description'; $modelConf = 'medium' }
        [void](Set-IdField $id 'Name' $u.FriendlyName)
    }

    # 4. mDNS TXT records
    $cast = @($d.Mdns | Where-Object { $_.Service -eq '_googlecast._tcp' }) | Select-Object -First 1
    $air = @($d.Mdns | Where-Object { $_.Service -in @('_airplay._tcp', '_raop._tcp') }) | Select-Object -First 1
    if ($cast) {
        if (Set-IdField $id 'Model' $(if ($cast.Txt.Contains('md')) { $cast.Txt['md'] })) { $modelFrom = 'mDNS Google Cast TXT'; $modelConf = 'medium' }
        [void](Set-IdField $id 'Name' $(if ($cast.Txt.Contains('fn')) { $cast.Txt['fn'] }))
        $score += 3
    }
    if ($air) {
        $am = if ($air.Txt.Contains('model')) { $air.Txt['model'] } elseif ($air.Txt.Contains('am')) { $air.Txt['am'] } else { $null }
        if (Set-IdField $id 'Model' $am) { $modelFrom = 'mDNS AirPlay TXT'; $modelConf = 'medium' }
        [void](Set-IdField $id 'Brand' $(if ($air.Txt.Contains('manufacturer')) { $air.Txt['manufacturer'] }))
    }

    # 5. Platform inference from protocols and ports
    $svcs = @($d.Mdns | ForEach-Object { $_.Service })
    $ports = @($d.OpenPorts)
    $allText = ((@($d.Upnp | ForEach-Object { "$($_.Manufacturer) $($_.ModelName) $($_.ModelDesc) $($_.DeviceType) $($_.HttpServer)" }) +
                 @($d.Ssdp | ForEach-Object { "$($_.Server) $($_.ST)" })) -join ' ')
    if ($ports -contains 3000 -or $ports -contains 3001 -or $allText -match 'webOS|lge-com') {
        [void](Set-IdField $id 'Platform' 'LG webOS'); [void](Set-IdField $id 'Brand' 'LG'); $score += 8
    } elseif ($svcs -contains '_androidtvremote2._tcp' -or $ports -contains 6466) {
        [void](Set-IdField $id 'Platform' 'Android TV / Google TV'); $score += 8
    } elseif ($svcs -contains '_amzn-wplay._tcp') {
        [void](Set-IdField $id 'Platform' 'Fire TV (Fire OS or Vega OS)'); $score += 6
    } elseif ($ports -contains 36669 -or $allText -match 'VIDAA|Hisense') {
        [void](Set-IdField $id 'Platform' 'Hisense VIDAA (likely)'); $score += 6
    } elseif ($ports -contains 8001 -or $ports -contains 8002 -or $allText -match 'Samsung') {
        [void](Set-IdField $id 'Platform' 'Samsung Tizen (likely)'); $score += 6
    } elseif ($ports -contains 8060 -or $allText -match 'Roku') {
        [void](Set-IdField $id 'Platform' 'Roku OS (likely)'); $score += 6
    } elseif ($cast) {
        [void](Set-IdField $id 'Platform' 'Google Cast device')
    }
    if ($ports -contains 5555 -and $id.Platform) { $id.Platform = "$($id.Platform) [ADB port open]" }
    if ($allText -match 'MediaRenderer|tvdevice|RemoteControlReceiver|\bTV\b') { $score += 2 }
    if ($ports -contains 1400 -or $svcs -contains '_sonos._tcp') { $score -= 10 }

    # 6. MAC vendor as a last resort for the brand
    if ($d.OuiVendor -and $d.OuiVendor -notmatch 'randomized') { [void](Set-IdField $id 'Brand' $d.OuiVendor) }

    if ($id.Model) { $id.Confidence = $modelConf; $id.Source = $modelFrom }
    elseif ($id.Brand -or $id.Platform) { $id.Confidence = 'low'; $id.Source = 'brand/platform only (no model reported)' }
    $id.TvScore = $score
    $id.IsTv = $score -ge 6
    return [pscustomobject]$id
}

$results = @(foreach ($d in ($Devices.Values | Sort-Object { ConvertTo-UInt32Ip $_.IP })) {
    $ident = Resolve-Identity $d
    [pscustomobject]@{ Identity = $ident; Device = [pscustomobject]$d }
})

# ---------------------------------------------------------------------------
# Output
# ---------------------------------------------------------------------------
$jsonPath = Join-Path $OutDir 'discovery-full.json'
[pscustomobject]@{
    ScriptVersion = $ScriptVersion; Started = $StartTime.ToString('o'); LocalIp = $LocalIp; Gateway = $Gateway
    Interface = $route.InterfaceAlias; Results = $results
} | ConvertTo-Json -Depth 8 | Set-Content -Path $jsonPath -Encoding UTF8

function Format-MacShort { param([string]$Mac) if ($Mac) { $Mac.Substring(0, 8) + '-xx-xx-xx' } else { '' } }

$tvs = @($results | Where-Object { $_.Identity.IsTv } | Sort-Object { $_.Identity.TvScore } -Descending)
$summary = New-Object System.Collections.Generic.List[string]
$summary.Add("TV discovery summary  (script $ScriptVersion, $($StartTime.ToString('yyyy-MM-dd HH:mm')))")
$summary.Add("Network: $LocalIp via $($route.InterfaceAlias); devices seen: $($results.Count)")
$summary.Add('Serial numbers and full MAC addresses are left out of this file so it is safe to share.')
$summary.Add('')
if ($tvs.Count) {
    $summary.Add("LIKELY TVs / STREAMING DEVICES: $($tvs.Count)")
    foreach ($t in $tvs) {
        $i = $t.Identity; $d = $t.Device
        $summary.Add('------------------------------------------------------------')
        $summary.Add("IP            : $($d.IP)   MAC vendor: $($d.OuiVendor)  ($(Format-MacShort $d.MAC))")
        $summary.Add("Brand         : $($i.Brand)")
        $summary.Add("Model         : $($i.Model)")
        if ($i.ModelCode) { $summary.Add("Model code    : $($i.ModelCode)") }
        if ($i.Name) { $summary.Add("Name on TV    : $($i.Name)") }
        $summary.Add("Platform / OS : $($i.Platform) $($i.OS)")
        if ($i.Firmware) { $summary.Add("Firmware      : $($i.Firmware)") }
        if ($null -ne $i.DeveloperMode) { $summary.Add("Developer mode: $($i.DeveloperMode)") }
        $summary.Add("Confidence    : $($i.Confidence)  (source: $($i.Source))")
        $summary.Add("Open TV ports : " + ((@($d.OpenPorts | Sort-Object) | ForEach-Object { "$_ ($($PortMeaning[[int]$_]))" }) -join ', '))
        $summary.Add("mDNS services : " + ((@($d.Mdns | ForEach-Object { $_.Service } | Select-Object -Unique)) -join ', '))
        if ($d.Adb -is [string]) { $summary.Add("ADB           : $($d.Adb)") }
        elseif ($d.Adb) { $summary.Add("ADB           : connected; build props in discovery-full.json") }
    }
} else {
    $summary.Add('No TV was identified automatically. See "If nothing was found" in discovery\README.md.')
}
$summary.Add('')
$summary.Add('ALL DEVICES')
foreach ($rr in $results) {
    $i = $rr.Identity; $d = $rr.Device
    $label = (@($i.Brand, $i.Model, $i.Platform) | Where-Object { $_ }) -join ' | '
    if (-not $label) { $label = $d.Hostname }
    $summary.Add(('{0,-16} {1,-28} ports:{2,-24} {3}' -f $d.IP, ($d.OuiVendor -replace '^(.{0,28}).*$', '$1'), ((@($d.OpenPorts | Sort-Object)) -join ','), $label))
}
$summaryPath = Join-Path $OutDir 'summary.txt'
$summary | Set-Content -Path $summaryPath -Encoding UTF8

Write-Host ''
$summary | ForEach-Object { Write-Host $_ }
Write-Host ''
Write-Host "Saved: $summaryPath" -ForegroundColor Green
Write-Host "Saved: $jsonPath  (full detail; contains serials/MACs, keep private)" -ForegroundColor Green
Write-Host ("Done in {0:N0} s." -f ((Get-Date) - $StartTime).TotalSeconds)
