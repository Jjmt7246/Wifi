<#
.SYNOPSIS
    Vizio SmartCast local control: find, pair, back up settings, apply
    privacy / speed / streaming-box presets, and undo every change.

.DESCRIPTION
    Talks to the TV's built-in local API (HTTPS on port 7345, or 9000 on older
    firmware), the same one the Vizio mobile app uses. It cannot replace the
    TV's operating system. It can change settings the TV already has, faster
    than menus, with a backup and an undo log.

    Safety rules built in:
      - Find, Info and Backup only read.
      - Every change is confirmed first (unless -Yes), verified by reading it
        back, and recorded in an undo log. 'Undo' restores the old values.
      - Action-type items (resets, factory reset, channel scan) are never
        touched; only on/off and list settings can be changed.
      - The pairing token is stored encrypted for your Windows user (DPAPI).

.EXAMPLE
    .\Vizio-Tool.ps1                     # interactive menu
.EXAMPLE
    .\Vizio-Tool.ps1 Pair -Ip 192.168.1.40
    .\Vizio-Tool.ps1 Optimize -Preset Privacy,BoxMode          # show what would change
    .\Vizio-Tool.ps1 Optimize -Preset Privacy,BoxMode -Apply   # change it, with prompts
    .\Vizio-Tool.ps1 Undo
#>
#Requires -Version 5.1
[CmdletBinding()]
param(
    [Parameter(Position = 0)]
    [ValidateSet('Menu', 'Find', 'Pair', 'Info', 'Backup', 'Optimize', 'Set', 'Undo', 'Key', 'Input', 'Forget')]
    [string]$Action = 'Menu',
    [string]$Ip,
    [int]$Port,
    [ValidateSet('Privacy', 'FastStart', 'BoxMode')]
    [string[]]$Preset = @('Privacy'),
    [switch]$Apply,
    [switch]$Yes,
    [string]$Name,
    [string]$Value,
    [string]$KeyName
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
$StateDir = Join-Path $env:LOCALAPPDATA 'TvDiscovery\vizio'
New-Item -ItemType Directory -Force -Path $StateDir | Out-Null

# --------------------------------------------------------------------------
# HTTP + JSON helpers
# --------------------------------------------------------------------------
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
try { [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12 } catch { }

function Get-Prop {
    # Case-insensitive, StrictMode-safe property read (Vizio mixes key casing).
    param($Obj, [string]$Name)
    if ($null -eq $Obj -or $Obj -is [string]) { return $null }
    $p = $Obj.PSObject.Properties[$Name]
    if ($p) { return $p.Value }
    return $null
}

function Invoke-Vizio {
    param($Conn, [string]$Path, [string]$Method = 'GET', $Body, [int]$Timeout = 8000)
    $url = "https://$($Conn.Ip):$($Conn.Port)$Path"
    $req = [Net.HttpWebRequest]::Create($url)
    $req.Method = $Method
    $req.Timeout = $Timeout
    $req.ReadWriteTimeout = $Timeout
    $req.Proxy = $null
    $req.Accept = 'application/json'
    $req.ServerCertificateValidationCallback = [TvDiscovery.Tls]::Callback
    if ($Conn.AuthToken) { $req.Headers.Add('AUTH', $Conn.AuthToken) }
    if ($Method -ne 'GET') {
        $json = if ($null -ne $Body) { $Body | ConvertTo-Json -Depth 6 -Compress } else { '{}' }
        Write-Verbose "$Method $Path $json"
        $bytes = [Text.Encoding]::UTF8.GetBytes($json)
        $req.ContentType = 'application/json'
        $req.ContentLength = $bytes.Length
        $s = $req.GetRequestStream(); $s.Write($bytes, 0, $bytes.Length); $s.Close()
    }
    $resp = $null
    try { $resp = $req.GetResponse() }
    catch [Net.WebException] { $resp = $_.Exception.Response; if (-not $resp) { return $null } }
    try {
        $text = (New-Object IO.StreamReader($resp.GetResponseStream())).ReadToEnd()
    } finally { $resp.Close() }
    try { return ($text | ConvertFrom-Json) } catch { return $null }
}

function Read-JsonArray {
    # Windows PowerShell 5.1 returns a JSON array as one nested object; flatten it.
    param([string]$File)
    $raw = Get-Content $File -Raw | ConvertFrom-Json
    return @($raw | ForEach-Object { $_ })
}

function Get-ResultCode { param($R) return "$(Get-Prop (Get-Prop $R 'STATUS') 'RESULT')".ToUpper() }
function Test-Success { param($R) return ((Get-ResultCode $R) -eq 'SUCCESS') }

function Test-TcpPort {
    param([string]$TargetIp, [int]$TargetPort, [int]$Ms = 1200)
    $c = New-Object Net.Sockets.TcpClient
    try { $t = $c.ConnectAsync($TargetIp, $TargetPort); return ($t.Wait($Ms) -and $c.Connected) }
    catch { return $false } finally { $c.Close() }
}

function Confirm-Step {
    param([string]$Question)
    if ($Yes) { return $true }
    $a = Read-Host "$Question [y/N]"
    return ($a -match '^(y|yes)$')
}

# --------------------------------------------------------------------------
# Saved connection (IP, port, encrypted auth token)
# --------------------------------------------------------------------------
function Get-StateFile { param([string]$TvIp) Join-Path $StateDir ("tv-" + $TvIp.Replace('.', '_') + '.json') }
function Get-ChangeLogFile { param([string]$TvIp) Join-Path $StateDir ("changes-" + $TvIp.Replace('.', '_') + '.json') }

function Protect-Text { param([string]$Text) ConvertTo-SecureString $Text -AsPlainText -Force | ConvertFrom-SecureString }
function Unprotect-Text {
    param([string]$Enc)
    $ss = ConvertTo-SecureString $Enc
    $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($ss)
    try { return [Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr) } finally { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr) }
}

function Save-Conn {
    param($Conn)
    $o = [ordered]@{ Ip = $Conn.Ip; Port = $Conn.Port; DeviceId = $Conn.DeviceId; Model = $Conn.Model; SettingsRoot = $Conn.SettingsRoot
                     AuthTokenEnc = $(if ($Conn.AuthToken) { Protect-Text $Conn.AuthToken } else { $null }); Saved = (Get-Date).ToString('o') }
    $o | ConvertTo-Json | Set-Content -Path (Get-StateFile $Conn.Ip) -Encoding UTF8
}

function Get-DeviceInfo {
    param($Conn)
    $r = Invoke-Vizio -Conn $Conn -Path '/state/device/deviceinfo'
    $item = @(Get-Prop $r 'ITEMS') | Select-Object -First 1
    return (Get-Prop $item 'VALUE')
}

function Resolve-Conn {
    # Builds a connection from -Ip/-Port, or from the one saved TV.
    param([switch]$NeedAuth)
    $tvIp = $Ip
    if (-not $tvIp) {
        $saved = @(Get-ChildItem -Path $StateDir -Filter 'tv-*.json' -ErrorAction SilentlyContinue)
        if ($saved.Count -eq 1) { $tvIp = (Get-Content $saved[0].FullName -Raw | ConvertFrom-Json).Ip }
        elseif ($saved.Count -gt 1) { throw "Several TVs are saved. Pass -Ip. Saved: $(($saved | ForEach-Object { $_.BaseName }) -join ', ')" }
        else { throw 'No TV saved yet. Run Find, then Pair -Ip <address>.' }
    }
    $conn = [pscustomobject]@{ Ip = $tvIp; Port = $Port; DeviceId = $null; AuthToken = $null; Model = $null; SettingsRoot = 'tv_settings' }
    $sf = Get-StateFile $tvIp
    if (Test-Path $sf) {
        $s = Get-Content $sf -Raw | ConvertFrom-Json
        if (-not $conn.Port) { $conn.Port = [int]$s.Port }
        $conn.DeviceId = $s.DeviceId; $conn.Model = $s.Model
        if ($s.SettingsRoot) { $conn.SettingsRoot = $s.SettingsRoot }
        if ($s.AuthTokenEnc) { try { $conn.AuthToken = Unprotect-Text $s.AuthTokenEnc } catch { Write-Warning 'Saved token could not be decrypted (different Windows user?). Pair again.' } }
    }
    if (-not $conn.Port) {
        foreach ($p in 7345, 9000) { if (Test-TcpPort $tvIp $p) { $conn.Port = $p; break } }
        if (-not $conn.Port) { throw "No SmartCast API at $tvIp (ports 7345/9000 closed). Is the TV on, and is it a SmartCast model (2016 or newer)?" }
    }
    if ($NeedAuth -and -not $conn.AuthToken) { throw "Not paired with $tvIp yet. Run: Pair -Ip $tvIp" }
    return $conn
}

# --------------------------------------------------------------------------
# Find
# --------------------------------------------------------------------------
function Find-Vizio {
    $targets = @()
    if ($Ip) { $targets = @($Ip) }
    else {
        $route = Get-NetRoute -DestinationPrefix '0.0.0.0/0' -PolicyStore ActiveStore -ErrorAction SilentlyContinue |
            Sort-Object { [int](Get-Prop $_ 'RouteMetric') + [int](Get-Prop $_ 'InterfaceMetric') } | Select-Object -First 1
        if (-not $route) { throw 'No network connection found.' }
        $ipInfo = Get-NetIPAddress -InterfaceIndex $route.InterfaceIndex -AddressFamily IPv4 | Where-Object { $_.IPAddress -notlike '169.254.*' } | Select-Object -First 1
        $octets = $ipInfo.IPAddress.Split('.')
        $base = '{0}.{1}.{2}.' -f $octets[0], $octets[1], $octets[2]
        Write-Host "Scanning $($base)1-254 for SmartCast ports 7345/9000..."
        $jobs = foreach ($n in 1..254) {
            foreach ($p in 7345, 9000) {
                $c = New-Object Net.Sockets.TcpClient
                [pscustomobject]@{ Ip = "$base$n"; Port = $p; Client = $c; Task = $c.ConnectAsync("$base$n", $p) }
            }
        }
        try { [Threading.Tasks.Task]::WaitAll([Threading.Tasks.Task[]]($jobs | ForEach-Object { $_.Task }), 2500) | Out-Null } catch { }
        foreach ($j in $jobs) {
            if ($j.Task.Status -eq 'RanToCompletion' -and $j.Client.Connected) { $targets += $j.Ip }
            try { $j.Client.Close() } catch { }
        }
        $targets = @($targets | Select-Object -Unique)
    }
    $found = 0; $lastFound = $null
    foreach ($t in $targets) {
        $script:Ip = $t
        try { $conn = Resolve-Conn } catch { continue }
        $info = Get-DeviceInfo $conn
        if (-not $info) { continue }
        $found++; $lastFound = $t
        Write-Host ''
        Write-Host ("Vizio found at {0}:{1}" -f $t, $conn.Port) -ForegroundColor Green
        Write-Host ("  Model    : {0}" -f (Get-Prop $info 'MODEL_NAME'))
        Write-Host ("  Name     : {0}" -f (Get-Prop $info 'CAST_NAME'))
        Write-Host ("  Paired   : {0}" -f $(if ($conn.AuthToken) { 'yes' } else { 'no' }))
        if (-not $conn.AuthToken) { Write-Host "  Next     : .\Vizio-Tool.ps1 Pair -Ip $t" }
    }
    # Remember the TV for the next menu step only when there is exactly one.
    $script:Ip = $(if ($found -eq 1) { $lastFound } else { $null })
    if (-not $found) {
        Write-Host 'No SmartCast TV found.' -ForegroundColor Yellow
        Write-Host '  - Turn the TV on and make sure the PC is on the same network.'
        Write-Host '  - Vizio TVs from before 2016 (VIA / Internet Apps) have no local API. For those, see README: streaming box.'
    }
}

# --------------------------------------------------------------------------
# Pair
# --------------------------------------------------------------------------
function Invoke-Pair {
    if (-not $Ip) { throw 'Pair needs -Ip (run Find first).' }
    $conn = Resolve-Conn
    if (-not $conn.DeviceId) { $conn.DeviceId = 'pc-tvtool-' + ([guid]::NewGuid().ToString('N').Substring(0, 8)) }
    $info = Get-DeviceInfo $conn
    if ($info) {
        $conn.Model = Get-Prop $info 'MODEL_NAME'
        $root = Get-Prop $info 'SETTINGS_ROOT'
        if ($root) { $conn.SettingsRoot = $root }
    }
    $start = Invoke-Vizio -Conn $conn -Path '/pairing/start' -Method PUT -Body ([ordered]@{ DEVICE_ID = $conn.DeviceId; DEVICE_NAME = 'Windows TV Tool' })
    if (-not (Test-Success $start)) { throw "TV refused to start pairing: $(Get-ResultCode $start). If a PIN is already showing, wait for it to close and retry." }
    $item = Get-Prop $start 'ITEM'
    $reqToken = Get-Prop $item 'PAIRING_REQ_TOKEN'
    $challenge = Get-Prop $item 'CHALLENGE_TYPE'
    $pin = Read-Host 'Enter the 4-digit PIN shown on the TV'
    if (-not $pin) {
        [void](Invoke-Vizio -Conn $conn -Path '/pairing/cancel' -Method PUT -Body ([ordered]@{ DEVICE_ID = $conn.DeviceId; DEVICE_NAME = 'Windows TV Tool' }))
        Write-Host 'Pairing cancelled.'; return
    }
    $fin = Invoke-Vizio -Conn $conn -Path '/pairing/pair' -Method PUT -Body ([ordered]@{
        DEVICE_ID = $conn.DeviceId; CHALLENGE_TYPE = $(if ($challenge) { [int]$challenge } else { 1 }); RESPONSE_VALUE = "$pin".Trim(); PAIRING_REQ_TOKEN = [long]$reqToken })
    $token = Get-Prop (Get-Prop $fin 'ITEM') 'AUTH_TOKEN'
    if (-not (Test-Success $fin) -or -not $token) { throw "Pairing failed: $(Get-ResultCode $fin). Check the PIN and try again." }
    $conn.AuthToken = $token
    Save-Conn $conn
    Write-Host "Paired with $($conn.Model) at $($conn.Ip). The token is saved encrypted for your Windows user." -ForegroundColor Green
    Write-Host 'To revoke later: TV Settings > Mobile Devices (or Admin & Privacy) > remove "Windows TV Tool".'
}

# --------------------------------------------------------------------------
# Settings tree (read-only crawl)
# --------------------------------------------------------------------------
function Get-SettingsList {
    param($Conn)
    $root = $Conn.SettingsRoot
    $list = New-Object System.Collections.Generic.List[object]
    $queue = New-Object System.Collections.Generic.Queue[object]
    $queue.Enqueue([pscustomobject]@{ Path = ''; Depth = 0; Trail = '' })
    $requests = 0
    while ($queue.Count -gt 0 -and $requests -lt 600) {
        $node = $queue.Dequeue()
        $dyn = Invoke-Vizio -Conn $Conn -Path "/menu_native/dynamic/$root$($node.Path)"; $requests++
        if (-not (Test-Success $dyn)) {
            if ($node.Path -eq '' -and (Get-ResultCode $dyn) -match 'BLOCKED|AUTH|DENIED|INVALID') { throw "TV rejected the saved pairing ($(Get-ResultCode $dyn)). Pair again." }
            continue
        }
        $static = Invoke-Vizio -Conn $Conn -Path "/menu_native/static/$root$($node.Path)"; $requests++
        $choices = @{}
        foreach ($si in @(Get-Prop $static 'ITEMS')) {
            $c = Get-Prop $si 'CNAME'; $e = Get-Prop $si 'ELEMENTS'
            if ($c -and $e) { $choices[$c] = @(@($e) | Where-Object { $_ -is [string] }) }
        }
        foreach ($it in @(Get-Prop $dyn 'ITEMS')) {
            $cname = Get-Prop $it 'CNAME'
            if (-not $cname) { continue }
            $type = "$(Get-Prop $it 'TYPE')".ToLower()
            $nm = "$(Get-Prop $it 'NAME')"
            $trail = if ($node.Trail) { "$($node.Trail) > $nm" } else { $nm }
            if ($type -like 't_menu*') {
                # Channel lists can be huge and cast settings are not menus we change.
                if ($node.Depth -lt 6 -and $cname -notin @('channels', 'cast')) {
                    $queue.Enqueue([pscustomobject]@{ Path = "$($node.Path)/$cname"; Depth = $node.Depth + 1; Trail = $trail })
                }
                continue
            }
            $list.Add([pscustomobject]@{
                Menu = $node.Path; CName = $cname; Name = $nm; Trail = $trail; Type = $type
                Value = (Get-Prop $it 'VALUE'); HashVal = (Get-Prop $it 'HASHVAL'); Enabled = (Get-Prop $it 'ENABLED')
                Choices = @(if ($choices.ContainsKey($cname)) { $choices[$cname] })
            })
        }
    }
    return ,$list
}

function Save-Backup {
    param($Conn, $List)
    $file = Join-Path $StateDir ('backup-{0}-{1}.json' -f $Conn.Ip.Replace('.', '_'), (Get-Date).ToString('yyyyMMdd-HHmmss'))
    [pscustomobject]@{ Ip = $Conn.Ip; Model = $Conn.Model; Taken = (Get-Date).ToString('o'); Settings = $List } |
        ConvertTo-Json -Depth 6 | Set-Content -Path $file -Encoding UTF8
    return $file
}

function Test-Changeable {
    param($S)
    # Only plain list/value settings. Never action items (resets, scans, etc.).
    return ($S.Type -match '^t_(list|value)' -and $S.Type -notmatch 'action' -and "$($S.Enabled)" -ne 'FALSE' -and $null -ne $S.HashVal)
}

function Set-VizioSetting {
    param($Conn, $S, $NewValue, [string]$Reason = 'manual')
    $root = $Conn.SettingsRoot
    # Re-read the menu for a fresh HASHVAL (the TV rejects stale ones).
    $dyn = Invoke-Vizio -Conn $Conn -Path "/menu_native/dynamic/$root$($S.Menu)"
    $cur = @(Get-Prop $dyn 'ITEMS') | Where-Object { (Get-Prop $_ 'CNAME') -eq $S.CName } | Select-Object -First 1
    if (-not $cur) { Write-Warning "Could not re-read '$($S.Name)'."; return $false }
    $old = Get-Prop $cur 'VALUE'
    if ($old -is [int] -or $old -is [long]) { $NewValue = [int]$NewValue }
    $body = [ordered]@{ REQUEST = 'MODIFY'; HASHVAL = (Get-Prop $cur 'HASHVAL'); VALUE = $NewValue }
    $r = Invoke-Vizio -Conn $Conn -Path "/menu_native/dynamic/$root$($S.Menu)/$($S.CName)" -Method PUT -Body $body
    if (-not (Test-Success $r)) { Write-Warning "TV rejected the change to '$($S.Name)': $(Get-ResultCode $r)"; return $false }

    Start-Sleep -Milliseconds 400
    $check = Invoke-Vizio -Conn $Conn -Path "/menu_native/dynamic/$root$($S.Menu)"
    $after = Get-Prop (@(Get-Prop $check 'ITEMS') | Where-Object { (Get-Prop $_ 'CNAME') -eq $S.CName } | Select-Object -First 1) 'VALUE'
    $ok = ("$after" -eq "$NewValue")

    $logFile = Get-ChangeLogFile $Conn.Ip
    $log = @()
    if (Test-Path $logFile) { $log = Read-JsonArray $logFile }
    $log += [pscustomobject]@{ Time = (Get-Date).ToString('o'); Menu = $S.Menu; CName = $S.CName; Name = $S.Name; Trail = $S.Trail
                               Old = $old; New = $NewValue; Verified = $ok; Reason = $Reason; Undone = $false }
    ConvertTo-Json -InputObject @($log) -Depth 4 | Set-Content -Path $logFile -Encoding UTF8

    if ($ok) { Write-Host ("  OK  {0}: {1} -> {2}" -f $S.Trail, $old, $NewValue) -ForegroundColor Green }
    else { Write-Warning ("{0}: sent '{1}' but TV now reports '{2}'." -f $S.Trail, $NewValue, $after) }
    return $ok
}

# --------------------------------------------------------------------------
# Presets
# --------------------------------------------------------------------------
$Rules = @(
    [pscustomobject]@{ Preset = 'Privacy'; Match = '^(Viewing Data|Smart Interactivity)$'; Want = @('Off', 'Disabled')
        Why = 'ACR: the TV identifies what is on screen (apps, antenna and HDMI inputs) and reports it to Vizio for ads and measurement.' }
    [pscustomobject]@{ Preset = 'Privacy'; Match = 'Limit Ad Tracking'; Want = @('On', 'Enabled')
        Why = 'Stops ads personalized to the TV advertising ID.' }
    [pscustomobject]@{ Preset = 'Privacy'; Match = 'Interest.?Based|Personali[sz]ed Ad|Ad Personali'; Want = @('Off', 'Disabled')
        Why = 'Turns off interest-based ads.' }
    [pscustomobject]@{ Preset = 'FastStart'; Match = '^Power Mode$'; Want = @('Quick Start')
        Why = 'Wakes in seconds instead of cold-booting. Costs more standby power and keeps the network on.' }
    [pscustomobject]@{ Preset = 'BoxMode'; Match = '^CEC'; Want = @('On', 'Enabled')
        Why = 'Lets a streaming box turn the TV on, switch to its input, and share one remote.' }
)

function Invoke-Optimize {
    $conn = Resolve-Conn -NeedAuth
    Write-Host "Reading all settings from $($conn.Model) ($($conn.Ip))... (read-only)"
    $list = Get-SettingsList $conn
    Write-Host "Read $($list.Count) settings."
    $plan = New-Object System.Collections.Generic.List[object]
    foreach ($rule in ($Rules | Where-Object { $Preset -contains $_.Preset })) {
        $hits = @($list | Where-Object { $_.Name -match $rule.Match -and (Test-Changeable $_) })
        if (-not $hits.Count) { Write-Host ("  --  [{0}] no setting matching '{1}' on this TV" -f $rule.Preset, $rule.Match) -ForegroundColor DarkGray; continue }
        foreach ($h in $hits) {
            $target = @($h.Choices | Where-Object { $rule.Want -contains $_ }) | Select-Object -First 1
            if (-not $target) { Write-Host ("  ??  {0} = {1} (options: {2}) - no matching option, left alone" -f $h.Trail, $h.Value, ($h.Choices -join '/')) -ForegroundColor Yellow; continue }
            if ("$($h.Value)" -eq $target) { Write-Host ("  ok  {0} = {1}" -f $h.Trail, $h.Value) -ForegroundColor DarkGreen; continue }
            Write-Host ("  ->  {0}: {1} -> {2}" -f $h.Trail, $h.Value, $target) -ForegroundColor Cyan
            Write-Host ("      {0}" -f $rule.Why)
            $plan.Add([pscustomobject]@{ Setting = $h; Target = $target; Preset = $rule.Preset })
        }
    }
    if (-not $plan.Count) { Write-Host 'Nothing to change.'; return }
    if (-not $Apply) { Write-Host ''; Write-Host "Preview only. Re-run with -Apply to make these $($plan.Count) change(s)." -ForegroundColor Yellow; return }

    $bk = Save-Backup $conn $list
    Write-Host "Backup of all settings saved: $bk"
    foreach ($p in $plan) {
        if (Confirm-Step ("Change '{0}' from {1} to {2}?" -f $p.Setting.Trail, $p.Setting.Value, $p.Target)) {
            [void](Set-VizioSetting $conn $p.Setting $p.Target "preset $($p.Preset)")
        } else { Write-Host '  skipped' }
    }
    Write-Host 'Done. Undo any time with: .\Vizio-Tool.ps1 Undo'
}

function Invoke-Set {
    if (-not $Name -or $null -eq $Value -or $Value -eq '') { throw 'Set needs -Name "<setting name or menu path>" -Value "<new value>".' }
    $conn = Resolve-Conn -NeedAuth
    $list = Get-SettingsList $conn
    $hits = @($list | Where-Object { $_.Name -eq $Name -or $_.Trail -eq $Name -or "$($_.Menu)/$($_.CName)" -eq $Name })
    if (-not $hits.Count) { $hits = @($list | Where-Object { $_.Name -like "*$Name*" }) }
    if ($hits.Count -ne 1) {
        Write-Host "Found $($hits.Count) matches. Use the full path:"
        $hits | Select-Object -First 30 | ForEach-Object { Write-Host ("  {0}/{1}  ({2} = {3})" -f $_.Menu, $_.CName, $_.Trail, $_.Value) }
        return
    }
    $s = $hits[0]
    if (-not (Test-Changeable $s)) { throw "'$($s.Trail)' is type $($s.Type) and is not changed by this tool (actions and menus are never touched)." }
    if ($s.Choices.Count -and $s.Choices -notcontains $Value) { throw "Allowed values for '$($s.Trail)': $($s.Choices -join ', ')" }
    [void](Save-Backup $conn $list)
    if (Confirm-Step ("Change '{0}' from {1} to {2}?" -f $s.Trail, $s.Value, $Value)) { [void](Set-VizioSetting $conn $s $Value 'manual') }
}

function Invoke-Undo {
    $conn = Resolve-Conn -NeedAuth
    $logFile = Get-ChangeLogFile $conn.Ip
    if (-not (Test-Path $logFile)) { Write-Host 'No changes recorded for this TV.'; return }
    $log = Read-JsonArray $logFile
    $pending = @($log | Where-Object { -not $_.Undone })
    if (-not $pending.Count) { Write-Host 'Everything is already undone.'; return }
    [array]::Reverse($pending)
    foreach ($e in $pending) {
        if (Confirm-Step ("Restore '{0}' to {1} (currently {2})?" -f $e.Trail, $e.Old, $e.New)) {
            $s = [pscustomobject]@{ Menu = $e.Menu; CName = $e.CName; Name = $e.Name; Trail = $e.Trail }
            if (Set-VizioSetting $conn $s $e.Old 'undo') { $e.Undone = $true }
        }
    }
    # Set-VizioSetting appended 'undo' entries; merge the Undone flags back in.
    $fresh = Read-JsonArray $logFile
    foreach ($e in $fresh) {
        $orig = $pending | Where-Object { $_.Time -eq $e.Time -and $_.CName -eq $e.CName } | Select-Object -First 1
        if ($orig -and $orig.Undone) { $e.Undone = $true }
        if ($e.Reason -eq 'undo') { $e.Undone = $true }
    }
    ConvertTo-Json -InputObject @($fresh) -Depth 4 | Set-Content -Path $logFile -Encoding UTF8
}

# --------------------------------------------------------------------------
# Info, backup, keys, inputs
# --------------------------------------------------------------------------
function Invoke-Info {
    $conn = Resolve-Conn
    $info = Get-DeviceInfo $conn
    Write-Host ("TV        : {0}:{1}" -f $conn.Ip, $conn.Port)
    Write-Host ("Model     : {0}" -f (Get-Prop $info 'MODEL_NAME'))
    Write-Host ("Name      : {0}" -f (Get-Prop $info 'CAST_NAME'))
    if (-not $conn.AuthToken) { Write-Host 'Pair to see firmware, power state, input and app.'; return }
    $root = $conn.SettingsRoot
    foreach ($p in "/menu_native/dynamic/$root/system/system_information/tv_information", "/menu_native/dynamic/$root/admin_and_privacy/system_information/tv_information") {
        $r = Invoke-Vizio -Conn $conn -Path $p
        if (Test-Success $r) {
            foreach ($it in @(Get-Prop $r 'ITEMS')) {
                $n = Get-Prop $it 'NAME'
                if ($n -and $n -notmatch 'Serial') { Write-Host ("{0,-10}: {1}" -f $n, (Get-Prop $it 'VALUE')) }
            }
            break
        }
    }
    $pw = Invoke-Vizio -Conn $conn -Path '/state/device/power_mode'
    Write-Host ("Power     : {0}" -f $(if ((Get-Prop (@(Get-Prop $pw 'ITEMS') | Select-Object -First 1) 'VALUE') -eq 1) { 'on' } else { 'standby' }))
    $ci = Invoke-Vizio -Conn $conn -Path "/menu_native/dynamic/$root/devices/current_input"
    Write-Host ("Input     : {0}" -f (Get-Prop (@(Get-Prop $ci 'ITEMS') | Select-Object -First 1) 'VALUE'))
    $app = Invoke-Vizio -Conn $conn -Path '/app/current'
    $av = Get-Prop (Get-Prop $app 'ITEM') 'VALUE'
    if ($av) { Write-Host ("App       : APP_ID {0} / NAME_SPACE {1}" -f (Get-Prop $av 'APP_ID'), (Get-Prop $av 'NAME_SPACE')) }
}

function Invoke-Backup {
    $conn = Resolve-Conn -NeedAuth
    Write-Host 'Reading all settings (read-only)...'
    $list = Get-SettingsList $conn
    $file = Save-Backup $conn $list
    Write-Host "Saved $($list.Count) settings to $file"
    $csv = [IO.Path]::ChangeExtension($file, '.csv')
    $list | Select-Object Trail, Value, Type, @{ n = 'Options'; e = { $_.Choices -join ' / ' } }, Menu, CName |
        Export-Csv -Path $csv -NoTypeInformation -Encoding UTF8
    Write-Host "Readable copy: $csv"
}

$Keys = @{
    POWER_OFF = @(11, 0); POWER_ON = @(11, 1); POWER = @(11, 2); INPUT = @(7, 1)
    HOME = @(4, 15); MENU = @(4, 8); BACK = @(4, 0); OK = @(3, 2)
    UP = @(3, 8); DOWN = @(3, 0); LEFT = @(3, 1); RIGHT = @(3, 7)
    VOL_UP = @(5, 1); VOL_DOWN = @(5, 0); MUTE = @(5, 4)
}

function Invoke-Key {
    $k = "$KeyName".ToUpper()
    if (-not $Keys.ContainsKey($k)) { throw "Use -KeyName one of: $(($Keys.Keys | Sort-Object) -join ', ')" }
    $conn = Resolve-Conn -NeedAuth
    $body = [ordered]@{ KEYLIST = @([ordered]@{ CODESET = $Keys[$k][0]; CODE = $Keys[$k][1]; ACTION = 'KEYPRESS' }) }
    $r = Invoke-Vizio -Conn $conn -Path '/key_command/' -Method PUT -Body $body
    Write-Host ("{0}: {1}" -f $k, (Get-ResultCode $r))
}

function Invoke-Input {
    $conn = Resolve-Conn -NeedAuth
    $root = $conn.SettingsRoot
    $names = Invoke-Vizio -Conn $conn -Path "/menu_native/dynamic/$root/devices/name_input"
    $inputs = @(Get-Prop $names 'ITEMS' | ForEach-Object {
        $v = Get-Prop $_ 'VALUE'
        [pscustomobject]@{ Input = (Get-Prop $_ 'NAME'); Label = $(if ($v -is [string]) { $v } else { Get-Prop $v 'NAME' }) }
    })
    $cur = @(Get-Prop (Invoke-Vizio -Conn $conn -Path "/menu_native/dynamic/$root/devices/current_input") 'ITEMS') | Select-Object -First 1
    if (-not $Value) {
        Write-Host "Current input: $(Get-Prop $cur 'VALUE')"
        $inputs | ForEach-Object { Write-Host ("  {0,-12} {1}" -f $_.Input, $_.Label) }
        Write-Host 'Switch with: .\Vizio-Tool.ps1 Input -Value HDMI-1'
        return
    }
    $body = [ordered]@{ REQUEST = 'MODIFY'; HASHVAL = (Get-Prop $cur 'HASHVAL'); VALUE = $Value }
    $r = Invoke-Vizio -Conn $conn -Path "/menu_native/dynamic/$root/devices/current_input" -Method PUT -Body $body
    Write-Host ("Input -> {0}: {1}" -f $Value, (Get-ResultCode $r))
}

function Invoke-Forget {
    $conn = Resolve-Conn
    Remove-Item (Get-StateFile $conn.Ip) -ErrorAction SilentlyContinue
    Write-Host "Forgot the saved pairing for $($conn.Ip) on this PC. Undo log and backups are kept in $StateDir."
    Write-Host 'Also remove "Windows TV Tool" on the TV: Settings > Mobile Devices (or Admin & Privacy).'
}

# --------------------------------------------------------------------------
# Entry point
# --------------------------------------------------------------------------
function Invoke-Action {
    param([string]$A)
    switch ($A) {
        'Find'     { Find-Vizio }
        'Pair'     { Invoke-Pair }
        'Info'     { Invoke-Info }
        'Backup'   { Invoke-Backup }
        'Optimize' { Invoke-Optimize }
        'Set'      { Invoke-Set }
        'Undo'     { Invoke-Undo }
        'Key'      { Invoke-Key }
        'Input'    { Invoke-Input }
        'Forget'   { Invoke-Forget }
    }
}

if ($Action -ne 'Menu') {
    try { Invoke-Action $Action } catch { Write-Host "Error: $($_.Exception.Message)" -ForegroundColor Red; exit 1 }
    exit 0
}

while ($true) {
    Write-Host ''
    Write-Host '=== Vizio TV Tool ===' -ForegroundColor Cyan
    Write-Host ' 1  Find my Vizio TV'
    Write-Host ' 2  Pair with the TV (shows a PIN on screen)'
    Write-Host ' 3  TV info'
    Write-Host ' 4  Back up all settings'
    Write-Host ' 5  Privacy check (preview only)'
    Write-Host ' 6  Privacy fix (turn off Viewing Data / ad tracking)'
    Write-Host ' 7  Streaming-box mode (CEC on) + fast start'
    Write-Host ' 8  Undo my changes'
    Write-Host ' Q  Quit'
    $choice = (Read-Host 'Choose').Trim().ToUpper()
    try {
        switch ($choice) {
            '1' { $script:Ip = $null; Find-Vizio }
            '2' { if (-not $Ip) { $script:Ip = Read-Host 'TV IP address (from step 1)' }; Invoke-Pair }
            '3' { Invoke-Info }
            '4' { Invoke-Backup }
            '5' { $script:Preset = @('Privacy'); $script:Apply = $false; Invoke-Optimize }
            '6' { $script:Preset = @('Privacy'); $script:Apply = $true; Invoke-Optimize }
            '7' { $script:Preset = @('BoxMode', 'FastStart'); $script:Apply = $true; Invoke-Optimize }
            '8' { Invoke-Undo }
            'Q' { return }
            default { Write-Host 'Pick 1-8 or Q.' }
        }
    } catch { Write-Host "Error: $($_.Exception.Message)" -ForegroundColor Red }
}
