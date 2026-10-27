# Step 1: Find and identify the TV automatically

`Discover-TV.ps1` finds every TV and streaming device on your network and
reports its brand, exact model, OS, firmware, and which advanced-access
paths are open (developer mode, ADB). It is read-only: it never pairs,
logs in, or changes settings on any device.

## Run it

1. Turn the TV **on** (not standby). Many TVs drop off the network in standby.
2. Make sure the PC is on the **same network** as the TV (not a guest Wi-Fi),
   and disconnect any VPN.
3. Download this `discovery` folder to the PC.
4. Double-click **`Run-Discovery.cmd`**.
   - If Windows Firewall asks about PowerShell, allow it on **Private**
     networks only. Discovery replies are blocked otherwise.
   - If SmartScreen complains because the file was downloaded:
     right-click the file > Properties > tick **Unblock** > OK.

Takes about 30-60 seconds. Results go to `tv-discovery-<date>\` next to the script:

| File | What it is | Share it? |
|---|---|---|
| `summary.txt` | Readable result. No serial numbers or full MACs. | Yes, paste it back to Claude |
| `discovery-full.json` | Every raw response | Keep private (has serials and MACs) |
| `discovery.log` | Warnings and steps | If something failed |

### Options

```powershell
# from a PowerShell window in this folder
powershell -ExecutionPolicy Bypass -File .\Discover-TV.ps1 -Subnet 192.168.1.0/24   # pick the network
powershell -ExecutionPolicy Bypass -File .\Discover-TV.ps1 -Offline                 # skip the IEEE vendor-list download
powershell -ExecutionPolicy Bypass -File .\Discover-TV.ps1 -TryAdb                  # Android/Google/Fire TV: read build props over ADB
powershell -ExecutionPolicy Bypass -File .\Discover-TV.ps1 -Verbose                 # more console detail
```

`-TryAdb` needs Google's `adb.exe` (Android SDK platform-tools, from
developer.android.com only) on PATH or in a `platform-tools` folder next to the
script. The TV will ask "Allow USB debugging?". The script only runs `getprop`,
reads `/proc/meminfo`, and runs `df`.

## What it checks

| Method | Finds | Typical result |
|---|---|---|
| Ping sweep + ARP table | Every live device, its MAC | MAC vendor (e.g. "Samsung Electronics", "LG Innotek", "TCL", "Hisense") |
| IEEE OUI list | Manufacturer of the network chip | Brand hint only. The Wi-Fi chip maker can differ from the TV brand |
| SSDP / UPnP | Device description XML | `manufacturer`, `modelName`, `modelNumber`, `friendlyName` |
| mDNS / DNS-SD | Google Cast, Android TV Remote, AirPlay, Fire TV, Spotify Connect, HomeKit | Cast `md=` model, AirPlay `model=` |
| TCP port fingerprint | Platform-specific control ports | Tizen 8001/8002, webOS 3000/3001, Roku 8060, Cast 8008/8009/8443, Android TV Remote 6466/6467, ADB 5555, Vizio 7345/9000, Philips 1925/1926, Hisense 36669, Panasonic 55000 |
| Vendor info endpoints | Exact model and firmware, no pairing needed | Samsung `/api/v2/` (also shows Developer Mode on/off), Roku `/query/device-info` (also developer mode), Cast `eureka_info`, Vizio `deviceinfo`, Philips `/system`, Sony `getInterfaceInformation`, Panasonic `ddd.xml` |
| ADB (opt-in) | Android build properties | `ro.product.model`, Android version, security patch, bootloader lock state, RAM |

Confidence levels in the summary:

- **exact**: the TV's own API or ADB reported the model.
- **high**: Google Cast device info.
- **medium**: UPnP or mDNS. Often the retail model, sometimes a family name.
- **low**: brand or platform only.

## If nothing was found

Work down this list:

1. **TV in standby or on another network.** Wake it, check it is on the same
   Wi-Fi/LAN as the PC (not guest Wi-Fi, which isolates clients), and re-run.
2. **Windows network set to Public.** Settings > Network & internet > your
   connection > Network profile type: **Private**. Re-run.
3. **VPN, or the PC on a different subnet** (mesh/extender in router mode).
   Disconnect the VPN, or pass `-Subnet`.
4. **Read it off the TV** (about 30 seconds, always exact):

   | Brand / OS | Where |
   |---|---|
   | Samsung (Tizen) | Settings > Support > About This TV |
   | LG (webOS) | Settings > All Settings > Support (or General) > About This TV / TV Information |
   | Sony, TCL, Hisense, Philips (Google TV / Android TV) | Settings > System > About |
   | Roku OS (incl. TCL/Hisense Roku TVs) | Settings > System > About |
   | Hisense / Toshiba (VIDAA) | Settings > Support > System Info |
   | Vizio (SmartCast) | Menu > System > System Information |
   | Fire TV (incl. Insignia/Toshiba Fire TVs) | Settings > My Fire TV > About |

   A phone photo of that screen is enough. The sticker on the back panel also
   has the exact model code.
5. **Router client list.** The router's admin page (usually the gateway IP the
   script prints) lists connected devices with names like `Samsung-TV`,
   `LGwebOSTV`, `BRAVIA-...`, `HiTV`.

## Safety notes

- Read-only. Requests are HTTP GETs to info pages, plus one Sony JSON-RPC
  getter (`getInterfaceInformation`), which is a POST but changes nothing.
- No credentials are tried. Nothing is sent to the internet except the
  one-time download of the public IEEE OUI list (skip it with `-Offline`).
- HTTPS certificate checks are relaxed only for requests to LAN devices,
  because TVs use self-signed certificates.
- Port checks are TCP connects to about 20 ports on devices already seen on
  your network. Nothing is sent after the connect.
