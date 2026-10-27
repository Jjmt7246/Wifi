# Old Vizio TV: what's possible and the tool for it

## Can it get a new operating system?

No. Vizio TVs only install firmware that Vizio has signed. There is no public
jailbreak or custom firmware for SmartCast or the older VIA system. Forcing one
would mean opening the TV and wiring into its circuit board (serial port or
flash chip), with a high chance of a dead TV. Even then, a new system would
have no drivers for the panel, remote, or video decoder. This project will not
try it.

The "new TV" route that works:

1. **Plug in a current streaming box** (Google TV Streamer or Chromecast with
   Google TV, Fire TV, Roku, Apple TV, Nvidia Shield). It brings current apps
   and security updates. Google TV devices allow the most customization later:
   custom launcher, fewer ads, sideloaded apps.
2. **Make the TV behave like a monitor for the box.** This tool turns on CEC,
   so the box powers the TV on, switches the input, and the box remote controls
   TV volume and power.
3. **Cut what the TV sends home.** This tool turns off Viewing Data (ACR) and ad
   tracking. Or, once the box is set up, remove the TV from Wi-Fi entirely
   (Settings > Network > forget the network). An offline TV cannot track or show
   home-screen ads, and no longer needs updates. Do this after you're done with
   the tool, since the tool needs the network.

## The tool: `Vizio-Tool.ps1`

Uses the TV's built-in local API, the same one the Vizio phone app uses. It
works on **SmartCast** TVs (about 2016 and later). Pre-2016 VIA / Internet Apps
models have no local API; for those, steps 1 and 3 above still apply.

### Run it

1. TV on, PC on the same network.
2. Double-click `Run-VizioTool.cmd`. A menu appears:

```
 1  Find my Vizio TV
 2  Pair with the TV (shows a PIN on screen)
 3  TV info
 4  Back up all settings
 5  Privacy check (preview only)
 6  Privacy fix (turn off Viewing Data / ad tracking)
 7  Streaming-box mode (CEC on) + fast start
 8  Undo my changes
```

Go in order: **1, 2, 4, 5**, then **6** and/or **7** if the preview looks right.

### What each preset changes

The tool finds settings by name, because the menu location differs between
models (newer: *Admin & Privacy*; older: *System > Reset & Admin*).

| Preset | Setting | Changed to | Why |
|---|---|---|---|
| Privacy | Viewing Data / Smart Interactivity | Off | ACR: the TV identifies what is on screen, including HDMI inputs, and reports it to Vizio |
| Privacy | Limit Ad Tracking | On | No ads targeted to the TV's advertising ID |
| Privacy | Interest-based / personalized ads (if present) | Off | Fewer targeted ads |
| FastStart | Power Mode | Quick Start | Turns on in seconds. Uses more standby power and keeps networking on |
| BoxMode | CEC | On | Box controls TV power, input, volume |

What it can't do: remove Vizio's built-in apps or the WatchFree+ home-screen
content, or stop all data collection. Vizio's privacy policy says turning off
Viewing Data does not stop "Activity Data" collected through SmartCast itself.
Taking the TV offline is the only complete fix.

### Safety

- Steps 1, 3, 4 and 5 only read.
- Every change asks first, is read back to confirm it took effect, and is
  recorded. Option 8 restores the old values.
- A full settings backup (JSON + CSV) is saved before any change, in
  `%LOCALAPPDATA%\TvDiscovery\vizio\`.
- Action items (factory reset, channel scan, reset ad ID) are never touched.
- The pairing token is stored encrypted for your Windows account. To revoke it:
  on the TV, Settings > Mobile Devices (or Admin & Privacy) > remove
  "Windows TV Tool", then run `.\Vizio-Tool.ps1 Forget`.

### Command line

```powershell
.\Vizio-Tool.ps1 Find
.\Vizio-Tool.ps1 Pair -Ip 192.168.1.40
.\Vizio-Tool.ps1 Optimize -Preset Privacy,BoxMode,FastStart          # preview
.\Vizio-Tool.ps1 Optimize -Preset Privacy,BoxMode,FastStart -Apply   # apply with prompts
.\Vizio-Tool.ps1 Set -Name "Viewing Data" -Value Off
.\Vizio-Tool.ps1 Input -Value HDMI-1
.\Vizio-Tool.ps1 Key -KeyName POWER_ON
.\Vizio-Tool.ps1 Undo
```

Run from PowerShell with `powershell -ExecutionPolicy Bypass -File .\Vizio-Tool.ps1 ...`
if scripts are blocked.

## References

- API endpoints and pairing flow follow the open-source
  [pyvizio](https://github.com/vkorn/pyvizio) library.
- [Vizio Viewing Data privacy policy](https://vizio.com/en/terms/privacy-policy/viewing-data-privacy-policy)
- [Tom's Guide: turning off smart TV data collection](https://www.tomsguide.com/uk/how-to/stop-your-snooping-smart-tv-how-to-turn-off-data-collection-for-every-brand)
- [Tom's Guide: FTC confirms Vizio tracked viewing](https://www.tomsguide.com/us/vizio-ftc-smart-tv-spying-privacy,news-24415.html)
