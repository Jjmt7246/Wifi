# Smart TV Optimization

Engineering project to identify a smart TV on the home network, map what its
hardware and firmware allow, and turn it into the fastest, cleanest, most
private setup it supports. Each change is measured, reversible, and done one at
a time with approval.

## Phases

| # | Phase | Status |
|---|---|---|
| 1 | Automatic identification (network discovery from Windows) | **Ready: [`discovery/`](discovery/README.md)** |
| 2 | Advanced access research for the exact model and firmware (developer mode, ADB, sideloading, launchers, root/homebrew feasibility, recovery) | After phase 1 results |
| 3 | Baseline benchmarks (boot time, app launch, RAM, network latency, DNS) | After phase 2 |
| 4 | Optimization, one change at a time, with backup and rollback | After phase 3 |
| 5 | Streaming ecosystem: free/legal services, open-source players, self-hosted media, security-vetted | Parallel with phase 4 |
| 6 | Privacy: telemetry, ads, DNS filtering | Parallel with phase 4 |

## What each platform usually allows

A starting point only. Phase 2 checks it against your exact model and firmware.

| Platform | Brands | Customization ceiling | Main levers |
|---|---|---|---|
| Google TV / Android TV | Sony, TCL, Hisense, Philips, Sharp, Chromecast | **Highest** | Developer options, ADB over network, sideloading, custom launchers, reversible app disabling (`pm disable-user`), animation scales, Private DNS. Root is rarely possible (locked bootloaders) |
| Fire OS | Amazon, Insignia, Toshiba Fire TV | High (older Fire OS), lower on newer | ADB and sideloading. Launcher replacement is restricted on recent Fire OS. Some newer devices run Vega OS, which does not allow sideloading |
| LG webOS | LG | Medium to high | Developer Mode app, Homebrew Channel. Root depends on the exact firmware version; check before updating |
| Samsung Tizen | Samsung | Medium | Developer Mode, sideloading signed Tizen apps (.wgt) through Tizen Studio. No public root for current firmware |
| Roku OS | Roku, TCL/Hisense Roku TVs | Low | Developer mode for sideloading one dev channel. No root |
| VIDAA / SmartCast | Hisense, Toshiba / Vizio | Low | Settings, DNS-level filtering, external streaming box |

On low-ceiling platforms, the fastest result is often a well-chosen external
Google TV streamer with the TV's own smart features minimized. Phase 2 weighs
that against modifying the TV.
