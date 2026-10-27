<h1 align="center">PatchDL</h1>

<p align="center">
  <img src="docs/images/hero.jpg" alt="PatchDL in a desktop browser, and the Other versions list on a phone" width="900">
</p>

<p align="center">
  Downloads and installs official updates for PS5 and PS4 games, controlled from any browser.
</p>

<p align="center">
  <img src="https://img.shields.io/github/v/release/knutwurst/ps5-patchdl?style=for-the-badge&label=release&color=22c55e" alt="Latest release">
  <img src="https://img.shields.io/github/downloads/knutwurst/ps5-patchdl/total?style=for-the-badge&color=22c55e" alt="Downloads">
  <img src="https://img.shields.io/badge/games-PS5%20%7C%20PS4-22c55e?style=for-the-badge" alt="PS5 and PS4 games">
  <img src="https://img.shields.io/badge/FW-1.00%E2%80%9313.60-22c55e?style=for-the-badge" alt="Firmware 1.00 to 13.60">
  <img src="https://img.shields.io/github/license/knutwurst/ps5-patchdl?style=for-the-badge&color=3a3a3a" alt="License">
</p>

<p align="center">
  <a href="https://github.com/knutwurst/ps5-patchdl/releases/latest">
    <img src="https://img.shields.io/badge/Download-latest%20release-22c55e?style=for-the-badge&logo=github&logoColor=white" alt="Download the latest release" height="42">
  </a>
</p>

<p align="center">
  If you like what I do, you can buy me a coffee*:
  <a href="https://paypal.me/oliverkoester"><img src="https://img.shields.io/badge/Donate-PayPal-22c55e?style=flat-square&logo=paypal&logoColor=white" alt="Donate via PayPal"></a><br>
  <sub>*It doesn't have to be a generous donation. A few cents are enough to show me who is interested in further development. So the motivation stays and I just know that I am not programming for the bin ;)</sub>
</p>

---

## What it does

PatchDL runs as a payload on the PS5 and serves a small web page. Open that page on your phone, your laptop or in the console's browser and you get a list of your installed games with their version and the latest update Sony has for them. Click Update, and PatchDL downloads the patch from Sony's servers and hands it to the console's own installer.

A few things it does on top of that:

- Update all queues every game that has an update and works through them one by one.
- Downloads use several connections at once (4 by default, up to 16).
- If the newest patch needs a firmware you don't have, PatchDL looks for the latest one that still runs on your console. Under Other versions you can pick any version of a patch yourself.
- A download that gets interrupted continues where it stopped, also after a pause or a restart of PatchDL.
- After a successful install the package is deleted. You can switch that off.
- Optionally every piece is checked against Sony's checksums.
- There's a switch for a PatchDL tile on the home screen.
- The interface is available in ten languages.

PatchDL only updates games installed from disc or the PlayStation Store. It doesn't download games, and it doesn't touch system software.

## Screenshots

<table>
  <tr>
    <td align="center" width="50%"><img src="docs/images/games.jpg" width="420" alt="Games with updates and a running download"><br><sub>Games with updates</sub></td>
    <td align="center" width="50%"><img src="docs/images/library.jpg" width="420" alt="All installed games, sorted by name"><br><sub>All installed games</sub></td>
  </tr>
  <tr>
    <td align="center" width="50%"><img src="docs/images/versions.jpg" width="420" alt="Other versions list in the browser and the guide on a phone"><br><sub>Picking another version</sub></td>
    <td align="center" width="50%"><img src="docs/images/settings.jpg" width="420" alt="Settings"><br><sub>Settings</sub></td>
  </tr>
  <tr>
    <td align="center" width="50%"><img src="docs/images/phones.jpg" width="420" alt="PatchDL on a phone: game list and settings"><br><sub>On a phone</sub></td>
    <td align="center" width="50%"><img src="docs/images/tile-homescreen.jpg" width="420" alt="PatchDL tile on the PS5 home screen"><br><sub>Home screen tile</sub></td>
  </tr>
</table>

## Installation

1. Download `patchdl_<version>.elf` from the [latest release](https://github.com/knutwurst/ps5-patchdl/releases/latest).
2. Send it to your PS5 with the ELF loader you already use.
3. The console shows a notification with the address, e.g. `http://192.168.0.42:12880/`. Open it in a browser on the same network.

You need a PS5 that can load ELF payloads. PatchDL should run on firmware 1.00 to 13.60; I've tested it on 11.60 and 13.60.

## FAQ

**Where do the updates come from?**
From Sony's update servers, the same files the console would download itself. Nothing gets modified. To find Sony's servers PatchDL uses public DNS (Cloudflare, Google, Quad9) and leaves the console's DNS settings alone, so if you block system updates through DNS, that block stays in place.

**How does it know about older patches?**
Sony only tells the console about the newest patch. The version history comes from [Prospero Patches](https://prosperopatches.com/) for PS5 games and [Orbis Patches](https://orbispatches.com/) for PS4 games. PatchDL sends them the game's title ID, nothing else.

**How do I get a specific version?**
Open Other versions on the game, pick a version and follow the steps. You copy one link from the patch site (on the PS5 you scan a QR code and do that part on your phone), paste it, and PatchDL downloads that version from Sony.

**Can I go back to an older version?**
On PS5 games, yes. Older versions under Other versions have a Downgrade button. A PS5 update contains the whole game, so PatchDL removes the installed game and puts the older version on. Your saves stay, but a save made with the newer version may not load in the older one. Turn off updates for that game afterwards, or Update all brings it back to the newest version. PS4 patches build on the installed one and only go forward.

**When is the package deleted?**
Only after the console reports the new version and its installer has registered the package. Otherwise it stays. You can turn deleting off in Settings.

**Do disc games work?**
Yes. Keep the disc in the drive while the update installs. Some disc builds are older than the base the update expects. Then PatchDL asks once and installs the update as the whole game instead; your saves stay and the disc stays the license.

**What if the power goes out during a download?**
Start PatchDL again and press Resume.

## Disclaimer

PatchDL is an independent project and not affiliated with or endorsed by Sony Interactive Entertainment. "PlayStation", "PS5" and "PS4" are trademarks of Sony Interactive Entertainment Inc.

PatchDL downloads official, unmodified updates for games that are already installed. It doesn't download games, doesn't contain Sony software, keys or game content, and doesn't install unsigned or modified packages. Use it with games you own. Issues about pirated content will be closed.

## Building

```sh
scripts/build_ps5.sh        # builds patchdl-ps5.elf
```

This needs the [ps5-payload-dev SDK](https://github.com/ps5-payload-dev/sdk) (0.44 or newer) with `libcurl` and `OpenSSL` from its [pacbrew-repo](https://github.com/ps5-payload-dev/pacbrew-repo). `libmicrohttpd` and SQLite are included in the repo. Every push is built by GitHub Actions, and tags become releases.

To try a build on your console:

```sh
PS5_HOST=<console-ip> scripts/deploy_ps5.sh
```

## Credits

Built on [libmicrohttpd](https://www.gnu.org/software/libmicrohttpd/), [libcurl](https://curl.se/), [OpenSSL](https://www.openssl.org/), [SQLite](https://sqlite.org/) and the [ps5-payload-dev SDK](https://github.com/ps5-payload-dev/sdk). The patch history comes from [Prospero Patches](https://prosperopatches.com/) and [Orbis Patches](https://orbispatches.com/). Thanks to everyone working on these.

## Support

If you like what I do, you can buy me a coffee*: [![Donate](https://img.shields.io/badge/Donate-PayPal-22c55e?style=flat-square&logo=paypal&logoColor=white)](https://paypal.me/oliverkoester)

<sub>*It doesn't have to be a generous donation. A few cents are enough to show me who is interested in further development. So the motivation stays and I just know that I am not programming for the bin ;)</sub>

## License

GNU General Public License v3.0 or later, see [LICENSE](LICENSE).

Copyright © 2026 Knutwurst.
