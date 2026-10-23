<div align="center">

# Cryptic™ Vaults for Android

*LUKS2 encrypted USB drives and containers on Android, without root*

![Android 14+](https://img.shields.io/badge/Android-14%2B-3ddc84?style=flat-square&logo=android&logoColor=white)
![Kotlin](https://img.shields.io/badge/Kotlin-7f52ff?style=flat-square&logo=kotlin&logoColor=white)
![No network access](https://img.shields.io/badge/Network-none-555?style=flat-square)
[![License: PolyForm Noncommercial 1.0.0](https://img.shields.io/badge/License-PolyForm_Noncommercial_1.0.0-blue?style=flat-square)](LICENSE)

[Privacy](#built-for-privacy) • [Features](#features) • [Install](#install) • [Usage](#usage) • [Compatibility](#compatibility) • [Build from source](#build-from-source) • [Tests](#tests)

</div>

## Security is a right, not a privilege.

Android can encrypt the phone itself, but not the drives you plug into it or the files you carry around. There was no baked-in way to manage industry standard drive and container encryption, and the few apps that claimed to add this were jank and lived behind a paywall. The developer rejected these options for both reasons, and Cryptic Vaults was born.

## Built for privacy

- Zero telemetry, analytics or ads.
- No sign-up or account required.
- No network access at all: Cryptic Vaults doesn't even ask for the internet permission.
- Nothing leaves your device. Passphrases and keys are only held in memory while a volume is unlocked. None is stored unless you turn on App lock and choose to save a vault's passphrase; those stay encrypted on this phone.
- Standard LUKS2, so your drives open with cryptsetup on any Linux machine, with or without Cryptic Vaults.

## Free, as it should be.

No paywall, no gotcha, no upsell, no monetizing your data. Free forever, because it's the right thing to do. If you don't think that's fair, you can always buy me a coffee from within the app! 😊

> [!NOTE]
> Cryptic Vaults is licensed under the [PolyForm Noncommercial License 1.0.0](LICENSE): free for personal and other non-commercial use. Commercial use, including selling it or building it into a paid product, needs the developer's written permission. The bundled Argon2 code (`app/src/main/cpp/argon2`) keeps its own license.

> [!NOTE]
> Cryptic™ and the Cryptic padlock are trademarks of the developer. The license covers the code, not the name or the logo: a modified version you share needs its own name and icon.

## How it works

Cryptic Vaults unlocks, creates and manages standard [LUKS2](https://gitlab.com/cryptsetup/cryptsetup) volumes, the same format `cryptsetup` uses on Linux, on USB drives and in container files. An unlocked volume shows up in Android's Files app, where any app can read and write it.

Everything runs inside the app: LUKS2, AES-XTS, Argon2 and the exFAT and ext4 filesystems are implemented in userspace, so it needs no root and no kernel support.

## Features

- **USB drives** – Plug in a LUKS2 drive over USB-C/OTG and Cryptic Vaults asks for the passphrase. It talks to the drive directly over USB mass storage (bulk-only, including UAS-capable SSDs).
- **Container files** – Open or create a LUKS2 volume stored as a file on the phone, and keep a list of the ones you use.
- **Read and write** – exFAT and ext4 inside the volume, read-write, exposed through a Files app root while unlocked.
- **Create** – Encrypt a drive (fresh GPT, one partition, LUKS2 with AES-XTS-512, Argon2id and SHA-512, then exFAT or ext4) or make a new container of any size.
- **Edit** – Change a volume's passphrase (crash-safe: new key slot first, then the old one is removed), its LUKS label, filesystem label and partition name.
- **Details** – Device, disk, USB, partition and LUKS header information, plus SMART health where the USB bridge passes it through.
- **Wipe** – Quick header wipe, or a full zero or random fill.
- **App lock** – Fingerprint or face, a passphrase of the app's own, or a YubiKey (FIDO2 with its PIN, optionally plus a second check). Never a PIN.
- **Saved passphrases (optional)** – Only with App lock on, stored encrypted behind it, per vault and only when you choose.
- **Auto-lock** – Lock an unlocked vault after a period without use, or as soon as you leave the app.

## Install

Download the APK from the [Releases](../../releases) page and open it on your phone to sideload it.

> [!IMPORTANT]
> Cryptic Vaults needs Android 14 or later on a 64-bit ARM phone with USB host (OTG) support for drives. Container files work without USB.

## Usage

1. **Plug in a drive** – Android asks whether Cryptic Vaults may access it; then enter the passphrase.
2. **Open in Files** – The unlocked volume appears as its own entry in the Files app. Copy, open and save files there as on any storage.
3. **Lock** – Tap *Lock*, or let auto-lock do it. Pending writes are flushed to the drive first.

Containers work the same way from *Open or create a container* on the main screen.

> [!TIP]
> Turn on *Open Cryptic Vaults when a drive is plugged in* in Settings, and tick Android's "always open" for a drive, to go straight to the passphrase prompt.

> [!WARNING]
> Lock a drive in Cryptic Vaults before unplugging it. Unplugging mid-write can leave the filesystem needing a check (`fsck`) on a computer.

## Compatibility

Cryptic Vaults reads volumes made by `cryptsetup luksFormat` with its defaults, and Linux opens the ones Cryptic Vaults makes.

| | Supported |
|---|---|
| Format | LUKS2 (LUKS1 is not supported) |
| Cipher | `aes-xts-plain64` |
| Key derivation | Argon2id, Argon2i, PBKDF2 |
| Sector size | 512 and 4096 bytes |
| Partitions | Whole-disk LUKS2, GPT or MBR (primary partitions) |
| Filesystems | exFAT, ext4 (volumes using ext4 encryption or casefolding are refused) |

Not supported: dm-integrity, volumes in the middle of a re-encryption, TexFAT.

## Build from source

Prerequisites:

- **JDK 17 to 24** (tested with 21). Gradle 8.14 doesn't run on newer versions.
- **Android SDK** with platform 36 and the **NDK** 27.0.12077973 (`ndk-build` builds the native Argon2). Install both with Android Studio's SDK Manager or `sdkmanager`.

> [!IMPORTANT]
> Tell the build where both are before the first build. A fresh clone knows neither.
>
> - **JDK:** set `JAVA_HOME`, or, if your default Java is newer than 24, add `org.gradle.java.home=/path/to/jdk-21` to `~/.gradle/gradle.properties` (applies to your machine only).
> - **Android SDK:** set `ANDROID_HOME`, or create `local.properties` in the project root with `sdk.dir=/path/to/android-sdk`. It's git-ignored.

Then build:

```bash
./gradlew assembleDebug
```

The APK is written to `app/build/outputs/apk/debug/app-debug.apk`. Install it with:

```bash
adb install -r app/build/outputs/apk/debug/app-debug.apk
```

Argon2 is the [reference implementation](https://github.com/P-H-C/phc-winner-argon2) in `app/src/main/cpp/argon2`, compiled for arm64; the unit tests fall back to Bouncy Castle's Java version.

## Tests

The unit tests check Cryptic Vaults' output against real Linux tools: `cryptsetup`, `fsck.exfat` and `e2fsck` run in a privileged Docker container, and every image Cryptic Vaults writes has to pass them.

```bash
test-vectors/vectors.sh make     # reference images made by cryptsetup, mkfs.exfat and mkfs.ext4
./gradlew testDebugUnitTest
```

> [!NOTE]
> The container needs `--privileged` for the loop devices and dm-crypt. On macOS, Docker Desktop or Colima works.

## The Cryptic™ family

Cryptic Vaults is a member of the Cryptic™ family of utilities. Check out our other apps:

- [Cryptic Vaults for Linux and macOS](https://github.com/nockesocks/cryptic-vaults): the same LUKS2 drives and containers on your computer.
- Cryptic Pass: a password manager. Coming soon.

See all Cryptic™ apps on [github.com/nockesocks](https://github.com/nockesocks).
