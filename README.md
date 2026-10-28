# CipherDesk

A Windows desktop proof of concept for encrypting files to groups of contacts and decrypting received files. 
Kleopatra manages keys; CipherDesk uses the same GnuPG installation and keyring. Groups and settings stay on your computer.

## Start

1. Install [Gpg4win](https://www.gpg4win.org/), including Kleopatra and GnuPG.
2. In Kleopatra, create your OpenPGP key pair. Exchange **public** keys with colleagues and import their public keys. Verify each full fingerprint through a trusted, separate channel, then certify the verified key in Kleopatra.
3. Extract the Windows package and launch `CipherDesk\CipherDesk.exe` (or `dist\CipherDesk\CipherDesk.exe` in the source project). Keep its `_internal` folder alongside it. This build does not require Python.
4. For the source version, install 64-bit Python 3.10 or newer and double-click `run.cmd`. It creates `.venv` beside the app and installs the pinned UI dependency on first launch. Gpg4win is still required.

The usual Gpg4win locations are detected automatically. If GnuPG is installed in a custom location, launch with `--gpg-path C:\path\to\gpg.exe`. If Kleopatra is not detected, open it from the Windows Start menu.

## Everyday use

- Open Kleopatra from the app to create, import, certify, back up, or revoke keys. Refresh the contact list after changing keys.
- Create a named group, select its contacts, and save it. Groups contain full public-key fingerprints, so duplicate names and email addresses do not silently redirect a group.
- Add files, choose one or more groups, choose an output folder, and encrypt. Selecting multiple groups combines and deduplicates recipients. Create a group with a single contact when sharing with one person. Each file is encrypted separately to the selected recipients.
- Include your own public key if you want to decrypt the outgoing copies later. Signing additionally proves possession of the selected signing key; it does not establish identity unless the key's fingerprint has been verified.
- To receive files, choose the encrypted files and a local output folder, then decrypt. Review the result and any signature status before opening the output.

Unsigned files are accepted and clearly labelled by default. Enable **Require a valid signature from a trusted key** to reject unsigned documents and signatures whose keys have not been certified as trusted. Invalid or unverifiable signatures and failed integrity checks do not produce a final decrypted output file.

Original source files are left unchanged. Choose a separate output folder for generated files. Passphrases are handled by GnuPG's Pinentry prompt and agent; CipherDesk does not request or save them.

## Local storage

Normal configuration is stored under `%LOCALAPPDATA%\CipherDesk`. It contains contact groups, full fingerprints, and settings; it contains no private keys or passphrases. GnuPG keeps key material in its own keyring, as used by Kleopatra. Treat configuration as local application data, not as a key backup.

CipherDesk deliberately does not read advanced `gpg.conf` options. It selects recipients, output files, and trust behavior explicitly while keeping the default keyring and GnuPG agent. Custom `gpg.conf` recipient rules and overrides do not apply to this app.

The output folder can be a Cloud synced folder. Only choose that folder for **encrypted** output; use a separate local, unsynced folder for decrypted documents. A completed encryption operation means the local file was written. The app does not confirm upload or sync completion.

Removing a contact from a group affects future encryptions. It cannot revoke access to an existing encrypted copy or a file someone already decrypted. New recipients require a newly encrypted copy of the original document. Filenames and sizes are not concealed from storage providers.

## Run from PowerShell

From this directory:

```powershell
py -3 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe app.py
```

Or use `powershell -NoProfile -ExecutionPolicy Bypass -File .\run.ps1` for automatic source setup. `run.ps1 -Python C:\path\to\python.exe` runs an already prepared environment without installing dependencies.

For an isolated test profile, the app accepts optional `--data-dir PATH`, `--gpg-home PATH`, and `--gpg-path PATH` arguments. `--no-key-refresh` starts without the automatic initial key listing. Normal launches should omit these arguments so the app shares Kleopatra's default keyring. A custom GnuPG home uses a different keyring and may not match the Kleopatra instance launched normally.

## Build a Windows package

Build on 64-bit Windows with the same Python environment:

```powershell
.\.venv\Scripts\python.exe -m pip install -r requirements-build.txt
powershell -NoProfile -ExecutionPolicy Bypass -File .\build.ps1
```

The executable is `dist\CipherDesk\CipherDesk.exe`. Distribute the **whole** `dist\CipherDesk` folder, not the `.exe` alone. Gpg4win is a separate prerequisite and is not bundled. The generated application is unsigned; internal deployment may require your organization's signing and distribution process. Build scratch files default to the Windows temporary directory. `build.ps1` also accepts `-Python`, `-DistPath`, and `-WorkPath`. Keep the supplied `CipherDesk.spec`: it prevents unrelated ICU libraries from a build machine's Python distribution from shadowing the Windows ICU required by Qt.

## PoC limits

This is a focused local prototype. It has not had an independent security review. It provides no shared contact directory, organization-wide policy, recovery service, access revocation, upload confirmation, audit service, secure deletion, document preview, or Office coauthoring. Recipients' computers, private-key backups, working copies, and editor temporary files still need appropriate protection. Validate it with sample documents and test keys before using it for sensitive material.
