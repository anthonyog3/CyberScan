# CyberScan

A defensive, educational antivirus prototype written in Python for Windows 11.

## Features
- Recursive file and folder scanning
- SHA-256 hashing
- Local known-hash detection database
- Safe static suspicious-file rules
- Transparent risk scoring
- Quarantine and restore
- Scan logging and history
- Simple Windows-friendly GUI

## Safety
This project does not execute suspicious files, create malware, disable security software, or attempt to evade antivirus products. It uses static analysis only.

This is an educational prototype and is not a replacement for Windows Defender or commercial antivirus software.

## Setup

```powershell
py -m pip install -r requirements.txt
py main.py
```

## Testing

```powershell
py -m unittest discover tests
```

The included tests use harmless temporary files.
