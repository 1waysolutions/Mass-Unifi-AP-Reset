# Mass Unifi AP Resetter
Scans specified network and resets all APs found

## Description
I needed a way to reset alot of APs at once, so I built one. It scans the network for Unifi OUIs, trys to SSH in using specified user and pass, then resets. Causes no harm to anything it's not able to log into

## How to use:
Run the python script. It will auto detect OS, Platform, etc, install what it needs, then run. No worry on reqs, software, etc. Currently supports Windows and most Linux distros (sorry mac users :( )

## Requirements
It will install everything listed as needed, but here is what it needs:
Linux & Windows:
```
Python (OFC)
paramiko
scapy
```
Linux Specific:
```
arp-scan
```
Windows Specific:
```
NPCAP (https://npcap.com/dist/npcap-1.80.exe)
```

## Open-source
This project is entirely open source, allowing anyone to modify, update, and distribute it freely.
