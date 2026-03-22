---
title: "SCC 2026 Quals Writeup: Forensics Challenges Walkthrough"
date: "2026-03-22"
tags:
    - [CTF]
    - [Writeup]
    - [Security]
bookmark: false
---

> **Summary:** This post provides a technical walkthrough of three forensics challenges I authored for the SCC 2026 Qualifiers. It covers the intended solutions for "The Silent Leak" (DNS exfiltration), "Beeper's Revenge" (COM hijacking), and "Vault 126" (App-Bound encryption).

---

## 1. The Silent Leak
**Category:** Forensics
**Difficulty:** Easy
**Points:** 50

### Description
>   A suspicious PCAP file has been recovered from a compromised system. Something is quietly slipping through the network traffic. Find it and retrieve the flag.

### Overview
The challenge provides a PCAP file containing a mix of legitimate network traffic and a large volume of DNS queries. The goal is to identify and reconstruct a data exfiltration stream hidden within these DNS requests.

### Identification

Filtering for DNS traffic reveals two primary domains involved in unusual activity:
-   `flag-provider.com`: Contains static or decoy fragments.
-   `system-update.internal`: Contains the actual encoded payload.

The subdomains for system-update.internal follow a structured format: [data_chunk].[hex_index].system-update.internal. For example, a query might appear as `Q1R.00.system-update.internal`.

### Data Reassembly

The primary technical hurdle is that the packets are not captured in chronological order. To successfully reconstruct the payload, the extracted chunks must be sorted by their hexadecimal index (the second level of the subdomain). Simply concatenating the strings as they appear in the capture will result in an invalid Base64 string.

### Solution
```bash
  tshark -r dump.pcap -Y 'dns.flags.response == 0 && dns.qry.name contains "system-update.internal"' -T fields -e dns.qry.name | sort -t '.' -k2 | cut -d '.' -f1 | tr -d '\n' | base64 -d
```

### The Flag
`SCC{pr0mpt_3ngin33r1ng_15_n0t_for3n51c5}`

---

## 2. Beeper's Revenge
**Category:** Forensics
**Difficulty:** Medium
**Points:** 200

### Description
>   System administrators are reporting mysterious audible beep signals coming from the Admin workstation, while File Explorer is showing signs of instability.
>   Although all standard security tools claim the system is clean, a sophisticated "fileless" malware is suspected of manipulating system objects and hiding deep within the system memory.
>   Your task is to analyze the provided memory dump and disk image, locate the phantom module, and reconstruct the flag, which is split into three fragments (Registry, Environment, and Memory).

### Overview
The challenge centers around a COM Hijacking technique. Instead of deploying a standalone executable, the malware resides as a DLL masquerading as a system binary: `IconCache_x64.bin`. By overriding a legitimate COM Class ID (CLSID) in the Current User registry hive, the malware ensures it is loaded by trusted Windows processes whenever specific folder operations occur.
The flag was fragmented into three distinct "shards" across different layers of the Windows OS:

-   **Registry Layer:** A non-standard key within the Explorer advanced settings.
-   **Process Layer:** A specific environment variable injected into the surrogate process.
-   **Memory Layer:** An encrypted shard within the process VAD (Virtual Address Descriptor) space.

### Solution

**1. Process Identification**
Initial triage begins by identifying the active surrogate process. Given the symptoms of audible beeps and PowerShell activity, we list the active processes.
```bash
  vol -f dump.raw windows.pslist
```
![Volatility output](/assets/img/vol1.png)
PID is 9392

**2. Extraction of Shard 1: Registry Analysis**
The first fragment is hidden within the User's Registry hive, specifically under the Explorer folder modes.
```bash
  vol -f dump.raw windows.registry.printkey --key "Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced\FolderMode"
```
![Volatility output](/assets/img/vol2.png)
Result: `InternalID` = `SCC{d34d_`

**3. Extraction of Shard 2: Environment Variables**
The second fragment is stored in the Environment Block of the hijacked process.
```bash
  vol -f dump.raw windows.environ --pid 9392
```
![Volatility output](/assets/img/vol3.png)
Result: `COMPLUS_Version` = `DLLs_t3ll_`
**4. Memory Analysis: Locating Shard 3**
The final shard is stored within a memory-mapped file that does not have a standard .dll extension, making it invisible to basic module listing.
Step A: VAD Enumeration
```bash
  vol -f dump.raw windows.vadinfo --pid 9392 | grep "IconCache_x64.bin"
```
![Volatility output](/assets/img/vol4.png)
Identify the base address of `IconCache_x64.bin` (e.g., `0x7fff0b830000`).
Step B: Memory Region Extraction
```bash
  vol -f dump.raw -o . windows.memmap --pid 9392 --address 0x7fff0b830000 --dump
```
The resulting dump contains the encrypted payload.
**5. Cryptographic Key Recovery (Machine SID)**
Shard 3 is XOR-encrypted using the Machine SID as the cryptographic key. This requires the investigator to recover the SID from the system's security tokens.
```bash
  vol -f dump.raw windows.getsids --pid 9392
```
The key is derived from the base Machine SID (e.g., `S-1-5-21-98682186-3360650230-258948293`).
**6. Final Reconstruction**
By applying the recovered XOR key to the bytes extracted from the VAD space, the final fragment is revealed.
Decrypted Shard 3: `n0_t4l35}`
### The Flag
`SCC{d34d_DLLs_t3ll_n0_t4l35}`

---

## 3. Vault 126
**Category:** Forensics
**Points:** 300
**Difficulty:** Medium

### Description
>   Following an internal audit of the workstation Admin-PC, a selective triage of forensic artifacts was performed to investigate a suspected unauthorized session.
>   Initial analysis suggests that a persistent session state may be preserved within the local environment. However, due to recent security hardening on the host, standard recovery procedures have proven unsuccessful. You are tasked with analyzing the provided filesystem structure to verify the identity of the active session.
>   Known Data:
>- Target User: Admin-PC
>- Known Password: Admin123
>- Environment: Windows 10 
>- Zip Password: forensics

### Overview
This challenge focuses on the modern App-Bound Encryption introduced in recent versions of Google Chrome. Standard DPAPI extraction fails because the `encrypted_key` in the `Local State` file is double-encrypted: first at the machine level (S-1-5-18) and then at the user level.

### Solution

**1. Registry & LSA Secrets**
The process begins by extracting the `DPAPI_SYSTEM` secret from the `SYSTEM` and `SECURITY` registry hives. This secret is necessary to unlock the machine-level MasterKey.
```bash
  mimikatz # lsadump::secrets /system:SYSTEM /security:SECURITY
```
**2. Unlocking the System MasterKey**
Using the machine secret, we derive the MasterKey for the `S-1-5-18` (System) account located in `C:\Windows\System32\Microsoft\Protect\`.
```bash
  mimikatz # dpapi::masterkey /in:"\Windows\System32\Microsoft\Protect\S-1-5-18\User\0f72ee3c-8c78-4522-a588-926ef9f3c512" /system:67e4c0007ac65c240f3278682f97535b835cd55caa4310c984b78b1d5d63640a5fb2bd17ea7f5235
```
SystemKey: `8e266617067c8d324e19d2e145d5a909fd0b1723e85dbf8509ce274aa5955da7fe66f9d86b63fa0a401c2e5cbe58bb813ea5d7419111d037495d5e5fd98eede0`
**3. Unlocking the User MasterKey**
Unlock the user-level encryption using the known password and SID:
```bash
mimikatz # dpapi::masterkey /in:"\Users\Admin-PC\AppData\Roaming\Microsoft\Protect\S-1-5-21-...\a47ee1c4-f671-45d8-b518-83170fa9087b" /sid:S-1-5-21-98682186-3360650230-258948293-1001 /password:Admin123
```
Result: `pbData`: `a5cd29b02511d808a3ebc2c5fb8f9f8545e54fc31a2a559a9611dc1ddb5a4d99`
**4. Decrypting the App-Bound Key (Double DPAPI Pivot)**
With both keys cached, decrypt the `Local State` key blob (ensure the `APPB` header is removed):
**5. Database Decryption**
Use the extracted AES key to decrypt the SQLite `Cookies` database:
```bash
mimikatz # dpapi::chrome /in:"\AppData\Local\Google\Chrome\User Data\Default\Network\Cookies" /masterkey:a5cd29b02511d808a3ebc2c5fb8f9f8545e54fc31a2a559a9611dc1ddb5a4d99
```
**6. Decode the Flag**
Flag is stored in AuthToken Cookie. The decrypted cookie value contains JWT token with the flag embedded in its payload. Decoding the JWT reveals base64-encoded flag fragments, which are then concatenated to reconstruct the final flag.
AuthToken: `eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkFkbWluLVBDIiwicm9sZSI6InN1cGVydXNlciIsImludGVybmFsX2lkIjoiVTBORGUyNHdYMjB3Y2pOZmJURnNhMTltTUhKZmRHZ3pjek5mTTNod01EVXpaRjlqTURCck1UTTFmUT09IiwiaWF0IjoxNTE2MjM5MDI2LCJleHAiOjE4MDUwOTYzMTZ9.w_1pnqEb50fIE4z6GiERzGJbeF3uQ7HRFAm3o2TdOBg`

### The Flag
`SCC{n0_m0r3_m1lk_f0r_th3s3_3xp053d_c00k135}`

---



