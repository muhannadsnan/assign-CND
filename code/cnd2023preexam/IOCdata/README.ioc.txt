README.txt for IOC Data
CND Nov 2023 Examiantion

The format of the IOC file is:

# Datestamp this should match the filename
DATE
# The hash value here should be used to check the integrity of the validation tools
# /opt/security/bin/validate and /opt/security/bin/strcheck
VALIDATE sha256hash
STRCHECK sha256hash
# IOC  values to check
IOC sha256hash directory
# Strings follow.  These are strings  that may indicate  problems
STR string directory
\end{verbatim}
An example IoC  file is shown below:


An example of this is:
# Datestamp this should match the filename 
20231012
# The hash value here should be used to check the integrity of the validation tools
# /opt/security/bin/validate and /opt/security/bin/strcheck
VALIDATE 5730f0e6112870ca638a21167e670502ef7fd0fffc2d438c0420e5ac63ac4c6e
STRCHECK 73abb4280520053564fd4917286909ba3b054598b32c9cdfaf1d733e0202cc96
# IOC  values to check
IOC de9f83707e8eb38b2028d6f4330f6b5c19a3afac49bb63c7eb8a6ff5e565487a 	/
IOC ac2bec8f1f09a99571924f6f4ff3075348bc8edfa4859d77292ea37d5edf8014	/var/www/uploads
IOC 888e275738cf32583ee1e9bd3c40d753a46352d2e7bd37779cbf578f942be0fb    /var/www
# Strings follow.  These are strings  that may indicate  problems
STR string directory
STR IFZvbHVtZSBpbiBkcml2ZS /var/www
STR PSEXECscv	/data/share/windows
STR "/eval\(|rot13\(/"  /var/www
STR "/r0nin|m0rtix|upl0ad|r57shell|phpshell|void\.ru/"  /var/www


In this directory you will find:
index.html - this is the index.html file served up on the host in the URL provided to the script eg: https://iocserve.int.org/tth
IOC-20231122.ioc - A vaild example IOC file
IOC-20231122.gpg - the detached GPG signature for the above
IOC-20231120.ioc - An invaild example IOC file
IOC-20231121.ioc - An example IOC with an invalid signature
IOC-20231121.gpg - the detached GPG signature for the above
CND Example KEY_0xB230916A_public.asc - the public key of the signign key for validating the IOC files
CND Example KEY_0xB230916A_SECRET.asc  - An example signing key (so you can sign your own variants)
nasty1 - a binary that will  flag an IOC check
nasty2 - a file that will flag a STR check

These signing keys are examples only.  The grading system in the examination will have its own keys already installed.
The IOC files contain the hash values for VALIDATE and STRCHECK, based on a currenlty updated Ubuntu 22.04 LTS server install ( as of 21/11/2023). This can be used to aid in your testing. Alternatley you can modify/create your own IOC files.

5730f0e6112870ca638a21167e670502ef7fd0fffc2d438c0420e5ac63ac4c6e  /usr/bin/sha256sum
73abb4280520053564fd4917286909ba3b054598b32c9cdfaf1d733e0202cc96  /usr/bin/grep

Suggested use of this test data
================================
The easiest way to use this test data is create an appropriate directory on your Apache install webroot, and copy the contents of this directory to that.  You can then pass your script the url eg https://myserver/myti/ as a base url.

Validating DATA
================
Files other than this file can be verified using the data below. This is also contained in the file checksum.sha256

9a526d7470299070c099e7bdcdf38ff3e7d0b9b6d16d3dca84b3be9fae1e1649  CND Example KEY_0xB230916A_public.asc
0a412ae9f2405c6ef2e57229b2c2cd7b698b5c852389dcdc3d3b0af6e9030810  CND Example KEY_0xB230916A_SECRET.asc
9113fea8151506e1230fea20eb6f3f56ef5be584f980cc2bbec596095d863efa  index.html
d8c62f607fc2f46b36b274236ef9a6645e20bc0d9d0487e462ebdc779ff9ba90  IOC-20231120.ioc
cd2acfa05d9681a0ebadb3a902eef606e13c574fd013ab590d4c509ae70a3a9c  IOC-20231121.gpg
05339a95005fca4442ca77c59852977b14b5a56d9182a2c09994de785ad5cad0  IOC-20231121.ioc
dfbff0be503797fe1328c50ece031778ffaf702e76937b1137355c67b1413eee  IOC-20231122.gpg
a3c937c36ec3b58f55cd714e408a7fb6ea530e0b927ba3d840f1b8a8041a7924  IOC-20231122.ioc
78dae33cf64c6bca2c0a4d2390f88e0fa339029cfc6556a5c6aeb165e57f31a7  nasty1
60e25ccc7f5d13d6b6bf7dd6b7ff54b4846ac9d96e3913d46011c7fc6d04f315  nasty2


GPG Verification
================
IOC-20231122.gpg IOC-20231122.ioc
gpg: Signature made Tue 21 Nov 2023 11:36:29 PM SAST
gpg:                using EDDSA key F4009EDE95828DB1C0C88E67EFE2E210B230916A
gpg: Good signature from "CND Example KEY <cndnov23example@stud.noroff.no>" [ultimate]



IOC-20231121.gpg IOC-20231121.ioc
gpg: Signature made Tue 21 Nov 2023 11:36:50 PM SAST
gpg:                using EDDSA key F4009EDE95828DB1C0C88E67EFE2E210B230916A
gpg: BAD signature from "CND Example KEY <cndnov23example@stud.noroff.no>" [ultimate]






































































Setting up trusted GPG import
==============================
You need to add trust otherwise the signature will show as bad


gpg --edit-key F4009EDE95828DB1C0C88E67EFE2E210B230916A
gpg (GnuPG) 2.2.27; Copyright (C) 2021 Free Software Foundation, Inc.
This is free software: you are free to change and redistribute it.
There is NO WARRANTY, to the extent permitted by law.

Secret key is available.

sec  ed25519/EFE2E210B230916A
     created: 2023-11-21  expires: 2026-11-21  usage: SC  
     trust: unknown       validity: unknown
ssb  cv25519/02172CC3C8A2C5D9
     created: 2023-11-21  expires: 2026-11-21  usage: E   
[ unknown] (1). CND Example KEY <cndnov23example@stud.noroff.no>

gpg> trust
sec  ed25519/EFE2E210B230916A
     created: 2023-11-21  expires: 2026-11-21  usage: SC  
     trust: unknown       validity: unknown
ssb  cv25519/02172CC3C8A2C5D9
     created: 2023-11-21  expires: 2026-11-21  usage: E   
[ unknown] (1). CND Example KEY <cndnov23example@stud.noroff.no>

Please decide how far you trust this user to correctly verify other users' keys
(by looking at passports, checking fingerprints from different sources, etc.)

  1 = I don't know or won't say
  2 = I do NOT trust
  3 = I trust marginally
  4 = I trust fully
  5 = I trust ultimately
  m = back to the main menu

Your decision? 5
Do you really want to set this key to ultimate trust? (y/N) y

sec  ed25519/EFE2E210B230916A
     created: 2023-11-21  expires: 2026-11-21  usage: SC  
     trust: ultimate      validity: unknown
ssb  cv25519/02172CC3C8A2C5D9
     created: 2023-11-21  expires: 2026-11-21  usage: E   
[ unknown] (1). CND Example KEY <cndnov23example@stud.noroff.no>
Please note that the shown key validity is not necessarily correct
unless you restart the program.

gpg> 





