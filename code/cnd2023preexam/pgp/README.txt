PGP Data check

This directory hotds a test file for you to validate that your key has been loaded on the exam system

Keys have been laoded based on the two calls for key uploads along with a few late uploads due to lost keys

Checking your Key:
=================
The easiest way tyo check is to successfully decrypt the file 
preexamcheck.txt.asc

Cheking if your key was bundled
================================
You can check they keyids that are in the gpg packets using the command:

gpg --list-packet preexamcheck.txt.asc

The will list the individual data packets.  You can use grep to search for your keyID.
If you don’t see the short key ID when running gpg --list-keys, try running gpg --list-keys --keyid-format short instead.


LOST KEYS
=========
If you have lost your key or fogotten the password:
* Mail me your replacement key by 23:59 on Friday 24th November 2023
* The email *must* have the subject: "REPLACEMENT EXAM KEY"

NO FURTHER PROCESSING OF KEYS WILL HAPPEN AFTER THIS DATE.
