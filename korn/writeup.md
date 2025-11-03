# Korn on the cob

Solution tagline: _You rock! So, grab your favorite cat or your friend John and let's get cracking!_

## Description

Oh, no! Both vexillology.net and flagfans.org have been breached and the list of users and password hashes have been leaked on the internet. Can you gain access using those to find the flag?
connection_info:

```shell
nc vexillology.ctf.thelegogroup.com 1337
nc flagfans.ctf.thelegogroup.com 1337
```

### Theme

Crypto

### Hint

- What does a corn say when it's surprised? Ah, shucks!

## Solution

Reading the challenge description, we can safely deduce that this challenge will include password cracking. We can get the CSVs from both dumps, vexillology a.k.a. Vexi and flagfans a.k.a. Flag, and start the analysis.

Vexi sample:

```
Email,MD5_Hashed_Password
pat@zoho.com,9e7a4a23c68ac81f205531a064f0f08e
jane@yahoo.com,0587ca83c9cc05ed7502b76564b9df77
sam8@outlook.com,40d60bb0755c654658ae6c7f92abb6b3
jane@aol.com,a3638b069f3a0f0f834bab8da1d47f2e
john3@aol.com,4dbf2e1e939e7ba72b3c4ba46a64b7f4
```

What we can see is that we have user emails and MD5 hashed passwords. MD5 is not a state-of-the-art algorithm because it is quite easy to attack. We shall use this information later on.

Flag sample:

```
Email,Hashed_Password
jordan@gmail.com,$2b$12$rc4m2/omOFV2igwyLD5J6.m8uayeTH9iCX1QzOvdwFEYJJcq.BDBW
pat@yahoo.com,$2b$12$vKPbnZQ7dwmYESls8ir0qeJQEfvmk921nUrfSgNy9fb9oBbtj5VsG
jordan@zoho.com,$2b$12$QHZbrgkErOhuDbR3LD3qNeoceFgfOO4z1XpJ3UdDDXxGG8.opoj8K
drew0425@aol.com,$2b$12$RA.75IilnFOp6BSCg2IV4ey0PTrBX0BEnzsKvLiJpDpDb.AykIHjq
riley92@zoho.com,$2b$12$8YGid9su80w2YI7hgM7zvuuxMfWi8BcE6PWKlyzticd4UgxQi24a6
```

In this sample, we can see that the passwords are hashed, but it's not clear which algorithm was used. Executing an online search with `$2b$12$rc4m2/omOFV2igwyLD5J6.m8uayeTH9iCX1QzOvdwFEYJJcq.BDBW`, we can see that `bcrypt` is one of the top results. The Wikipedia article confirms this and explains what the `$2b$12$` prefix means.

- `$2b$` - Hashing algorithm identifier - `bcrypt(February 2014 revision)`
- `12` - Rounds/Cost factor - higher number means higher security
- `$` - Separator for the salt and hash

Because `bcrypt` is an industry standard, it will most likely be impossible to crack since it is designed to be computationally expensive. If we try to generate a `bcrypt` hash of the word "test", we get the following outputs on multiple runs of the algorithm:

```
$2a$12$sWYtjh.cVx5WJY5UcYnSX.13kqVhCPyRrLk64f/w0usx3YCKRko2a
$2a$12$M1HsXUwfZR0tWLt2Zg7rkef54Y6wFiAU/M./15.OwU7ZqDFtU8I8O
$2a$12$gYdyDvVsc7U3hsUBuOzVcuSHsbedFVQFBx5pooEw86NXgUipC3drO
```

As we can see, the hashes are different on each subsequent run.

We can now proceed to the cracking part of the challenge. For this part we can use either `hashcat` or `John The Ripper` as they are the most common tools used for this purpose. `hashcat` was chosen as the tool, so the examples will be using it for cracking.

First, we have to change the format of the dumps to be in accordance with files that `hashcat` is able to use. In order to do that, we have to remove the heading, replace the comma with a colon and for good measure, sort the input in ascending order and remove all duplicates.

Vexi refined sample:

```
aaron.connor@protonmail.com:5d41402abc4b2a76b9719d911017c592
adventurous.spirit@gmail.com:5f4dcc3b5aa765d61d8327deb882cf99
alex@gmail.com:2dc66f0cd602e8a8bb778c7081effd44
alex@outlook.com:98ce25ca8a4a36e61d0721c7af93a26d
alex@protonmail.com:75ef6a0fc175b9c33f819b4bb7238e4a
```

Flag refined sample:

```
alex@aol.com:$2b$12$erfH9zshAEvZ3Lr4ghE5E.sN5aAR.IzspIFLOYKIlzi5IvFQyzbnm
alex@gmail.com:$2b$12$mLaViKqxj4e1mq3D9MX8eOwoy3HMYAE.MZj5fHAIht/TM.ifXYey.
alex@hotmail.com:$2b$12$3y40S60HDUbk2uaeVLc5BeXHRnr/YYwKaaD8ixpF4f5zOjlE4GT/6
alex@protonmail.com:$2b$12$3olpKDeZURm70XdSnTFqnuaJzTZNwWRSRp5IeOJee.NLJrm8gAwcO
alex0@outlook.com:$2b$12$i8RPf26zfqaaic5iSs7EluhReEXEQCeqvQH7NQU.iiwK0d08YWpKi
```

Removing the header and replacing the symbols can be done with a basic text editor. Sorting and removing duplicates was done using `sort [old_file] | uniq > [new_file]`. We removed 8 duplicates from Vexi.

Now that we have the files formatted correctly, we can also get a wordlist, that will make our cracking more efficient, since we won't have to brute-force all combinations of letters and numbers, but rather try the most common passwords and see if we are lucky and we can crack some passwords. The most well known list is `rockyou.txt` and with its small size it can give us the necessary help we need.

We can crack the passwords using this command:

```
hashcat -a 0 -m 0 --username vexi_refined_md5.txt rockyou.txt
```

- `-a 0` - attack mode that is used, in this case it's `Straight` which means a dictionary attack
- `-m 0` - hash type of the password hashes, MD5 in our case
- `--username` - specifies that the file is in `username:password` format
- `vexi_refined_md5.txt rockyou.txt` - file with the password hashes and the wordlist

The process should be fairly quick(under 1 min) and once done we can save the results into a file:

```
hashcat --show -m 0 --username vexi_refined_md5.txt -o vexi_cracked.txt
```

Cracked and sorted Vexi results sample:

```
aaron.connor@protonmail.com:5d41402abc4b2a76b9719d911017c592:hello
adventurous.spirit@gmail.com:5f4dcc3b5aa765d61d8327deb882cf99:password
bobby.johnson@yahoo.com:5d41402abc4b2a76b9719d911017c592:hello
bobby.johnson1985@yahoo.com:5d41402abc4b2a76b9719d911017c592:hello
brenda_smith1989@yahoo.com:5d41402abc4b2a76b9719d911017c592:hello
```

The file contains 45 cracked passwords out of the original 194. This is an okay result and we can continue with our efforts. If we find out that this is not enough, we can opt for a different wordlist or a different approach.

Now, we can try cracking the Flag file. Since it's using `bcrypt`, we should see that it should be infeasible.

```
hashcat -a 0 -m 3200 --username flag_refined_bcrypt.txt rockyou.txt
```

We only changed the `-m 3200` to signify the `bcrypt` hash format. Once running, we can get the status and see the estimate completion `Time.Estimated...: Tue Aug  3 16:24:12 2027 (1 year, 272 days)`. Letting this run for a while, the time seems to be increasing, so we can conclude that this strategy is infeasible and cracking this file is not the right approach.

So, let's move on to try and get access to the first server. Here's an AI generated Python program which stuffs the credentials into the Vexi server given the cracked passwords file. Run `pip install pexpect` to get all the necessary packages.

```python
#!/usr/bin/env python3
import sys
import time

import pexpect


def try_credential(username, password):
    HOST = "vexillology.ctf.thelegogroup.com"
    PORT = "1337"
    # Use netcat (nc) to connect
    cmd = f"nc {HOST} {PORT}"

    try:
        # Spawn the netcat process; set encoding to get string output
        child = pexpect.spawn(cmd, timeout=10, encoding="utf-8")

        # Wait for the menu prompt "Enter your choice:" and select "1" for Login
        child.expect("Enter your choice:")
        child.sendline("1")

        # Wait for the "Email:" prompt and send the username
        child.expect("Email:")
        child.sendline(username)

        # Wait for the "Password:" prompt and send the password
        child.expect("Password:")
        child.sendline(password)

        # Wait for either the error message or the next menu prompt
        index = child.expect(
            ["Invalid user and/or pass", "Enter your choice:"], timeout=5
        )
        response = child.before  # capture any text output before the expected match
        child.close()

        if index == 0:
            print(f"[!] {username}:{password} is invalid.")
            return False
        else:
            print(f"[+] {username}:{password} may be valid!")
            print("Response from server:")
            print(response)
            return True

    except Exception as e:
        print(f"[!] Error testing {username}:{password} -> {e}")
        return False


def main():
    if len(sys.argv) < 2:
        print("Usage: {} <creds_file>".format(sys.argv[0]))
        sys.exit(1)

    creds_file = sys.argv[1]

    try:
        with open(creds_file, "r") as f:
            creds = [line.strip() for line in f if line.strip() and ":" in line]
    except Exception as e:
        print(f"Could not open {creds_file}: {e}")
        sys.exit(1)

    for cred in creds:
        username, _, password = cred.split(":", 2)
        print(f"Trying {username}:{password} ...")
        if try_credential(username, password):
            print(f"Success! Valid credentials found: {username}:{password}")
            # If you want to stop after the first valid credential, uncomment the next line:
            # break
        time.sleep(0.5)  # Delay between attempts to avoid overwhelming the server


if __name__ == "__main__":
    main()
```

Running this with `python3 stuff.py vexi_cracked_sorted.txt`, we are able to access 1 specific account belonging to `nicole.perloth@outlook.com` with the password `fluffy`. Browsing around the server, we have a file with the name like `flag.txt`. Reading the contents of the file we get the following:

```
My favorite flags are:
Albania
Pride flag
Wales
Isle of Man
Checkered flag
```

This means we now have the correct credentials for the first server.

Now moving on to the second server. We know that cracking `bcrypt` hash format is nearly impossible, so we have to look for another approach. This is where the hint can be useful.

```
What does a corn say when it's surprised? Ah, shucks!
```

What a seemingly strange thing to say. Trying out a search for `password shucks` we find an interesting article on the topic of `Password Shucking`. This seems like a promising lead.
The article can be summed up as follows:

- password shucking involves the use of an inner and an outer password hashing algorithms, such as `bcrypt(sha1(password))`
- the danger lies in using weak hashing algorithms, such as MD5 and no salting on the password, because it lets the attacker bypass the security of the outer algorithm by knowing what the input to it was, by utilizing the hashed inner value

This process would in our case mean that the Vexi passwords are generated as `md5(password)` and the Flag password would be generated as `bcrypt(md5(password))`. We have access to the MD5 hashed passwords, so we can just pass the value to `bcrypt` and check if it's a valid password.

Here's an AI generated Python program which takes a list of MD5 hashes and tests each one against all available `bcrypt` hashes. Our assumption here could be that because we found a valid login for Vexi, we could just test that specific MD5 hash. However, checking them all is safer, in case the known one isn't the correct one. Run `pip install bcrypt` to get all the necessary packages.

```python
#!/usr/bin/env python3
import sys

import bcrypt


def load_entries(filename):
    """
    Loads a file whose lines are in the format: email:hash
    Returns a list of (email, hash) tuples.
    """
    entries = []
    with open(filename, "r") as file:
        for line in file:
            line = line.strip()
            if not line or ":" not in line:
                continue  # skip empty or malformed lines
            email, hash_val = line.split(":", 1)
            entries.append((email, hash_val))
    return entries


def main(md5_file, bcrypt_file):
    # Load data from both files
    md5_entries = load_entries(md5_file)
    bcrypt_entries = load_entries(bcrypt_file)
    total = len(bcrypt_entries)
    print(f"total number: {total}")
    index = 0

    for bcrypt_email, bcrypt_hash in bcrypt_entries:
        index += 1
        print(f"checking number: {index} with bcrypt email: {bcrypt_email} ")
        for md5_email, md5_hash in md5_entries:
            candidate = md5_hash.encode("utf-8")
            hashed_pw = bcrypt_hash.encode("utf-8")
            # bcrypt.checkpw expects (plaintext, hashed) as bytes.
            if bcrypt.checkpw(candidate, hashed_pw):
                # If the check passes, print both identities on the same line.
                print(
                    f"md5email: {md5_email} owns a password hash that matches the bcryptemail: {bcrypt_email}"
                )


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print(f"Usage: {sys.argv[0]} [md5_file] [bcrypt_file]")
        sys.exit(1)

    md5_file = sys.argv[1]
    bcrypt_file = sys.argv[2]
    main(md5_file, bcrypt_file)
```

Running it with `python3 checker.py vexi_refined_md5.txt flag_refined_bcrypt.txt`, supplying the refined files, we will get an output that looks like the following:

```
...
checking number: 94 with bcrypt email: sam8057@aol.com
checking number: 95 with bcrypt email: shaynetopp@gmail.com
md5email: nicole.perloth@outlook.com owns a password hash that matches the bcryptemail: shaynetopp@gmail.com
checking number: 96 with bcrypt email: taylor@aol.com
checking number: 97 with bcrypt email: taylor@zoho.com
...
```

We can see that `shaynetopp@gmail.com`'s password on Flag is the same as `nicole.perloth@outlook.com`'s password on Vexi.

Logging into the Flag server, using `shaynetopp@gmail.com` as the email and `nicole.perloth@outlook.com`'s password `fluffy`(at least how we remember it, it could also have been Nicole's MD5 hash) we are able to log in. Then it's just a matter of reading the contents of the `flag.txt` file which contains the flag.
