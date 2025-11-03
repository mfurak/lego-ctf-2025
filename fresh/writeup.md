# Fresh in memory

Solution tagline: _Memory is volatile, so be careful what you are trying to remember._

## Description

We were tasked to perform forensics on a machine.
Strangely, there were no files on the disc.
But what about the memory?

### Theme

Forensics

## Solution

This challenge is about performing an analysis on a memory of a machine. The file `memory.dmp` will be used for this. The first step was finding some tools that could be used for the task. Since the focus is on memory, the search was pointing towards a tool called `volatility3`. This is a Python package that can be installed by running `pip install volatility3`.

Now that we have the tool we can start gathering some information about the memory dump. We will use the following structure for the commands:

```
vol -f memory.dmp [PLUGIN]
```

- `vol` - name of the volatility3 binary
- `-f memory.dmp` - name of the memory dump
- `[PLUGIN]` - name of the plugin that we want to used

First step is to figure out what OS this dump came from. We can run 3 variations of the command which lists the processes on the machine. `vol -f memory.dmp mac.pslist` and `vol -f memory.dmp linux.pslist` don't provide any results, however `vol -f memory.dmp windows.pslist` yields a table of running processes. We can now assume that the dump is from a Windows machine and we confirm it by running the info plugin.

```shell
vol -f memory.dmp windows.info

Volatility 3 Framework 2.26.0
Progress:  100.00               PDB scanning finished
Variable        Value

Kernel Base     0xf8050fe12000
DTB     0x1ad000
Is64Bit True
IsPAE   False
layer_name      0 WindowsIntel32e
memory_layer    1 WindowsCrashDump64Layer
base_layer      2 FileLayer
KdDebuggerDataBlock     0xf80510a12b20
NTBuildLab      19041.1.amd64fre.vb_release.1912
CSDVersion      0
KdVersionBlock  0xf80510a21408
Major/Minor     15.19041
MachineType     34404
KeNumberProcessors      1
SystemTime      2025-09-02 17:40:22+00:00
NtSystemRoot    C:\Windows
NtProductType   NtProductWinNt
NtMajorVersion  10
NtMinorVersion  0
PE MajorOperatingSystemVersion  10
PE MinorOperatingSystemVersion  0
PE Machine      34404
PE TimeDateStamp        Thu Apr 17 15:14:37 2070
```

We can see that it's a Windows 10 machine. This allows us to make some assumptions about what the file system looks like.

Next, we perform a dump of all files on the system and save it to a new file.

```shell
vol -f memory.dmp windows.filescan > files.txt
```

Since we know this is a Windows system we can look for some specific strings contained in the files. Let's try and look for `\Users\` which can give us the name of profile that exists on this machine.

```
...
0x860becf81dd0	\Users\gihop\AppData\Local\Microsoft\OneDrive\25.149.0803.0003\libssl-3-x64.dll
0x860becf820f0	\Windows\Registration\R000000000006.clb
0x860becf82280	\Windows\System32\apphelp.dll
0x860becf82410	\Users\gihop\AppData\Local\Microsoft\OneDrive\25.149.0803.0003\FileSyncCxPImpl.dll
0x860becf825a0	\Windows\System32\samlib.dll
0x860becf82730	\Windows\System32
0x860becf828c0	\Windows\System32\propsys.dll
0x860becf82a50	\Windows\System32\dwmredir.dll
0x860becf83090	\Windows\System32\WindowsCodecs.dll
0x860becf83220	\Users\gihop\AppData\Local\Microsoft\OneDrive\25.149.0803.0003\Qt5WinExtras.dll
0x860becf833b0	\Users\gihop\AppData\Local\Microsoft\OneDrive\25.149.0803.0003\libcrypto-3-x64.dll
0x860becf83540	\Users\gihop\AppData\Local\Microsoft\OneDrive\25.149.0803.0003\WnsClientApi.dll
0x860becf836d0	\Windows\System32\RstrtMgr.dll
...
```

From this we can see that `gihop` is the name of the user. Let's examine if there's any interesting files on the desktop using the search for `gihop\Desktop`. We find one specifically interesting file:

```
...
0x860beec89110	\$Directory
0x860beec892a0	\Users\gihop\Desktop\flag.txt
0x860beec89430	\$Directory
...
```

Since we have the virtual address we can just dump the files using `vol -f memory.dmp windows.dumpfiles --virtaddr 0x860beec892a0`, removing the `.dat` extension and we get a file with the following contents:

```
"learn how to take screenshots"
```

This can tell us that although the flag is not yet there, we are looking for screenshots. We can grab all the files that have the most common extensions used by images `.png, .jpg and .gif`. One specific file is looking suspicious, because it's a PNG that exists within ScreenSketch, a snipping tool from Microsoft. We can get the file `vol -f memory.dmp windows.dumpfiles --virtaddr 0x860bf0c56cd0`. After removing the `.dat` extension, the file is a screenshot.
![screenshot](screenshot.png)
We can see that there are 2 open files in Notepad. The `*Untitled` file contains `c2Npc251cjBGe0ZU00w=`. This is immediately suspicious as a base64 encoded string due to the presence of the equal sign at the end, which is used as padding. Decoding the string yields `scisnur0F{FTCL` which when reversed gives us `LCTF{F0rensics`, the first part of the flag.

The `flag` file is not clearly visible, but we can try and use a different tactic to recover the text. We can use the `strings` utility. This program is able to recover any continuous words, by default longer than 4 letters. We can run this utility on the memory dump and output the strings into a new file by running `strings memory.dmp > strings.txt`. Then we can search for `aHR0cHM` part of the string. Going through the occurences bring us to 2 interesting lines:

```
https://www.bing.com/ck/a?!&&p=7d20121f67c978d80cd1d20e4782deafdb013356a0f4f950d87fe7bc6efaa4ceJmltdHM9MTc1NjY4NDgwMA&ptn=3&ver=2&hsh=4&fclid=02b0e7b0-b2ae-6729-3b37-f1eab3dc66f4&psq=cyberchef&u=a1aHR0cHM6Ly9jeWJlcmNoZWYub3JnLw&ntb=1
https://cyberchef.org/#recipe=To_Base64('A-Za-z0-9%2B/%3D')&input=aHR0cHM6Ly9zaG9ydHVybC5mbS9iS1J5aQ
```

Following the second url brings us to a website and gives us this shortened URL as the input:

```
https://shorturl.fm/bKRyi
```

And following the link, we get `https://www.youtube.com/watch?v=-50NdPawLVY`, which is the video `Crab Rave 10 Hours`. This was a red herring, or rather a red 🦀, a distraction that is supposed to take us away from the task.

Looking back at the picture there is one more interesting notepad. It's the one in the bottom right corner, containing a `To do list:`, but more importantly also a section for `Passwords:`. We can use the words we see to determine what words are in the section that is hidden. Performing a case-sensitive search for `Passwords:` in the `strings.txt` file gives us 3 results with the last one being the most understandable:

```
1b8-4ff0-96fe-ede47de6cf1e
-90985b8ef693 Passwords:
165df38-145f
16-a38b-84087079e4c
9 _1s_always_fun}
6b5ca
```

We can see that the text `_1s_always_fun}` is in the required format for the flag. Putting it together with the first part of the flag, that we found earlier we get the full flag and thus the solution:

```
LCTF{F0rensics_1s_always_fun}
```
