## Challenge name: Brute It


<img width="1454" height="184" alt="image" src="https://github.com/user-attachments/assets/c17f2cbf-e7d8-4b4e-b7ca-c854881bbbad" />
<br>
<br>

```Room Link:``` [https://tryhackme.com/room/bruteit](https://tryhackme.com/room/bruteit)
<br>
<br>

**Let's start by doing recon on target.**
<br><br>
**Port Scanning:** ``` nmap -p- -sSVC 10.49.172.212 -oN sr -v ```

```
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 4b:0e:bf:14:fa:54:b3:5c:44:15:ed:b2:5d:a0:ac:8f (RSA)
|   256 d0:3a:81:55:13:5e:87:0c:e8:52:1e:cf:44:e0:3a:54 (ECDSA)
|_  256 da:ce:79:e0:45:eb:17:25:ef:62:ac:98:f0:cf:bb:04 (ED25519)
80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
|_http-title: Apache2 Ubuntu Default Page: It works
|_http-server-header: Apache/2.4.29 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

```

