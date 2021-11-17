## Initial Enumeration
### Nmap
```
nmap -sS -sC -oN initial_scan.txt {IP}  
nmap -sS -p- -oN all_ports.txt {IP}
``
### Gobuster 
```
gobuster dir -u http://url -w /location/wordlist/file.txt
gobuster vhost -u http://url -w /location/wordlist/file.txt

/usr/share/seclists/Discovery/Web-Content/common.txt
/usr/share/seclists/Discovery/Web-Content/big.txt
/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
```
