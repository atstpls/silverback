#!/bin/bash

verify_command(){
if ! command -v $1 > /dev/null 
then
	echo "- $1 not installed"
	exit
else 
  echo " + $1" 
fi
}

verify_file(){
if ! file $1 > /dev/null 
then
	echo "- $1 not downloaded"
	exit
else 
  echo " + $1" 
fi
}


# enumeration 
if ! command -v gobuster > /dev/null
then  apt -qq install gobuster -y && verify_command gobuster
fi

# privesc
wget -q https://github.com/pentestmonkey/windows-privesc-check/raw/master/windows-privesc-check2.exe -O wpc2.exe
verify_file wpc2.exe

wget -q https://raw.githubusercontent.com/EmpireProject/Empire/master/data/module_source/privesc/PowerUp.ps1
verify_file PowerUp.ps1

wget -q https://raw.githubusercontent.com/sleventyeleven/linuxprivchecker/master/linuxprivchecker.py
verify_file linuxprivchecker.py

wget -q https://raw.githubusercontent.com/rasta-mouse/Sherlock/master/Sherlock.ps1
verify_file Sherlock.ps1

wget -q https://github.com/AonCyberLabs/Windows-Exploit-Suggester/blob/master/windows-exploit-suggester.py
verify_file windows-exploit-suggester.py

# shells

# Covenant

# PoshC2
echo "To install PoshC2:    curl -sSL https://raw.githubusercontent.com/nettitude/PoshC2/master/Install.sh | bash"

cat << EOF
- Edit the config file by running posh-config --nano 
- Run the server using posh-server
- Others can view the log using posh-log
- Interact with the implants using the handler, run by using posh
EOF

# CrackMapExec 
cat << EOF
For Ubuntu:
  apt-get install -y libssl-dev libffi-dev python-dev build-essential
  pip install crackmapexec

For Kali:
  apt-get install crackmapexec
EOF



# Elite

# Empire
cat << EOF
git clone https://github.com/EmpireProject/Empire.git
sudo ./setup/install.sh
EOF
