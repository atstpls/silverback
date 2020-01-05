#!/bin/bash

verify_command(){
if ! command -v $1 > /dev/null 
then
	echo "- $1 not installed"
else 
  echo " + $1" 
fi
}

verify_file(){
if ! file $1 > /dev/null 
then
	echo "- $1 not downloaded"
else 
  echo " + $1" 
fi
}

grab(){
   FILENAME=echo $2 | rev | cut -d '/' -f 1 | rev
   wget -q $2 -O "$1/$FILENAME"
   verify_file "$1/$FILENAME"
}

# recon
printf "\n[Recon]\n"
mkdir recon

if ! command -v gobuster > /dev/null
then  
    apt -qq install gobuster -y 
    verify_command gobuster
else
    verify_command gobuster
fi

grab recon https://raw.githubusercontent.com/atstpls/silverback/master/scanTarget.sh

# privesc
printf "\n[PrivEsc]\n"
mkdir privesc
grab privesc https://github.com/pentestmonkey/windows-privesc-check/raw/master/windows-privesc-check2.exe
grab privesc https://raw.githubusercontent.com/EmpireProject/Empire/master/data/module_source/privesc/PowerUp.ps
grab privesc https://raw.githubusercontent.com/sleventyeleven/linuxprivchecker/master/linuxprivchecker.py
grab privesc https://raw.githubusercontent.com/rasta-mouse/Sherlock/master/Sherlock.ps1
grab privesc https://github.com/AonCyberLabs/Windows-Exploit-Suggester/blob/master/windows-exploit-suggester.py

# Post-Exploitation
printf "\n[PostExp]\n"
cat << EOF
PoshC2:     curl -sSL https://raw.githubusercontent.com/nettitude/PoshC2/master/Install.sh | bash
Empire:      git clone https://github.com/EmpireProject/Empire.git && sudo ./setup/install.sh
EOF
