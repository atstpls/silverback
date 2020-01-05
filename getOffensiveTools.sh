#!/bin/bash

verify_command(){
if ! command -v $1 > /dev/null 
then
	echo "- $1 not installed"
	exit
else 
  echo " + $1 installed" 
fi
}

verify_file(){
if ! file $1 > /dev/null 
then
	echo "- $1 not installed"
	exit
else 
  echo " + $1 installed" 
fi
}


# enumeration 
apt -qq install gobuster -y
verify_command gobuster

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
