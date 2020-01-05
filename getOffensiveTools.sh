#!/bin/bash

# enumeration 
echo "> Getting Gobuster.."
apt install gobuster -y
if (command -v gobuster 1>/dev/null)
then echo "+ Gobuster installed at $(which gobuster)"

# privesc
echo "> Getting windows-privesc-check2.exe..."
wget https://github.com/pentestmonkey/windows-privesc-check/raw/master/windows-privesc-check2.exe -O wpc2.exe
if (file wpc2.exe 1>/dev/null)
then echo "+ windows-privesc-check2 downloaded as wpc2.exe"

echo "> Getting PowerUp.ps1..." 
wget https://raw.githubusercontent.com/EmpireProject/Empire/master/data/module_source/privesc/PowerUp.ps1
if (file PowerUp.ps1 1>/dev/null)
then echo "+ PowerUp.ps1 downloaded"
