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
   FILENAME=$(echo $2 | rev | cut -d '/' -f 1 | rev)
   wget -q $2 -O "$1/$FILENAME"
   verify_file "$1/$FILENAME"
}

# recon
printf "\n[Recon]\n"
mkdir -p recon

if ! command -v gobuster > /dev/null
then  
    apt -qq install gobuster -y 
    verify_command gobuster
else
    verify_command gobuster
fi

grab recon https://raw.githubusercontent.com/atstpls/silverback/master/scanTarget.sh
chmod +x recon/scanTarget.sh

cd recon 
git clone https://github.com/maurosoria/dirsearch.git
ln -s $(pwd)/dirsearch/dirsearch.py /usr/local/bin/dirsearch.py


# privesc
printf "\n[PrivEsc]\n"
mkdir -p privesc

grab privesc https://github.com/pentestmonkey/windows-privesc-check/raw/master/windows-privesc-check2.exe
# windows-privesc-check2.exe --audit -a -o report

grab privesc https://raw.githubusercontent.com/EmpireProject/Empire/master/data/module_source/privesc/PowerUp.ps1
# Invoke-AllChecks

grab privesc https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh
chmod +x LinEnum.sh

grab privesc https://raw.githubusercontent.com/sleventyeleven/linuxprivchecker/master/linuxprivchecker.py
# python linuxprivchecker.py

grab privesc https://raw.githubusercontent.com/rasta-mouse/Sherlock/master/Sherlock.ps1
# Find-AllVulns

grab privesc https://raw.githubusercontent.com/atstpls/silverback/master/showOneLiners.sh
chmod +x privesc/showOneLiners.sh

grab privesc https://github.com/AonCyberLabs/Windows-Exploit-Suggester/blob/master/windows-exploit-suggester.py
# python windows-exploit-suggester.py -u
# python windows-exploit-suggester.py -d <xls> -i systeminfo.txt

# https://github.com/GhostPack/SharpUp
# SharpUp.exe

# https://github.com/rasta-mouse/Watson
# Watson.exe

# Post-Exploitation
printf "\n[PostExp]\n"

mkdir -p postexp
grab postexp https://raw.githubusercontent.com/samratashok/nishang/master/Antak-WebShell/antak.aspx
grab postexp https://raw.githubusercontent.com/samratashok/nishang/master/Shells/Invoke-PowerShellTcp.ps1


cat << EOF
FOR SILENT TRINITY
git clone https://github.com/byt3bl33d3r/SILENTTRINITY && cd SILENTTRINITY
pip3 install --user pipenv && pipenv install && pipenv shell
python st.py
EOF


cat << EOF
PoshC2:     curl -sSL https://raw.githubusercontent.com/nettitude/PoshC2/master/Install.sh | bash
Empire:      git clone https://github.com/EmpireProject/Empire.git && sudo ./setup/install.sh
EvilWinRm:  gem install evil-winrm
EOF
Pupy:
    git clone --recursive https://github.com/n1nj4sec/pupy
    cd pupy
    pip2.7 install --upgrade pip
    pip2.7 install virtualenv
    ./create-workspace.py pupyws
    export PATH=$PATH:~/.local/bin; pupysh
    pupyws/bin/pupysh
    
printf "Metasploit modules\t\tuse post/multi/recon/local_exploit_suggester\n"
printf "Windows Privesc Check\t\twindows-privesc-check2.exe --audit -a -o report\n"
printf "PowerUp\t\t\t\tInvoke-AllChecks\n"
printf "SharpUp\t\t\t\tSharpUp.exe\n"
printf "Sherlock\t\t\tFind-AllVulns\n"
printf "Watson\t\t\t\tWatson.exe\n"
printf "linuxprivchecker.py\t\tpython linuxprivchecker.py\n"
printf "windows-exploit-suggester.py\tpython windows-exploit-suggester.py -u\n"
printf "\t\t\t\tpython windows-exploit-suggester.py -d <xls> -i systeminfo.txt\n"
