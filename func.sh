# ~/.profile: executed by the command interpreter for login shells.
# This file is not read by bash(1), if ~/.bash_profile or ~/.bash_login
# exists.
# see /usr/share/doc/bash/examples/startup-files for examples.
# the files are located in the bash-doc package.

# the default umask is set in /etc/profile; for setting the umask
# for ssh logins, install and configure the libpam-umask package.
#umask 022

# if running bash
if [ -n "$BASH_VERSION" ]; then
    # include .bashrc if it exists
    if [ -f "$HOME/.bashrc" ]; then
	. "$HOME/.bashrc"
    fi
fi

# set PATH so it includes user's private bin if it exists
if [ -d "$HOME/bin" ] ; then
    PATH="$HOME/bin:$PATH"
fi

# set PATH so it includes user's private bin if it exists
if [ -d "$HOME/.local/bin" ] ; then
    PATH="$HOME/.local/bin:$PATH"
fi

####################################################
####################################################
####################################################
####################################################
####################################################


# PS1="\[\033[32m\](\[\033[37m\]\u: \[\033[90m\]\w\[\033[32m\])\$\[\033[37m\] "
PS1="\[\033[37m\]\[\033[90m\]\w\[\033[32m\]>\[\033[37m\] "

####################################################
####################################################
####################################################

export TOOLS=$HOME/tools
export GOPATH=$HOME/go
export PATH=$PATH:/usr/local/go/bin:$GOPATH/bin
export PATH=$PATH:$HOME/scripts/Python:$HOME/scripts/Bash


alias sshp='ssh -o PreferredAuthentications=password -o PubkeyAuthentication=no '
alias scpp='scp -o PreferredAuthentications=password -o PubkeyAuthentication=no '
alias python="python3"
alias firefox="firefox --new-window --private-window"
alias urldecode='python3 -c "import sys, urllib.parse as ul; print(ul.unquote_plus(sys.argv[1]))"'
alias urlencode='python3 -c "import sys, urllib.parse as ul; print (ul.quote_plus(sys.argv[1]))"'

export DISPLAY=:0

####################################################
####################################################
####################################################

hgrep () {
    history | egrep --color=auto --recursive "$@" | egrep --color=auto --recursive -v "hgrep $@"
}

getCert () {
    timeout 3 openssl s_client -showcerts -servername $1 -connect $1:443 <<< "Q" 2> /dev/null | openssl x509 -text -noout | grep DNS | tr ',' '\n' | cut -d ':' -f 2 | sort -fu
}

FindTakeovers() {
  subjack -w $1 -t 100 -timeout 30 -ssl -c $TOOLS/subjack/fingerprints.json -v 3 >> Takeovers
}

KillDockers() {
  docker stop $(docker ps -q) | docker rm -f $(docker ps -a -q)
}

CleanGitRepoHistory() {
  echo "Make sure you're in top level of repo, press ENTER"
  read ack
  git checkout --orphan latest_branch
  git add -A
  git commit -am "cleanup"
  git branch -D master
  git branch -m master
  git push -f origin master
}

getResponses() {
  
  [ ! -d headers ] && mkdir headers
  [ ! -d responsebody ] && mkdir responsebody
  CURRENT_PATH=$(pwd)
  
  for x in $(cat $1)
  do
    NAME=$(echo $x | awk -F/ '{print $3}')
    curl -sk -X GET -H "X-Forwarded-For: evil.com" $x -I > "$CURRENT_PATH/headers/$NAME"
    curl -sk -X GET -H "X-Forwarded-For: evil.com" -L $x > "$CURRENT_PATH/responsebody/$NAME"
  done
}

dirsearch() {
   python $TOOLS/dirsearch/dirsearch.py -u $1 -e $2
}

pause(){
  read -s -n 1 -p "Press any key to continue . . ."
  echo
}

RemoveDockerNones() {
  docker images | grep none | awk '{ print $3; }' | xargs docker rmi -f
}

createVenv() {
   python3 -m venv venv
   source venv/bin/activate
   echo $(pwd) > $(python -c "from distutils.sysconfig import get_python_lib; print(get_python_lib())")/path.pth
}

certspotter() {
 sed -e 's/^"//' -e 's/"$//' <<< $(curl -s https://certspotter.com/api/v0/certs\?domain\=$1 | jq '.[].dns_names[]') | sort -u
}

showme(){
  if [ -z "$2" ]
  then
    f=(hosts cnames resolved whois alive notalive)
    for i in "${f[@]}"
    do
      printf "$(cat $1/$i|wc -l)\t$i\n"
    done
  else
    cat $1/$2
  fi
}
