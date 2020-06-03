PS1="\[\033[32m\](\[\033[37m\]\u: \[\033[90m\]\w\[\033[32m\])\$\[\033[37m\] "

alias sshp='ssh -o PreferredAuthentications=password -o PubkeyAuthentication=no '
alias scpp='scp -o PreferredAuthentications=password -o PubkeyAuthentication=no '
alias python="python3"

alias urldecode='python3 -c "import sys, urllib.parse as ul; print(ul.unquote_plus(sys.argv[1]))"'
alias urlencode='python3 -c "import sys, urllib.parse as ul; print (ul.quote_plus(sys.argv[1]))"'

hgrep () {
    history | egrep --color=auto --recursive "$@" | egrep --color=auto --recursive -v "hgrep $@"
}

getCert () {
    timeout 3 openssl s_client -showcerts -servername $1 -connect $1:443 <<< "Q" 2> /dev/null | openssl x509 -text -noout | grep DNS | tr ',' '\n' | cut -d ':' -f 2 | sort -fu
}

FindTakeovers() {
  subjack -w $1 -t 100 -timeout 30 -ssl -c ~/subjack/fingerprints.json -v 3 >> Takeovers
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

fix() {
  /etc/init.d/network-manager restart
  echo "nameserver 1.1.1.1" | sudo tee -a /etc/resolv.conf
  echo "nameserver 8.8.8.8" | sudo tee -a /etc/resolv.conf
}

export PATH=$PATH:~/go/bin:~/scripts/Python

RemoveDockerNones() {
  docker images | grep none | awk '{ print $3; }' | xargs docker rmi -f
}

createVenv() {
   python3 -m venv venv
   source venv/bin/activate
   echo $(pwd) > $(python -c "from distutils.sysconfig import get_python_lib; print(get_python_lib())")/path.pth
}
