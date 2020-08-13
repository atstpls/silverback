#!/bin/bash

# is first arg empty?
if [ $1 ];then
  CMD="docker run -it --rm -v $(pwd):/root frolvlad/alpine-python2"

  # is second arg empty?
  if [ -z $2 ];then
    FILE="$1"
    $CMD /root/$FILE
  fi

  # is second arg there?
  if [ $2 ];then
    FILE="$1"
    shift
    MODS="$@"
    $CMD ash -c "pip install $MODS;python /root/$FILE"
  fi

else
  echo "No argument supplied"
fi

}