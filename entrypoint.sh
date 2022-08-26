#!/bin/bash

MINIPOT_ENVS=( "DEBUG" "-debug" "OUTPUTDIR" "-outputdir" "ID" "-id" "HOSTNAME" "-hostname" "NETWORKMODE" "-networkmode" "SESSIONTIMEOUT" "-sessiontimeout" "PCAP" "-pcap" "PRIVATEKEY" "-privatekey" "BINDADDRESS" "-bindaddress" )

i=0
for a in ${MINIPOT_ENVS[@]}; do
    x=$(($i%2))
    if [[ $x -eq 0 ]]; then
        if [[ "${!a}" != "" ]]; then
            args+=( "${MINIPOT_ENVS[$i+1]}"="${!a}" )
        fi
    fi
    let i=$i+1
done

/minipot ${args[*]}
