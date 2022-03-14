#!/bin/bash


#for p in {1..9000}; do(echo > /dev/tcp/192.168.0.100/$p) > /dev/null 2>&1 && echo "$p open"; done

scanner() {
        # If number of args is less than 1 then exit with error code
        target=$1
        if [[ $# -ne 1 ]]
        then
                echo "Invalid number of arguments supplied. Usage: <IP Address>" && exit 1
        else
                # Perform port scan on every available TCP port
                for port in {1..65535}; do(echo > /dev/tcp/$target/$port) > /dev/null 2>&1 && echo "$port open"; done
                #for port in {$2..$3}; do(echo > /dev/tcp/$target/$port) > /dev/null 2>&1 && echo "$port open"; done
        fi
}

# Main IP address with the use of range parameters from beginning to en
scanner $1 
