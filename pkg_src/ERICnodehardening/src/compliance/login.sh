#!/bin/bash

localhost="localhost"
username="sshtest"
user_pass=$1

/usr/bin/expect << EOF
set timeout 60
spawn ssh -o "StrictHostKeyChecking no" $username@$localhost whoami
expect {
    "*assword:" {
        send "$user_pass\r"
        exp_continue
    }
    timeout {
        puts "Authentication failed. Script timed out."
        exit 1
    }
}
EOF
