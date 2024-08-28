#!/usr/bin/bash

EXPECT=/usr/bin/expect

$EXPECT <<EOF
 spawn passwd test
 expect -re "password:"
 expect -re "password:"
expect eof


EOF

