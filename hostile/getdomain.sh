#!/usr/bin/expect -f
set domain [lindex $argv 0]
spawn ruby hostile/sub_brute.rb
expect "domain"
sleep 1
send "$domain\r"
interact
