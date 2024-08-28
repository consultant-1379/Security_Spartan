#!/usr/bin/bash


if [ "$USER" == root ]; then

EXPECT=/usr/bin/expect
LOGFILE=logfile_gpg1.$(date +%F_%R)

if [ -f /var/tmp/checkfile.txt ]; then
  
  touch /tmp/pid.txt
  touch /tmp/output.txt

  ps -ef | grep gpg > /tmp/pid.txt
  grep -h "gpg-agent" /tmp/pid.txt > /tmp/output.txt
  pid="$(awk '{print $2}' /tmp/output.txt)"
  
  if [ -z "$pid" ]; then
    echo $(date -u) :"No gpg-agent process running"  >>/ericsson/security/log/Apply_NH_Logs/$LOGFILE
  else
    kill -9 $pid | echo $(date -u) : "Current PID :$pid is killed" >> /ericsson/security/log/Apply_NH_Logs/$LOGFILE

  fi
fi

rm -rf /tmp/pid.txt
rm -rf /tmp/output.txt

touch /var/tmp/checkfile.txt
chmod 700 /var/tmp/checkfile.txt
echo "$pid" > /var/tmp/checkfile.txt


if [ -d /root/.gnupg/ ]; then
  rm -rf /root/.gnupg/
  echo $(date -u) : "gpg configpath removed" >> /ericsson/security/log/Apply_NH_Logs/$LOGFILE
  echo " "
fi
	
	##############################################################################################
	##GPG key creation
	##############################################################################################
	echo -e "This Node hardening  process will take few minutes to complete, do not exit or press ctrl+C.\nIn case it breaks in between, Please rerun the Apply_nodehardening.py script again"
    echo ""


      ps -ef | grep /gpgenable.sh > /tmp/pid.txt
      pid="$(awk '{print $2}' /tmp/pid.txt)"
      ppid="$(awk '{print $3}' /tmp/pid.txt)"

	exec 2> /tmp/log.txt
	source /ericsson/security/bin/spinner.sh &
    SPIN_PID=$!
    echo $(date -u) : "Spinner started" >> /ericsson/security/log/Apply_NH_Logs/$LOGFILE
    trap 'kill -9 $SPIN_PID $pid $ppid | echo -e "Script got terminated abnormally\n"' `seq 2 15`  
    echo $(date -u) : "Script got terminated abnormally" >> /ericsson/security/log/Apply_NH_Logs/$LOGFILE   
    echo $(date -u) : "Spinner and process abrupted" >> /ericsson/security/log/Apply_NH_Logs/$LOGFILE
	
	echo $(date -u) : "GPG key creation started" >> /ericsson/security/log/Apply_NH_Logs/$LOGFILE
	$EXPECT <<EOF
        log_user 0
        spawn gpg --gen-key   
        expect -re "Your selection?"
        send "1\r"
        expect -re "What keysize do you want? (2048)"
        send "1024\r"
        expect -re "Key is valid for?"
        send "0\r"
        expect -re "Is this correct? (y/N)"
        send "y\r"
        expect -re "Real name:"
        send "CLEARTEXT\r"
        expect -re "Email address:"
        send "key.dummy@key.com\r"
        expect -re "Comment:"
        send "GPG KEY CREATION FOR CLEARTEXT\r"
        expect -re "Change (N)ame, (C)omment, (E)mail or (O)kay/(Q)uit?"
        send "O\r"
        expect -re "Passphrase" 
        sleep 2
        send "\r"
        sleep 2
        expect -re "<Take this one anyway>"
        send "\r"
        sleep 2
        expect -re "<Take this one anyway>"
        send "\r"
        sleep 2
        expect -re "<Yes, protection is not needed>"
        send "\r"
        sleep 2
        expect -re "Passphrase"
        send "\r"

        set timeout -1

        expect eof

EOF
    if [ -f /root/.gnupg/trustdb.gpg ]; then
    
      echo -e "\nGPG key creation completed"
      echo ""
      echo $(date -u) : "GPG key creation completed" >> /ericsson/security/log/Apply_NH_Logs/$LOGFILE
    fi
	echo $(date -u) : "Encryption script called" >> /ericsson/security/log/Apply_NH_Logs/$LOGFILE
    source /ericsson/security/bin/encrypt.sh
	if [ -f /ericsson/storage/etc/sourcefile.gpg ]; then
            
      echo -e "Encrypted file is available in the path\n"
    fi
    
    rm -rf /tmp/log.txt
    rm -rf /tmp/pid.txt
	chmod 700 /root/.gnupg/ 

else
 
  echo "\"You are not authorized to execute the script, script aborting.."\"
fi
       
   



