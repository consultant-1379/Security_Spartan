#!/usr/bin/bash

LOGFILE=logfile_gpg2.$(date +%F_%R)	
									 
if [ -d /root/.gnupg/ ]; then
	

   if [ -f /root/.gnupg/trustdb.gpg ]; then

      if [ -f /ericsson/storage/etc/sourcefile ]; then

         /usr/bin/gpg --batch --yes --trust-model always -r key.dummy@key.com -e /ericsson/storage/etc/sourcefile
  
         if [ -f /ericsson/storage/etc/sourcefile.gpg ]; then
    
	        echo $(date -u) : "Encryption done" >> /ericsson/security/log/Apply_NH_Logs/$LOGFILE
            rm -rf /ericsson/storage/etc/sourcefile 
         fi
      else
  
         echo $(date -u) : "NOTE:sourcefile does not exist in decrypted format to encrypt" >> /ericsson/security/log/Apply_NH_Logs/$LOGFILE
      fi
      
   else
   
      echo -e " No keys are available to decrypt/GPG key been removed. Check and restore the backed up keys to proceed decryption\n"
   fi
else
																													  

   echo -e "GPG key directory is not available to decrypt, Check and restore the backed up directory to proceed decryption\n"
fi


FOUND=`fgrep -c "rm -rf /ericsson/storage/etc/sourcefile" /ericsson/storage/bin/create_nas_users.sh`
if [ $FOUND -eq 0 ]; then
    echo $(date -u) : "create_nas_users.sh script is modified" >> /ericsson/security/log/Apply_NH_Logs/Apply_NH_Logs/$LOGFILE
    sed -i '/main 2>&1 | tee -a $OUT/ a rm -rf /ericsson/storage/etc/sourcefile' /ericsson/storage/bin/create_nas_users.sh
fi

FOUND=`fgrep -c "rm -rf /ericsson/storage/etc/sourcefile" /ericsson/storage/bin/setup_ssh_FileStore.sh`
if [ $FOUND -eq 0 ]; then
    echo $(date -u) : "setup_ssh_FileStore.sh is modified" >> /ericsson/security/log/Apply_NH_Logs/$LOGFILE
    sed -i '/header_1 Done/ a rm -rf /ericsson/storage/etc/sourcefile' /ericsson/storage/bin/setup_ssh_FileStore.sh
fi

if [ -e  ${*/ericsson/storage/etc/logfile*} ]
then
   mv /ericsson/storage/etc/logfile* /ericsson/security/log/Apply_NH_Logs/
   echo $(date -u) : "logs moved from /ericsson/storage/etc/ to /ericsson/security/log/Apply_NH_Logs " >> /ericsson/security/log/Apply_NH_Logs/$LOGFILE
fi											 
