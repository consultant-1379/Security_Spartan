#!/usr/bin/python
"""
# ********************************************************************
# Ericsson Radio Systems AB                                     SCRIPT
# ********************************************************************
#
#
# (c) Ericsson Radio Systems AB 2019 - All rights reserved.
#
# The copyright to the computer program(s) herein is the property
# of Ericsson Radio Systems AB, Sweden. The programs may be used
# and/or copied only with the written permission from Ericsson Radio
# Systems AB or in accordance with the terms and conditions stipulated
# in the agreement/contract under which the program(s) have been
# supplied.
#
# ********************************************************************
# Name      : add_cipher.py
# Purpose   : This script configures sshd to use Specific Secure
#               Ciphers and algorithms.
# Revision  : B
# Reason    : EQEV-90266
# ********************************************************************
"""

import subprocess
import os
import time
import logging
import getpass

from sentinel_hardening import log_func
from Verify_NH_Config import configure_nh
from NH_Backup import backup_files
from user_verification import user_verification

ciphers_list=['aes256-ctr','aes192-ctr','aes128-ctr','chacha20-poly1305@openssh.com',\
'aes256-gcm@openssh.com','aes128-gcm@openssh.com']
macs_list=['hmac-sha2-512','hmac-sha2-256','hmac-sha2-512-etm@openssh.com',\
'hmac-sha2-256-etm@openssh.com']

ssh_file_path='/etc/ssh/ssh_config'
sshd_file_path='/etc/ssh/sshd_config'

mac_algorithms='MACs hmac-sha2-512,hmac-sha2-256,hmac-sha2-512-etm@openssh.com,\
hmac-sha2-256-etm@openssh.com\n'
cipher_algorithms='Ciphers aes256-ctr,aes192-ctr,aes128-ctr,\
chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com\n'

def append_algo(append_list,config_file,algo):
    if config_file==sshd_file_path:
        with open(config_file, 'r') as fin:
            data = fin.readlines()
            for i in data:
                if i == '# Ciphers and keying\n':
                    a1 = data.index(i)
            append_string = ','.join(append_list)
            if algo == 'Ciphers':
                data1 = data[a1+1].split('\n')
                s=data1[0]+','+append_string+'\n'
                data[a1+1]=s
            elif algo == 'MACs':
                data1 = data[a1+2].split('\n')
                s=data1[0]+','+append_string+'\n'
                data[a1+2]=s

            with open(config_file, 'w') as fout:
                fout.writelines(data)
    elif config_file==ssh_file_path:
        with open(config_file, 'r') as fin:
            data = fin.readlines()
            for i in data:
                if i == '#   Cipher 3des\n':
                    a2 = data.index(i)
            append_string = ','.join(append_list)
            if algo == 'Ciphers':
                data1 = data[a2+1].split('\n')
                s=data1[0]+','+append_string+'\n'
                data[a2+1]=s
            elif algo == 'MACs':
                data1 = data[a2+2].split('\n')
                s=data1[0]+','+append_string+'\n'
                data[a2+2]=s

            with open(config_file, 'w') as fout:
                fout.writelines(data)

def check_config_file(list1,algo_list,config_file,algo):
    flag=0
    if list1!=algo_list:
        flag=1
        temp_list=set(list1).difference(set(algo_list))
        if set(list1)==set(algo_list):
            flag=1
            logging.info("Recomended "+algo+" algorithms with different order")
        else:
            append_algo(list(temp_list),config_file,algo)
    return flag

def custom_scenario(config_file,algo):
    flag = 0
    with open(config_file, 'r') as fin:
        data = fin.read().split('\n')
    for i in data:
        if algo in i:
            data1=i.split()
            if data1[0] == algo:
                algo_list = data1[1].split(',')
                if algo == 'Ciphers':
                    flag = check_config_file(ciphers_list,algo_list,config_file,algo)
                elif algo == 'MACs':
                    flag = check_config_file(macs_list,algo_list,config_file,algo)
    return flag

#------------------------------------------------------------------------------------
#Adding Cipher
#------------------------------------------------------------------------------------
def add_cipher():
    """ This script adds the required set of strong ciphers and MACs"""

    backup_files(0, [sshd_file_path, ssh_file_path])
    try:
        with open(sshd_file_path, 'r') as fin:
            data = fin.readlines()
            for i in data:
                if i == '# Ciphers and keying\n':
                    a = data.index(i)

            if custom_scenario(sshd_file_path,'Ciphers')==1:
                print "Customized ciphers are found in SSHD config file\n"
                logging.info('Ciphers are customized in SSHD config file')
            else:
                if data[a+1] == cipher_algorithms:
                    print '\n*********Strong ciphers are already enforced in the server*********\n'
                    logging.info('Strong ciphers are already enforced in the server!')
                else:
                    data.insert(a+1, cipher_algorithms)
                    print "\n**********Successfully enforced strong ciphers for SSH server \
-communication on the server**********\n"
                    logging.info('Successfully enforced strong ciphers in the server')

            if custom_scenario(sshd_file_path,'MACs')==1:
                print "Customized MACs are found in SSHD config file\n"
                logging.info('MAcs are customized in SSHD config file')
            else:
                if data[a+2] == 'MACs hmac-sha2-512,hmac-sha2-256,hmac-sha2-512-etm@openssh.com,\
hmac-sha2-256-etm@openssh.com\n':
                    print '\n**********MACs are already enforced in the server!**********\n'
                    logging.info('MACs are already enforced in the server!')
                elif data[a+2] == 'MACs hmac-sha2-512,hmac-sha2-256,hmac-sha2-512-etm@openssh.com,\
hmac-sha2-256-etm@openssh.com,umac-128-etm@openssh.com,umac-128@openssh.com\n':
                    data[a+2] = data[a+2].replace("MACs hmac-sha2-512,hmac-sha2-256,\
hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,umac-128-etm@openssh.com,\
umac-128@openssh.com\n", "MACs hmac-sha2-512,hmac-sha2-256,hmac-sha2-512-etm@openssh.com,\
hmac-sha2-256-etm@openssh.com\n")
                    print "\n**********Successfully enforced strong MAC for SSH server \
communication on the server**********\n"
                    logging.info('Successfully enforced MACs in the server')
                else:
                    data.insert(a+2, mac_algorithms)
                    print "\n**********Successfully enforced strong MAC for SSH server \
communication on the server**********\n"
                    logging.info('Successfully enforced strong MACs in the server')

                with open(sshd_file_path, 'w') as fin:
                    fin.writelines(''.join(data))

        with open(ssh_file_path, 'r') as fout:
            data1 = fout.readlines()

            for i in data1:
                if i == '#   Cipher 3des\n':
                    a = data1.index(i)
            if custom_scenario(ssh_file_path,'Ciphers')==1:
                print "Customized ciphers are found in SSH config file\n"
                logging.info('Ciphers are customized in SSH config file')
            else:
                if data1[a+1] == cipher_algorithms:
                    print '\n**********Strong ciphers are already enforced for client \
communication**********\n'
                    logging.info('Strong ciphers are already enforced for the client!')
                else:
                    data1.insert(a+1, cipher_algorithms)
                    print "\n**********Successfully enforced strong ciphers for SSH client \
communication on the server**********\n"
                    logging.info('Successfully enforced strong ciphers for the client')

            if custom_scenario(ssh_file_path,'MACs')==1:
                print "Customized MACs are found in SSH config file\n"
                logging.info('MACs are customized in SSH config file')
            else:
                if data1[a+2] == mac_algorithms:
                    print '\n**********MACs are already enforced for the client!**********\n'
                    logging.info('MACs are enforced for the client!')
                elif data1[a+2] == 'MACs hmac-sha2-512,hmac-sha2-256,hmac-sha2-512-etm@openssh.com,\
hmac-sha2-256-etm@openssh.com,umac-128-etm@openssh.com,umac-128@openssh.com\n':
                    data1[a+2] = data1[a+2].replace("MACs hmac-sha2-512,hmac-sha2-256,\
hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,umac-128-etm@openssh.com,\
umac-128@openssh.com\n", "MACs hmac-sha2-512,hmac-sha2-256,hmac-sha2-512-etm@openssh.com,\
hmac-sha2-256-etm@openssh.com\n")
                    print "\n**********Successfully enforced strong MAC for SSH client \
communication on the server**********\n"
                    logging.info('Successfully enforced strong MACs in the server')
                else:
                    data1.insert(a+2, mac_algorithms)
                    print "\n**********Successfully enforced strong MAC for SSH client \
communication on the server**********\n"
                    logging.info('Successfully enforced MACs for the client')

                with open(ssh_file_path, 'w') as fout:
                    fout.writelines(''.join(data1))

        print "\nRestarting sshd service...\n"
        logging.info('Restarting sshd service...')
        os.system("systemctl restart sshd")
    except (IOError, RuntimeError, TypeError):
        logging.error('Script exited abnormally')
        log_func(SCRIPT_NAME, 1, LOG_PATH)

if __name__ == '__main__':
    user_verification()
    TIMESTR = time.strftime("%Y%m%d-%H%M%S")
    FNAME = TIMESTR + '_add_cipher.log'
    os.system("mkdir -p /ericsson/security/log/Apply_NH_Logs/Manual_Exec/")

    FORMAT_STRING = '%(levelname)s: %(asctime)s: %(message)s'
    logging.basicConfig(level=logging.DEBUG,
                        filename="/ericsson/security/log/Apply_NH_Logs/Manual_Exec/%s" % FNAME,
                        format=FORMAT_STRING)
    LOG_PATH = "/ericsson/security/log/Apply_NH_Logs/Manual_Exec/%s" % FNAME
    SCRIPT_NAME = 'add_cipher.py'
    log_func(SCRIPT_NAME, 0, LOG_PATH)
    print "\n\033[93mVerifying the security settings...\033[00m\n"
    configure_nh()
    STATUS = subprocess.check_output("echo $?", shell=True)
    if STATUS == '0\n':
        print "\n\x1b[32mSuccessfully verified the security settings\x1b[0m\n"
        add_cipher()
    else:
        print "Failed to verify the security settings. \
Execute /ericsson/security/bin/Verify_NH_Config.py to verify the same.\n"
    log_func(SCRIPT_NAME, 1, LOG_PATH)
