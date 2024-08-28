#!/usr/bin/python
"""
# ********************************************************************
# Ericsson Radio Systems AB                                     SCRIPT
# ********************************************************************
#
#
# (c) Ericsson Radio Systems AB 2021 - All rights reserved.
#
# The copyright to the computer program(s) herein is the property
# of Ericsson Radio Systems AB, Sweden. The programs may be used
# and/or copied only with the written permission from Ericsson Radio
# Systems AB or in accordance with the terms and conditions stipulated
# in the agreement/contract under which the program(s) have been
# supplied.
#
# ********************************************************************
# Name      : add_keyexchng_algorithm.py
# Purpose   : This script enforces the Strong key Exchange algorithms.
# Reason    : EQEV-92523
# Revision  : A
# ********************************************************************
"""
import subprocess
import time
import logging
import os
import getpass

from sentinel_hardening import log_func
from NH_Backup import backup_files
from Verify_NH_Config import configure_nh
from user_verification import user_verification


keyalgo_list=['curve25519-sha256','curve25519-sha256@libssh.org',\
'diffie-hellman-group14-sha256','diffie-hellman-group16-sha512','diffie-hellman-group18-sha512',\
'ecdh-sha2-nistp521','ecdh-sha2-nistp384','ecdh-sha2-nistp256',\
'diffie-hellman-group-exchange-sha256']

ssh_file_path='/etc/ssh/ssh_config'
sshd_file_path='/etc/ssh/sshd_config'

def append_algo(append_list,config_file):
    if config_file==sshd_file_path:
        with open(config_file, 'r') as fin:
            data = fin.readlines()
            for i in data:
                if 'KexAlgorithms' in i:
                    a1 = data.index(i)
            append_string = ','.join(append_list)
            data1 = data[a1].split('\n')
            s=data1[0]+','+append_string+'\n'
            data[a1]=s

            with open(config_file, 'w') as fout:
                fout.writelines(data)
    elif config_file==ssh_file_path:
        with open(config_file, 'r') as fin:
            data = fin.readlines()
            for i in data:
                if 'KexAlgorithms' in i:
                    a2 = data.index(i)
            append_string = ','.join(append_list)
            data1 = data[a2].split('\n')
            s=data1[0]+','+append_string+'\n'
            data[a2]=s

            with open(config_file, 'w') as fout:
                fout.writelines(data)

def check_config_file(list1,algo_list,config_file):
    flag=0
    if list1!=algo_list:
        flag=1
        temp_list=set(list1).difference(set(algo_list))
        if set(list1)==set(algo_list):
            flag=1
            logging.info("Recomended algorithms with different order")
        else:
            append_algo(list(temp_list),config_file)
    return flag

def custom_scenario(config_file):
    flag=0
    with open(config_file, 'r') as fin:
        data = fin.read().split('\n')
    for i in data:
        if 'KexAlgorithms ' in i:
            data1=i.split()
            if data1[0] == 'KexAlgorithms':
                algo_list = data1[1].split(',')
                flag = check_config_file(keyalgo_list,algo_list,config_file)
    return flag

def add_kex():
    """This function adds the strong Key Exchange Algorithms on server and client."""

    sshd_config_file = '/etc/ssh/sshd_config'
    ssh_config_file = '/etc/ssh/ssh_config'
    backup_files(0, [sshd_config_file, ssh_config_file])
    try:
        sshd_fin = open(sshd_config_file, 'r')
        sshd_filecontent = sshd_fin.read()
        sshd_fin.close()
        kex_algorithms = 'KexAlgorithms curve25519-sha256,curve25519-sha256@libssh.org,\
diffie-hellman-group14-sha256,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512,\
ecdh-sha2-nistp521,ecdh-sha2-nistp384,ecdh-sha2-nistp256,diffie-hellman-group-exchange-sha256\n'


        if custom_scenario(sshd_file_path)==1:
            print "Customized KexAlgorithms are found in SSHD config file\n"
            logging.info('KexAlgorithms are customized in SSHD config file')
        else:
            if sshd_filecontent.find(kex_algorithms) != -1:
                print '\n**********Key Exchange algorithms are already enforced in the \
server!**********\n'
                logging.info('Key Exchange algorithms are already enforced in the server!')
            else:
                sshd_filecontent = sshd_filecontent +"\n"+kex_algorithms
                fout = open(sshd_config_file, 'w')
                fout.write(sshd_filecontent)
                fout.close()

                print "\n**********Successfully enforced strong Key Exchange Algorithms for SSH \
server communication on the server**********\n"
                logging.info('Successfully enforced Key Exchange Algorithms in the server')

        ssh_fin = open(ssh_config_file, 'r')
        ssh_filecontent = ssh_fin.read()
        ssh_fin.close()

        if custom_scenario(ssh_file_path)==1:
            print "Customized KexAlgorithms are found in SSH config file\n"
            logging.info('KexAlgorithms are customized in SSH config file')
        else:
            if ssh_filecontent.find(kex_algorithms) != -1:
                print '\n**********Key Exchange algorithms are already enforced in the \
client!**********\n'
                logging.info('Key Exchange algorithms are already enforced in the client!')
            else:
                ssh_filecontent = ssh_filecontent +"\n"+kex_algorithms
                fout = open(ssh_config_file, 'w')
                fout.write(ssh_filecontent)
                fout.close()

                print "\n**********Successfully added strong Key Exchange Algorithms for SSH \
server communication on the client**********\n"
                logging.info('Successfully enforced Key Exchange Algorithms in the client')

    except IOError:
        logging.error('Script exited abnormally')
        log_func(SCRIPT_NAME, 1, LOG_PATH)

    subprocess.call('systemctl restart sshd', shell=True)

if __name__ == '__main__':
    user_verification()
    TIMESTR = time.strftime("%Y%m%d-%H%M%S")
    FNAME = TIMESTR + 'add_keyexchng_algorithm.log'
    os.system("mkdir -p /ericsson/security/log/Apply_NH_Logs/Manual_Exec/")
    FORMAT_STRING = '%(levelname)s: %(asctime)s: %(message)s'
    logging.basicConfig(level=logging.DEBUG,
                        filename="/ericsson/security/log/Apply_NH_Logs/Manual_Exec/%s" % FNAME,
                        format=FORMAT_STRING)
    LOG_PATH = "/ericsson/security/log/Apply_NH_Logs/Manual_Exec/%s" % FNAME
    SCRIPT_NAME = 'add_keyexchng_algorithm.py'
    log_func(SCRIPT_NAME, 0, LOG_PATH)
    print "\n\033[93mVerifying the security settings...\033[00m\n"
    configure_nh()

    STATUS = subprocess.check_output("echo $?", shell=True)
    if STATUS == '0\n':
        print "\n\x1b[32mSuccessfully verified the security settings\x1b[0m\n"
        add_kex()
    else:
        print "Failed to verify the security settings. \
Execute /ericsson/security/bin/Verify_NH_Config.py to verify the same.\n"
    log_func(SCRIPT_NAME, 1, LOG_PATH)
