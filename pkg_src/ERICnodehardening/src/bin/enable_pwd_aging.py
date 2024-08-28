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
#
# ********************************************************************
# Name      : enable_pwd_aging.py
# Author    : XMEGHHR
# Date      : 23-Aug-2019
# Revision  : A
# Purpose   : Apply aging on root and dcuser based on server type
#	      and user input
# Reason    : EQEV-65788-root & dcuser password expiry
#---------------------------------------------------------------------
# History
"""

import logging
import os
import pwd
import time
import subprocess

from user_verification import user_verification

days_def = " days*****\n"
err_print_msg = "\nScript exited abnormally...!!!"
err_log_msg = "Script exited abnormally"

def aging_root():
    """This function enable aging for root user"""
    print "\n*****Enabling aging for root user*****\n"
    logging.info('Enabling aging for root user')
    age = get_age()
    print "\n*****Enabling aging for root user with ", age, days_def
    logging.info('Enabling aging for root user with %s days' % age)
    warning = get_warning()
    print "\n*****Enabling Number of days for warning message as ", warning, days_def
    logging.info('Enabling Number of days for warning message as %s days' % warning)
    cmd_root = "chage -M " + str(age) + " -W " + str(warning) + " root"
    chage_output_root = os.system(cmd_root + "> /dev/null 2>&1")
    if chage_output_root == 0:
        print '\n*****Successfully Enabled Aging for root user*****\n'
        logging.info('Successfully Enabled Aging for root user')
    else:
        logging.error('Failed to enable Aging for root user')
        print '\n*****Failed to enable Aging for root user*****\n'
        exit(0)

def aging_dcuser():
    """This function enable aging for dcuser"""
    logging.info('Enabling aging for dcuser user')
    age = get_age()
    print "\n*****Enabling aging for dcuser with ", age, days_def
    logging.info('Enabling aging for dcuser with %s days' % age)
    warning = get_warning()
    print "\n*****Enabling Number of days for warning message as ", warning, days_def
    logging.info('Enabling Number of days for warning message as %s days' % warning)
    cmd_dcuser = "chage -M " + str(age) + " -W " + str(warning) + " dcuser"
    chage_output_dcuser = os.system(cmd_dcuser + "> /dev/null 2>&1")
    if chage_output_dcuser == 0:
        logging.info('Successfully Enabled Aging for root user')
        print '\n*****Successfully Enabled Aging for dcuser*****\n'
    else:
        print '\n*****Failed to enable Aging for dcuser*****\n'
        logging.error('Failed to enable Aging for root user')
        exit(0)

def aging_eniqs():
    """This function sets username details for ENIQS" aging"""
    user = get_user()
    if user == "root":
        aging_root()
    elif user == "dcuser":
        print "\n*****Enabling aging for dcuser*****\n"
        check_user()
        aging_dcuser()
    elif user == "both":
        aging_root()
        print "\n*****Enabling aging for dcuser*****\n"
        check_user()
        aging_dcuser()

def check_user():
    """This function check whether dcuser exist"""
    try:
        pwd.getpwnam('dcuser')
    except KeyError:
        print '\ndcuser does not exist...!!!!'
        aging_eniqs()

def get_user():
    """This function to get the username input"""
    try:
        while True:
            try:
                print "Select user for which you  want to enable aging[1,2,3]:"
                print "1.root"
                print "2.dcuser"
                print "3.both"
                print "To quit press q"
                option = raw_input().strip()
            except ValueError:
                print "You have given wrong input, Please give the valid input"
                get_user()
            if option == "q":
                logging.info('operation exited by the user')
                exit(0)
            elif option == "1":
                return "root"
            elif option == "2":
                return "dcuser"
            elif option == "3":
                return "both"
            else:
                print "Please Enter valid Input...!!!"
                logging.info('User Selected Invalid options')
    except (Exception, KeyboardInterrupt, EOFError):
        print err_print_msg
        logging.error(err_log_msg)
        exit(0)

def get_age():
    """This function to get the age input"""
    try:
        while True:
            print '\n'
            age_input = raw_input("Enter Password Age to set Password \
Aging(Recommended & Default is 90) [30,60,90]:")
            if age_input == '30' or age_input == '60' or age_input == '90':
                age = age_input
                return age
            elif age_input == '':
                age = 90
                return age
            else:
                print "Please Enter valid Password Age...!!!"
    except (Exception, KeyboardInterrupt, EOFError):
        print err_print_msg
        logging.error(err_log_msg)
        exit(0)

def get_warning():
    """This function to get the warning input"""
    try:
        while True:
            warning_input = raw_input("Enter Number of days to get warning before password \
expiry (Recommended & Default is 15)[7,15]:")
            if warning_input == '15' or warning_input == '7':
                warning = warning_input
                return warning
            elif warning_input == '':
                warning = 15
                return warning
            else:
                print "\nPlease Enter valid Warning days...!!!\n"
    except (Exception, KeyboardInterrupt, EOFError):
        print err_print_msg
        logging.error(err_log_msg)
        exit(0)

def user_input(server_type, text):
    """This function is to take confirmation to run this script"""
    try:
        proceed = raw_input("Do You still want to apply Password Aging for %s (y/n):?" % text)
        if proceed == "y" or proceed == "Y":
            if server_type == "MWS":
                logging.info('Enabling aging for root user on this MWS server')
                aging_root()
                print disclaimer_mws_end
            elif server_type == "ENIQS":
                print "\n***************Enabling aging for root and dcuser***************\n"
                logging.info('Enabling aging for root and dcuser on this ENIQ server')
                aging_eniqs()
                print disclaimer_eniqs_end
            else:
                print "\nServer not configured either as MWS nor as Eniq. Password Aging will \
not be applied on this server\n"
                logging.error('Server not configured either as MWS nor as Eniq')
                print "Script logs are saved at : /ericsson/security/log/"
                exit(0)
        elif (proceed == 'n') or (proceed == 'N'):
            print"\n"
            exit(0)
        else:
            print "\nYou have entered Invalid Option...!!\n"
            exit(0)
    except (Exception, KeyboardInterrupt, EOFError):
        print err_print_msg
        logging.error(err_log_msg)
        exit(0)

if __name__ == '__main__':
    user_verification()
    timestr = time.strftime("%Y%m%d-%H%M%S")
    fname = timestr + '_enable_password_aging.log'
    os.system("mkdir -p /ericsson/security/log/")

    format_str = '%(levelname)s: %(asctime)s: %(message)s'
    logging.basicConfig(level=logging.DEBUG,
                        filename="/ericsson/security/log/%s" % fname,
                        format=format_str)
    disclaimer_mws = """
###############################################################################
#DISCLAIMER:This script will apply password aging on root user,due to this    #
#password will get expired based on the password aging inputs provided by user#
###############################################################################
"""
    disclaimer_mws_end = """
###################################################################################
#WARNING: Password Aging is appplied on the server, Ensure the root password is   #
#changed prior to the expiry. if not there are critical impacts on the system     #
###################################################################################
"""
    disclaimer_eniqs = """
#################################################################################
#DISCLAIMER:This script will apply password aging on root and dcuser,due to this#
#password will get expired based on the password aging inputs provided by user  #
#################################################################################
"""
    disclaimer_eniqs_end = """
#########################################################################################
#WARNING: Password Aging is appplied on the server, Ensure the root & dcuser password   #
#is changed prior to the expiry. if not there are critical impacts on the system        #
#########################################################################################
"""

    check_mount_point = os.path.ismount("/JUMP")
    mws_insttype_path = os.path.exists("/ericsson/config/inst_type")
    eniq_insttype_path = os.path.exists("/eniq/installation/config/")
    if mws_insttype_path is True:
        mws_insttype = subprocess.check_output("cat /ericsson/config/inst_type", shell=True)
        server_config_name = subprocess.check_output("cat /ericsson/config/ericsson_use_config | \
cut -d'=' -f 2", shell=True)
        server_config_name = server_config_name.replace('\n', '')
        if (check_mount_point is True) and ('rhelonly' in mws_insttype) and \
('mws' in server_config_name):
            print disclaimer_mws
            Servre_Type = "MWS"
            user_input("MWS", "root")
        else:
            print "\nMWS configuration is not complete.Please verify the configuration!\n"
            logging.error('MWS configuration is not complete Verify the configuration!')
            print "Script logs are saved at : /ericsson/security/log/ directory!"
            exit(0)
    elif eniq_insttype_path is True:
        print disclaimer_eniqs
        server_type = "ENIQS"
        user_input("ENIQS", "root and dcuser")
    else:
        print "\nServer not configured either as MWS nor as Eniq\n"
        logging.error('Server not configured either as MWS nor as Eniq')
        print "Script logs are saved at : /ericsson/security/log/ directory!"
        exit(0)
