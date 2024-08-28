#!/usr/bin/python
# -*- coding: utf-8 -*-
"""
#*********************************************************************
# Ericsson Radio Systems AB                                     SCRIPT
#*********************************************************************
#
#
# (c) Ericsson Radio Systems AB 2023 - All rights reserved.
#
# The copyright to the computer program(s) herein is the property
# of Ericsson Radio Systems AB, Sweden. The programs may be used
# and/or copied only with the written permission from Ericsson Radio
# Systems AB or in accordance with the terms and conditions stipulated
# in the agreement/contract under which the program(s) have been
# supplied.
#
# ********************************************************************
# Name      :security_logcollector.py
# Purpose   :Logs to be provided for given date.
# Author    :ZKATSHR
# Reason    :EQEV-114297
# Revision  : A
# ********************************************************************
"""
import os
import re
import subprocess
import logging
import sys
import time
from datetime import datetime


try:
    if len(sys.argv) != 2:
        sys.exit(1)

    INPUT_DATE = sys.argv[1]
    DATE_FORMAT_CHANGE = datetime.strptime(INPUT_DATE, '%d%m%Y')
except (IOError, RuntimeError, AttributeError, TypeError, ValueError):
    print "\nPlease enter a date in the correct format (DDMMYYYY).\n"
    exit(1)

def calling_functions():
    """This function will call all the functions"""
    check_secure_log()
    if check_size() == 0:
        audit_log()
        fetch_zipfile()
        combine_output()
        clearing_copiedfile()
    else:
        logging.info("/tmp directory has reached the maximum size. Please check \
and take appropriate action\n")

def check_size():
    """This function checks the size of /tmp"""
    threshold = 4100000000
    return_value = 0
    size = subprocess.check_output("du -sb /tmp", shell=True, stderr=subprocess.PIPE).split()
    size = int(size[0])
    if size >= threshold:
        return_value = return_value+1
    return return_value

def check_secure_log():
    """This fucntion fetches the logs from secure file for required datestamp"""
    try:
        secure_log = DATE_FORMAT_CHANGE.strftime('%b %d').lstrip('0').replace(' 0', '  ')

        secure_command = "cat /var/log/secure | grep '{secure_log}' > /tmp/secure_{INPUT_DATE}.txt"\
.format(secure_log=secure_log, INPUT_DATE=INPUT_DATE)

        subprocess.check_output(secure_command, shell=True, stderr=subprocess.PIPE)
        logging.info("Secure logs are there for particular date stamp\n")
    except subprocess.CalledProcessError:
        logging.info("Secure logs are not there for particular date stamp\n")
    except ValueError:
        logging.info("Please enter a date in the correct format (DDMMYYYY)\n")

def audit_log():
    """This function fetches the logs from audit files for required datestamp"""
    try:
        raw_audit_date = DATE_FORMAT_CHANGE.strftime("%s")[:-5]
        date_stamp = int(raw_audit_date)
        date_stamp = date_stamp+1
        audit_date_stamp = str(date_stamp)
        audit_command = "grep -e " + raw_audit_date + " -e " +audit_date_stamp+ " -r  /var/\
log/audit > /tmp/audit_log.txt"
        subprocess.check_output(audit_command, shell=True, stderr=subprocess.PIPE)
        logging.info("Audit logs are there for particular date stamp\n")
    except subprocess.CalledProcessError:
        logging.info("Audit logs are not there for particular date stamp\n")

def fetch_zipfile():
    """This function fetches the zipped file for required datestamp and unzip the zip file"""
    try:
        formatted_date = DATE_FORMAT_CHANGE.strftime('%Y%m%d')
        pattern = re.compile(r"auditLog-(\d{8})-\d{6}-(\d{8})-\d{6}\.zip")
        for filename in os.listdir("/var/log/audit"):
            match = pattern.match(filename)
            if match:
                start_date_str, end_date_str = match.groups()
                start_date = datetime.strptime(start_date_str, '%Y%m%d')
                end_date = datetime.strptime(end_date_str, '%Y%m%d')
                if start_date <= datetime.strptime(formatted_date, "%Y%m%d") <= end_date:
                    zip_path = os.path.join("/var/log/audit", filename)
                    zip_command = "unzip {filename} -d /tmp\
/audit_unzipfile".format(filename=zip_path)
                    subprocess.check_output(zip_command, shell=True, stderr=subprocess.PIPE)
                    logging.info("Audit logs unzipped for particular date stamp\n")
                    fetch_logs_zipfile()
    except subprocess.CalledProcessError:
        logging.info("Audit logs are not unzipped for particular date stamp\n")

def fetch_logs_zipfile():
    """This function fetching the audit logs from unzipped files"""
    try:
        raw_date = DATE_FORMAT_CHANGE.strftime("%s")[:-5]
        date_stamp = int(raw_date)
        date_stamp = date_stamp+1
        date_stamp = str(date_stamp)
        command = "grep -e " + raw_date + " -e " +date_stamp + " -r  /tmp/audit_unzipfile/\
var/log/audit > /tmp/audit_zip.txt"
        subprocess.check_output(command, shell=True, stderr=subprocess.PIPE)
        logging.info("Zipped audit logs are there for particular date stamp\n")
    except subprocess.CalledProcessError:
        logging.info("Zipped audit logs are not there for particular date stamp\n")

def combine_output():
    """This function will combine the audit_zip file and audit log output"""
    directory_path  = "/tmp"
    fileone = 'audit_log.txt'
    filetwo = 'audit_zip.txt'
    file_path = os.path.join(directory_path, fileone)
    file_pathtwo = os.path.join(directory_path, filetwo)
    if os.path.exists(file_path) and os.path.exists(file_pathtwo):

        copy = "cat /tmp/audit_log.txt >> /tmp/audit_{INPUT_DATE}.txt".format(INPUT_DATE=INPUT_DATE)
        copyone = "cat /tmp/audit_zip.txt >> /tmp/audit_{INPUT_DATE}.txt".format(INPUT_DATE=INPUT_DATE)
        subprocess.check_output(copy, shell=True, stderr=subprocess.PIPE)
        subprocess.check_output(copyone, shell=True, stderr=subprocess.PIPE)
    elif os.path.exists(file_path):
        copy = "cat /tmp/audit_log.txt >> /tmp/audit_{INPUT_DATE}.txt".format(INPUT_DATE=INPUT_DATE)
        subprocess.check_output(copy, shell=True, stderr=subprocess.PIPE)
    elif os.path.exists(file_pathtwo):
        copyone = "cat /tmp/audit_zip.txt >> /tmp/audit_{INPUT_DATE}.txt".format(INPUT_DATE=INPUT_DATE)

        subprocess.check_output(copyone, shell=True, stderr=subprocess.PIPE)
    else:
        logging.info("Output files are not there\n")

def clearing_copiedfile():
    """This function will cpoy the clear two audit files"""
    directory_path  = "/tmp"
    file_one = 'audit_log.txt'
    file_two = 'audit_zip.txt'
    file_path_one = os.path.join(directory_path, file_one)
    file_path_two = os.path.join(directory_path, file_two)
    if os.path.exists(file_path_one) and os.path.exists(file_path_two):
        os.system("rm -rf /tmp/audit_log.txt")
        os.system("rm -rf /tmp/audit_zip.txt")
        os.system("rm -rf /tmp/audit_unzipfile")
    elif os.path.exists(file_path_one):
        os.system("rm -rf /tmp/audit_log.txt")
    elif os.path.exists(file_path_two):
        os.system("rm -rf /tmp/audit_zip.txt")
        os.system("rm -rf /tmp/audit_unzipfile")

if __name__ == '__main__':
    TIMESTR = time.strftime("%Y%m%d-%H%M%S")
    FNAME = TIMESTR + '_security_logcollector.log'
    os.system("mkdir -p /ericsson/security/log/dcglogs")
    FORMAT_STRING = '%(levelname)s: %(asctime)s: %(message)s'
    logging.basicConfig(level=logging.DEBUG,
                        filename="/ericsson/security/log/dcglogs/%s" % FNAME,
                        format=FORMAT_STRING)
    calling_functions()