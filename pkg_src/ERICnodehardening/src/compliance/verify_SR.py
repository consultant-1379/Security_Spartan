#!/usr/bin/python
"""This script verifies if source routing has been enabled or not"""
file_name = "/etc/sysctl.conf"
def check_sr_status():
    """This function verifies if source routing has been enabled or not"""
    if 'net.ipv4.conf.all.send_redirects=0' in open(file_name).read() and \
'net.ipv4.conf.default.send_redirects=0' in open(file_name).read() and \
'net.ipv4.conf.all.accept_redirects=0' in open(file_name).read() and \
'net.ipv4.conf.default.accept_redirects=0' in open(file_name).read() and \
'net.ipv4.conf.all.accept_source_route=0' in open(file_name).read() and \
'net.ipv4.conf.default.accept_source_route=0' in open(file_name).read() and \
'net.ipv6.conf.all.accept_source_route=0' in open(file_name).read() and \
'net.ipv6.conf.default.accept_source_route=0' in open(file_name).read() and \
'net.ipv6.conf.all.accept_redirects=0' in open(file_name).read() and \
'net.ipv6.conf.default.accept_redirects=0' in open(file_name).read():
        return "COMPLIANT"
    else:
        return "NON-COMPLIANT:  EXECUTE 'disable_SR.py' TO MAKE IT COMPLIANT"
if __name__ == '__main__':
    check_sr_status()
