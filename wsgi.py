#!/usr/bin/python3
import sys, os, logging

#to find config and other modules
if(os.path.dirname(__file__) in sys.path):
  pass
else:
  sys.path.insert(0,os.path.dirname(__file__))

import start

def application(environ, start_response):
    status = '200 OK'
    ret=start.do_work(environ)
    response_headers = [('Content-type', 'text/html'),('Content-Length', str(len(b''.join(ret))))]
    start_response(status, response_headers)
    return ret


'''
rtefresh                                                                                                
 cvkj                     
'''
