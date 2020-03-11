#!/bin/python3

#####
#  
# My basic attempt at replicating the AutoRecon tool by Tib3rius to help learn Python.
# Reference: https://github.com/Tib3rius/AutoRecon
#
# Starting from a base of the port scanner built in Violent Python.
# Reference: https://www.amazon.com/Violent-Python-Cookbook-Penetration-Engineers/dp/1597499579
#  
#####

import nmap
from colorama import init, Fore
import argparse

def nmap_scan(host, ports):
    nm = nmap.PortScanner()
    nm.scan(hosts=host, ports=ports, arguments='-sT -sV -O -n -T4')

    print("Host Information: " + host)
    for port in nm[host].all_tcp():
        state = nm[host]['tcp'][port]['state']
        name = nm[host]['tcp'][port]['name']
        product = nm[host]['tcp'][port]['product']
        print("[*] tcp/%d %s %s %s" % (port, state, name, product))


def main():
    
    parser = argparse.ArgumentParser(prog="scanner.py", description="Scan a list of ports", \
        usage="python %(prog)s -H <target ip> -p <target port(s)>")

    parser.add_argument("-H", "--host", nargs='?', help="Target host/IP to scan")
    parser.add_argument("-p", "--ports", nargs='?', help="Port range to scan (i.e. 1-999)")
    args = parser.parse_args()
 
    host = args.host
    ports = args.ports

    if host == None or ports == None:
        parser.print_help()
        exit(0)

    nmap_scan(host, str(ports))
    

if __name__ == '__main__':
    init()
    main()
