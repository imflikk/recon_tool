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
import os

output_dir = os.path.join(os.getcwd(), r'scan_results')

services = {
    'http':80,
    'https':443,
    'smb':445,
    'ftp':21,
    'ssh':22,
    'rdp':3389
}

http_commands = {
    'nmap':'nmap -p80 -sT -n --script="banner,(http* or ssl*) and not (brute or broadcast or dos or external or fuzzer)" %s',
    'nikto':'nikto -h %s',
    'gobuster':'gobuster dir -u http://%s -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt'
}

https_commands = {
    'nmap':'nmap -p443 -sT -n --script="banner,(https* or ssl*) and not (brute or broadcast or dos or external or fuzzer)" %s',
    'nikto':'nikto -h %s',
    'gobuster':'gobuster dir -u http://%s -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -k'
}

smb_commands = {
    'nmap':'nmap -p445 -sT -n --script="banner,(nbtstat or smb* or ssl*) and not (brute or broadcast or dos or external or fuzzer)" %s',
    'smbmap':'smbmap -H %s',
    'smbclient':'smbclient -U "" -N -L \\%s'
}

ftp_commands = {
    'nmap':'nmap -p21 -sT -n --script="banner,(ftp*) and not (brute or broadcast or dos or external or fuzzer)" %s'
}

ssh_commands = {
    'nmap':'nmap -p22 -sT -n --script="banner,(ssh* or ssl*) and not (brute or broadcast or dos or external or fuzzer)" %s'
}

rdp_commands = {
    'nmap':'nmap -p3389 -sT -n --script="banner,(rdp* or ssl*) and not (brute or broadcast or dos or external or fuzzer)" %s'
}

open_ports = []

def check_service(host, open_port):

    for service,port in services.items():
        if port == open_port:
            if port == 80:
                print(Fore.CYAN + "Potentially useful commands: " + Fore.RESET)
                for app,command in http_commands.items():
                    print("\t" + Fore.CYAN + app + Fore.RESET + ": '" + command % host + "'")
            elif port == 443:
                print(Fore.CYAN + "Potentially useful commands: " + Fore.RESET)
                for app,command in https_commands.items():
                    print("\t" + Fore.CYAN + app + Fore.RESET + ": '" + command % host + "'")
            elif port == 445:
                print(Fore.CYAN + "Potentially useful commands: " + Fore.RESET)
                for app,command in smb_commands.items():
                    print("\t" + Fore.CYAN + app + Fore.RESET + ": '" + command % host + "'")
            elif port == 21:
                print(Fore.CYAN + "Potentially useful commands: " + Fore.RESET)
                for app,command in ftp_commands.items():
                    print("\t" + Fore.CYAN + app + Fore.RESET + ": '" + command % host + "'")
            elif port == 22:
                print(Fore.CYAN + "Potentially useful commands: " + Fore.RESET)
                for app,command in ssh_commands.items():
                    print("\t" + Fore.CYAN + app + Fore.RESET + ": '" + command % host + "'")
            elif port == 3389:
                print(Fore.CYAN + "Potentially useful commands: " + Fore.RESET)
                for app,command in rdp_commands.items():
                    print("\t" + Fore.CYAN + app + Fore.RESET + ": '" + command % host + "'")

    print()


def nmap_scan(host, ports):
    nm = nmap.PortScanner()
    nm.scan(hosts=host, ports=ports, arguments='-sT -O -n -T4')

    print("Host Information: " + host)
    for port in nm[host].all_tcp():
        state = nm[host]['tcp'][port]['state']
        name = nm[host]['tcp'][port]['name']
        product = nm[host]['tcp'][port]['product']
        print(Fore.GREEN + "[*] tcp/%d %s %s %s" % (port, state, name, product) + Fore.RESET)
        
        open_ports.append(port)
        check_service(host, port)


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

    if not os.path.exists(output_dir):
        os.makedirs(output_dir)
    

if __name__ == '__main__':
    init()
    main()
