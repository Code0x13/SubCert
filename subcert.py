import argparse
import textwrap
import ssl
import socket

class color:
   PURPLE = '\033[1;35;48m'
   CYAN = '\033[1;36;48m'
   BOLD = '\033[1;37;48m'
   BLUE = '\033[1;34;48m'
   GREEN = '\033[1;32;48m'
   YELLOW = '\033[1;33;48m'
   RED = '\033[1;31;48m'
   BLACK = '\033[1;30;48m'
   UNDERLINE = '\033[4;37;48m'
   END = '\033[1;37;0m'

#globals
global_targets = []
global_results = []


def print_title():
    print(color.PURPLE + "\n<~~~~~~~~~~~~~~~~" + color.END)
    print(color.BLUE + "    SubCert v0.1" + color.END)
    print(color.PURPLE + "   ~~~~~~~~~~~~~~~~~~~~~~>\n" + color.END)

#given a FQDN convert it to an IP, return false on fail
def get_cert(target, port=443):
    try:
        context = ssl.create_default_context()
        with socket.create_connection((target, port)) as sock:
            with context.wrap_socket(sock, server_hostname=target) as wrap_sock:
                cert = wrap_sock.getpeercert()
        return cert
    except:
        return False

#accepts a target IP or host, can take a TCP port number, and can also set whether or not we want wildcard entries in there
#obtains the SSL cert for the target and returns an array of the Common and Alt Names for that host
def get_CN_and_SAN(target, port=443, remove_wildcard=True):
    results = []

    cert = get_cert(target, port)
    if(cert):
        #loop through the subject data to get the Common Name, add to results array
        for x in cert["subject"]:
            for y in x:
                if('commonName' in y):
                    if y[1] not in results:
                        if (remove_wildcard == False) or ('*' not in y[1]):
                            results.append(y[1])

        #loop through the subject Alt Names, add to results array if a new entry
        for x in cert["subjectAltName"]:
            if x[1] not in results:
                if(remove_wildcard == False) or ('*' not in x[1]):
                    results.append(x[1])
        
        return results
    else:
        print(color.RED + target + color.END + " - error retrieving certificate!")
        return False

#return a host's IP address, or an empty string if can't resolve
def resolve_ip(target):
    try:
        return socket.gethostbyname(target)
    except:
        print(color.RED + target + color.END + " - cannot resolve host")
        return ""

#load targets from file, return array of targets
def load_targets(fn):
    arr = []
    try:
        with open(fn, "r") as fp:
            for ln in fp:
                str = ln.rstrip()
                if (str not in arr) and (len(str) > 0):
                    arr.append(str)
    except:
        print(color.RED + fn + color.END + " - file error!")
    return arr

if __name__ == '__main__':
    print_title()

    parser = argparse.ArgumentParser(
        description = "SubCert v0.1 - Enumerate subdomains from your targets' certificates\n\n - by Code0x13 - https://github.com/Code0x13",
        formatter_class = argparse.RawDescriptionHelpFormatter,
        epilog = textwrap.dedent('''
        Example:
            subcert.py -f scope.txt
            subcert.py -t 192.168.0.1
            subcert.py -t www.target.com
        '''))
    parser.add_argument('-f', '--file', help='Specify a file of in-scope IP addresses or hosts')
    parser.add_argument('-t', '--target', help='Specify a single target IP or host')

    args = parser.parse_args()   

    #if a target is given, add this to the targets array
    if(args.target):
        global_targets.append(args.target)

    #if an input file is given, add these too
    if(args.file):
        arr = load_targets(args.file)
        if(len(arr) > 0):
            global_targets += arr

    if(len(global_targets) <= 0):
        print(color.RED + "You need to specify at least one target!" + color.END)
        exit()

    #go through the targets, get CN and SANs and append to global_results the hostname and resolved IP
    for target in global_targets:
        result = get_CN_and_SAN(target)
        if result:
            for r in result:
                global_results.append((r, resolve_ip(r)))

    #print the results
    for r in global_results:
        print(r[0] + ":" + r[1])

    #print a summary at the end
    print()
    if(len(global_results) > 0):
        print(color.GREEN + str(len(global_results)) + color.END + " hosts identified! :)")
    else:
        print(color.RED + "No" + color.END + " hosts identified! :(")
