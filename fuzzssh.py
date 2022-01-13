#!/usr/bin/env python3 
# -*- coding: utf-8 -*-"
"""
FuzzSSH (Simple SSH Fuzzer) - 2022 - by psy (epsylon@riseup.net)

You should have received a copy of the GNU General Public License along
with FuzzSSH; if not, write to the Free Software Foundation, Inc., 51
Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
----------
See following RFCs for more info:
    rfc4251 - The SSH Protocol Architecture
    rfc4252 - The SSH Authentication Protocol
    rfc4253 - The SSH Transport Layer Protocol
    rfc4254 - The SSH Connection Protocol
----------
Current [01/22][Paramiko] tested parameters: 
    username, password, pkey, key_filename, timeout, allow_agent, 
    look_for_keys, compress, sock, gss_auth, gss_kex, gss_deleg_creds, 
    gss_host, banner_timeout, auth_timeout, gss_trust_dns, passphrase, 
    disabled_algorithms
"""
import sys, time, os
try:
    import paramiko
except:
    print("\nError importing: paramiko lib. \n\n To install it on Debian based systems:\n\n $ 'sudo apt-get install python3-paramiko'\n")
    sys.exit()

VERSION = "v:0.1beta"
RELEASE = "12012022"
SOURCE1 = "https://code.03c8.net/epsylon/fuzzssh"
SOURCE2 = "https://github.com/epsylon/fuzzssh"
CONTACT = "epsylon@riseup.net - (https://03c8.net)"

try:
    import payloads.payloads # import payloads
except:
    print ("\n[Info] Try to run the tool with Python3.x.y... (ex: python3 fuzzssh.py) -> [EXITING!]\n")
    sys.exit()

def progressbar(it, prefix="", size=60, file=sys.stdout):
    count = len(it)
    def show(j):
        x = int(size*j/count)
        file.write("%s[%s%s] %i/%i\r" % (prefix, "#"*x, "."*(size-x), j, count))
        file.flush()        
    show(0)
    for i, item in enumerate(it):
        yield item
        show(i+1)
    file.write("\n")
    file.flush()

def payloading():
    print("\n"+"="*50 + "\n")
    payloads_numbers = payloads.payloads.numbers # load 'numbers' payloads
    num_payloads_numbers = len(payloads_numbers)
    payloads_overflows = payloads.payloads.overflows # load 'overflows' payloads
    num_payloads_overflows = len(payloads_overflows)
    payloads_strings = payloads.payloads.strings # load 'strings' payloads
    num_payloads_strings = len(payloads_strings)
    payloads_bugs = payloads.payloads.bugs # load 'bugs' payloads
    num_payloads_bugs = len(payloads_bugs)
    return payloads_numbers, num_payloads_numbers, payloads_overflows, num_payloads_overflows, payloads_strings, num_payloads_strings, payloads_bugs, num_payloads_bugs

def send_payload(client, payload, parameter, verbosity, num_payloads, method): # FUZZED PARAMETERS
    if parameter == "USERNAME":
        try:
            client.connect(hostname=str(target),port=int(port),username=payload, password=None, pkey=None, key_filename=None, timeout=None, allow_agent=True, look_for_keys=True, compress=False, sock=None, gss_auth=False, gss_kex=False, gss_deleg_creds=True, gss_host=None, banner_timeout=None, auth_timeout=None, gss_trust_dns=True, passphrase=None, disabled_algorithms=None)
            client.close() # close SSH client
        except:
            pass # keep testing
    elif parameter == "PASSWORD":
        try:
            client.connect(hostname=str(target),port=int(port),username=None, password=payload, pkey=None, key_filename=None, timeout=None, allow_agent=True, look_for_keys=True, compress=False, sock=None, gss_auth=False, gss_kex=False, gss_deleg_creds=True, gss_host=None, banner_timeout=None, auth_timeout=None, gss_trust_dns=True, passphrase=None, disabled_algorithms=None)
        except:
            pass # keep testing
    elif parameter == "PKEY":
        try:
            client.connect(hostname=str(target),port=int(port),username=None, password=None, pkey=payload, key_filename=None, timeout=None, allow_agent=True, look_for_keys=True, compress=False, sock=None, gss_auth=False, gss_kex=False, gss_deleg_creds=True, gss_host=None, banner_timeout=None, auth_timeout=None, gss_trust_dns=True, passphrase=None, disabled_algorithms=None)
        except:
            pass # keep testing
    elif parameter == "KEY_FILENAME":
        try:
            client.connect(hostname=str(target),port=int(port),username=None, password=None, pkey=None, key_filename=payload, timeout=None, allow_agent=True, look_for_keys=True, compress=False, sock=None, gss_auth=False, gss_kex=False, gss_deleg_creds=True, gss_host=None, banner_timeout=None, auth_timeout=None, gss_trust_dns=True, passphrase=None, disabled_algorithms=None)
        except:
            pass # keep testing
    elif parameter == "TIMEOUT":
        try:
            client.connect(hostname=str(target),port=int(port),username=None, password=None, pkey=None, key_filename=None, timeout=payload, allow_agent=True, look_for_keys=True, compress=False, sock=None, gss_auth=False, gss_kex=False, gss_deleg_creds=True, gss_host=None, banner_timeout=None, auth_timeout=None, gss_trust_dns=True, passphrase=None, disabled_algorithms=None)
        except:
            pass # keep testing
    elif parameter == "ALLOW_AGENT":
        try:
            client.connect(hostname=str(target),port=int(port),username=None, password=None, pkey=None, key_filename=None, timeout=None, allow_agent=payload, look_for_keys=True, compress=False, sock=None, gss_auth=False, gss_kex=False, gss_deleg_creds=True, gss_host=None, banner_timeout=None, auth_timeout=None, gss_trust_dns=True, passphrase=None, disabled_algorithms=None)
        except:
            pass # keep testing
    elif parameter == "LOOK_FOR_KEYS":
        try:
            client.connect(hostname=str(target),port=int(port),username=None, password=None, pkey=None, key_filename=None, timeout=None, allow_agent=True, look_for_keys=payload, compress=False, sock=None, gss_auth=False, gss_kex=False, gss_deleg_creds=True, gss_host=None, banner_timeout=None, auth_timeout=None, gss_trust_dns=True, passphrase=None, disabled_algorithms=None)
        except:
            pass # keep testing
    elif parameter == "COMPRESS":
        try:
            client.connect(hostname=str(target),port=int(port),username=None, password=None, pkey=None, key_filename=None, timeout=None, allow_agent=True, look_for_keys=True, compress=payload, sock=None, gss_auth=False, gss_kex=False, gss_deleg_creds=True, gss_host=None, banner_timeout=None, auth_timeout=None, gss_trust_dns=True, passphrase=None, disabled_algorithms=None)
        except:
            pass # keep testing
    elif parameter == "SOCK":
        try:
            client.connect(hostname=str(target),port=int(port),username=None, password=None, pkey=None, key_filename=None, timeout=None, allow_agent=True, look_for_keys=True, compress=False, sock=payload, gss_auth=False, gss_kex=False, gss_deleg_creds=True, gss_host=None, banner_timeout=None, auth_timeout=None, gss_trust_dns=True, passphrase=None, disabled_algorithms=None)
        except:
            pass # keep testing
    elif parameter == "GSS_AUTH":
        try:
            client.connect(hostname=str(target),port=int(port),username=None, password=None, pkey=None, key_filename=None, timeout=None, allow_agent=True, look_for_keys=True, compress=False, sock=None, gss_auth=payload, gss_kex=False, gss_deleg_creds=True, gss_host=None, banner_timeout=None, auth_timeout=None, gss_trust_dns=True, passphrase=None, disabled_algorithms=None)
        except:
            pass # keep testing
    elif parameter == "GSS_KEX":
        try:
            client.connect(hostname=str(target),port=int(port),username=None, password=None, pkey=None, key_filename=None, timeout=None, allow_agent=True, look_for_keys=True, compress=False, sock=None, gss_auth=False, gss_kex=payload, gss_deleg_creds=True, gss_host=None, banner_timeout=None, auth_timeout=None, gss_trust_dns=True, passphrase=None, disabled_algorithms=None)
        except:
            pass # keep testing
    elif parameter == "GSS_DELEG_CREDS":
        try:
            client.connect(hostname=str(target),port=int(port),username=None, password=None, pkey=None, key_filename=None, timeout=None, allow_agent=True, look_for_keys=True, compress=False, sock=None, gss_auth=False, gss_kex=False, gss_deleg_creds=payload, gss_host=None, banner_timeout=None, auth_timeout=None, gss_trust_dns=True, passphrase=None, disabled_algorithms=None)
        except:
            pass # keep testing
    elif parameter == "GSS_HOST":
        try:
            client.connect(hostname=str(target),port=int(port),username=None, password=None, pkey=None, key_filename=None, timeout=None, allow_agent=True, look_for_keys=True, compress=False, sock=None, gss_auth=False, gss_kex=False, gss_deleg_creds=True, gss_host=payload, banner_timeout=None, auth_timeout=None, gss_trust_dns=True, passphrase=None, disabled_algorithms=None)
        except:
            pass # keep testing
    elif parameter == "BANNER_TIMEOUT":
        try:
            client.connect(hostname=str(target),port=int(port),username=None, password=None, pkey=None, key_filename=None, timeout=None, allow_agent=True, look_for_keys=True, compress=False, sock=None, gss_auth=False, gss_kex=False, gss_deleg_creds=True, gss_host=None, banner_timeout=payload, auth_timeout=None, gss_trust_dns=True, passphrase=None, disabled_algorithms=None)
        except:
            pass # keep testing
    elif parameter == "AUTH_TIMEOUT":
        try:
            client.connect(hostname=str(target),port=int(port),username=None, password=None, pkey=None, key_filename=None, timeout=None, allow_agent=True, look_for_keys=True, compress=False, sock=None, gss_auth=False, gss_kex=False, gss_deleg_creds=True, gss_host=None, banner_timeout=None, auth_timeout=payload, gss_trust_dns=True, passphrase=None, disabled_algorithms=None)
        except:
            pass # keep testing
    elif parameter == "GSS_TRUST_DNS":
        try:
            client.connect(hostname=str(target),port=int(port),username=None, password=None, pkey=None, key_filename=None, timeout=None, allow_agent=True, look_for_keys=True, compress=False, sock=None, gss_auth=False, gss_kex=False, gss_deleg_creds=True, gss_host=None, banner_timeout=None, auth_timeout=None, gss_trust_dns=payload, passphrase=None, disabled_algorithms=None)
        except:
            pass # keep testing
    elif parameter == "PASSPHRASE":
        try:
            client.connect(hostname=str(target),port=int(port),username=None, password=None, pkey=None, key_filename=None, timeout=None, allow_agent=True, look_for_keys=True, compress=False, sock=None, gss_auth=False, gss_kex=False, gss_deleg_creds=True, gss_host=None, banner_timeout=None, auth_timeout=None, gss_trust_dns=True, passphrase=payload, disabled_algorithms=None)
        except:
            pass # keep testing
    elif parameter == "DISABLED_ALGORITHMS":
        try:
            client.connect(hostname=str(target),port=int(port),username=None, password=None, pkey=None, key_filename=None, timeout=None, allow_agent=True, look_for_keys=True, compress=False, sock=None, gss_auth=False, gss_kex=False, gss_deleg_creds=True, gss_host=None, banner_timeout=None, auth_timeout=None, gss_trust_dns=True, passphrase=None, disabled_algorithms=payload)
        except:
            pass # keep testing

def exploit(target, port, user, pw, verbosity, payloads_numbers, num_payloads_numbers, payloads_overflows, num_payloads_overflows, payloads_strings, num_payloads_strings, payloads_bugs, num_payloads_bugs):
    try:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.load_system_host_keys()
        paramiko.util.log_to_file("/dev/null", level="INFO") # logs + bypass -> paramiko.SSHException issue (https://github.com/paramiko/paramiko/issues/1752)
        print("[Info] Trying SSH connection...\n")
        client.connect(hostname=str(target),port=int(port),username=str(user),password=str(pw),timeout=10,banner_timeout=200,look_for_keys=False,allow_agent=False)
        print("[Info] Connection established -> OK!")
        if verbosity is True:
            b = client.get_transport().remote_version
            print ("\n  -> [*] Banner:")
            print("      -> "+str(b))
            so = client._transport.get_security_options()
            print ("\n  -> [*] Ciphering algorithms:")
            for c in so.ciphers:
                print("      -> "+str(c))
            print ("\n  -> [*] Key exchange algorithms:")
            for k in so.kex:
                print("      -> "+str(k))
            print("\n[Info] Connection closed -> OK!")
        print("\n"+"="*50)
    except:
        print("="*50)
        print ("\n[Error] Connection failed! -> [ABORTING!]\n")
        sys.exit()
    client.close() # close SSH client
    print("\n -> [*] Starting to test SSH (protocol)...")
    parameters = ("USERNAME", "PASSWORD", "PKEY", "KEY_FILENAME", "TIMEOUT", "ALLOW_AGENT", "LOOK_FOR_KEYS", "COMPRESS", "SOCK", "GSS_AUTH", "GSS_KEX", "GSS_DELEG_CREDS", "GSS_HOST", "BANNER_TIMEOUT", "AUTH_TIMEOUT", "GSS_TRUST_DNS", "PASSPHRASE", "DISABLED_ALGORITHMS") # FUZZED PARAMETERS
    for parameter in parameters:
        print("\n     -> [SSH] -> ["+str(parameter)+"]...\n")
        method = "         [*] Numbers       "
        for i in progressbar(range(num_payloads_numbers),method+" ", 40):
            time.sleep(0.7)
        for number in payloads_numbers:
            send_payload(client, number, parameter, verbosity, num_payloads_numbers, method)
            time.sleep(0.2)
        method = "         [*] Overflows     "
        for i in progressbar(range(num_payloads_overflows),method+" ", 40):
            time.sleep(0.7)
        for overflow in payloads_overflows:
            send_payload(client, overflow, parameter, verbosity, num_payloads_overflows, method)
            time.sleep(0.2)
        method = "         [*] Format Strings"
        for i in progressbar(range(num_payloads_strings),method+" ", 40):
            time.sleep(0.7)
        for string in payloads_strings:
            send_payload(client, string, parameter, verbosity, num_payloads_strings, method)
            time.sleep(0.2)
        method = "         [*] Known bugs    "
        for i in progressbar(range(num_payloads_bugs),method+" ", 40):
            time.sleep(0.7)
        for bug in payloads_bugs:
            send_payload(client, bug, parameter, verbosity, num_payloads_bugs, method)
            time.sleep(0.2)
        print("\n"+"-"*15)

def set_target():
    target = input("\n  + Enter TARGET (ex: '100.0.0.1'): ")
    if target == "": # exit when no 'target' set
        print("\n"+"="*50)
        print("\n[Error] Not ANY target detected -> [EXITING!]\n")
        sys.exit()
    port = input("\n  + Enter PORT (default: '22'): ")
    try: # check port as integer num
        port = int(port)
    except:
        port = 22
    if port == "": # default when no 'port' set
        port = 22
    user = input("\n  + Enter USER (default: 'root'): ")
    if user == "": # default when no 'user' set
        user = "root"
    pw = input("\n  + Enter PASSWORD (default: 'root'): ")
    if pw == "": # default when no 'password' set
        ps = "root"
    verbosity = input("\n  + Enter VERBOSITY (default: 'false'): ")
    if verbosity == "True" or verbosity == "true":
        verbosity = True
    else:
        verbosity = False # default when no 'verbosity' set
    return target, port, user, pw, verbosity

def print_banner():
    print("\n"+"="*50)
    print(" _____      __________        _   _ ")
    print("|  ___|   _|__  /__  /___ ___| | | |")
    print("| |_ | | | | / /  / // __/ __| |_| |")
    print("|  _|| |_| |/ /_ / /_\__ \__ \  _  |")
    print("|_|   \__,_/____/____|___/___/_| |_| by psy")
    print('\n"SSH -Protocol- Fuzzing Tool"')
    print("\n"+"-"*15+"\n")
    print(" * VERSION: ")
    print("   + "+VERSION+" - (rev:"+RELEASE+")")
    print("\n * SOURCES:")
    print("   + "+SOURCE1)
    print("   + "+SOURCE2)
    print("\n * CONTACT: ")
    print("   + "+CONTACT+"\n")
    print("-"*15+"\n")
    print("="*50)

# sub_init #
print_banner() # show banner
print("\n"+"="*50)
target, port, user, pw, verbosity = set_target()
payloads_numbers, num_payloads_numbers, payloads_overflows, num_payloads_overflows, payloads_strings, num_payloads_strings, payloads_bugs, num_payloads_bugs = payloading()
exploit(target, port, user, pw, verbosity, payloads_numbers, num_payloads_numbers, payloads_overflows, num_payloads_overflows, payloads_strings, num_payloads_strings, payloads_bugs, num_payloads_bugs)
