#!/bin/python3

# TO-DO by prio
# 1. TO-DO: If possible, make ssl check for login pages (port:443).
# 2. TO-DO: If possible, make EZDNSSEC style presentation <and> <or> make our finding title type presentation.

import re, argparse, subprocess, os
from colorama import Fore, Style
from pyfiglet import Figlet
from datetime import datetime

parser = argparse.ArgumentParser(description="Write the domain")
parser.add_argument('domain', type=str, help="Domain to control")
args = parser.parse_args()

try:
    custom_fig = Figlet(font='epic')
    print()
    print(Fore.RED + Style.BRIGHT + custom_fig.renderText('EZSSLSEC') + Style.RESET_ALL)

    # Printing the process
    #os.system('bash ./testssl.sh/testssl.sh --colorblind --quiet -S -s -p -R -4 -W -A -B -O -D -H -T -L -J -F -WS ' + args.domain + ' | tee tmp')

    print("Started at", datetime.now().strftime("%d/%m/%Y %H:%M:%S"))
    print("Auditing and Reporting (It may takes 3-5 minutes, PLEASE WAIT!)\n")

    subprocess.getoutput('bash ./testssl.sh/testssl.sh --colorblind --quiet -S -s -p -R -4 -W -A -B -O -D -H -T -L -J -F -WS ' + args.domain + ' | tee tmp')

    def check_cert_expiry():
        cert_expiry = str(subprocess.getoutput('cat tmp | grep -i -m 1 "Certificate Validity"'))
        print(cert_expiry)

    def check_trust():
        trust = str(subprocess.getoutput('cat tmp | grep -i -m 1 "trust"'))
        chain_of_trust = str(subprocess.getoutput('cat tmp | grep -i -m 1 "chain"'))
        print(trust)
        print(chain_of_trust)

    def check_key_length():
        ssl_key_length = str(subprocess.getoutput('cat tmp | grep -i -m 1 "Serial"'))
        print(ssl_key_length)

    def check_sign_algo():
        signature_algo = str(subprocess.getoutput('cat tmp | grep -i "Signature Algorithm"'))
        print(signature_algo)

    def check_encryption_packages():
        null_ciphers = str(subprocess.getoutput("sed -n '/NULL ciphers/p' tmp"))
        anonymous_null = str(subprocess.getoutput("sed -n '/Anonymous NULL/p' tmp"))
        export_ciphers = str(subprocess.getoutput("sed -n '/Export ciphers/p' tmp"))
        low64 = str(subprocess.getoutput("sed -n '/LOW: 64/p' tmp"))
        tripledes = str(subprocess.getoutput("sed -n '/Triple/p' tmp"))
        obsoleted = str(subprocess.getoutput("sed -n '/Obsoleted/p' tmp"))
        strong_encryption = str(subprocess.getoutput("sed -n '/Strong encryption/p' tmp"))
        forward_secrecy = str(subprocess.getoutput("sed -n '/Forward Secrecy/p' tmp"))

        print(null_ciphers)
        print(anonymous_null)
        print(export_ciphers)
        print(low64)
        print(tripledes)
        print(obsoleted)
        print(strong_encryption)
        print(forward_secrecy)

    def check_secure_renegotiation():
        renegotiation = str(subprocess.getoutput('cat tmp | grep -i "Secure Renegotiation"'))
        print(renegotiation)

    def check_rc4():
        rc4 = str(subprocess.getoutput('cat tmp | grep -i "rc4"'))
        print(rc4)

    def check_sweet32():
        sweet32 = str(subprocess.getoutput('cat tmp | grep -i "sweet32"'))
        print(sweet32)

    def check_beast():
        beast = str(subprocess.getoutput('cat tmp | grep -i "beast"'))
        beast_vuln = str(subprocess.getoutput("sed -n '/BEAST/,/VULNERABLE/p' tmp"))
        if re.search('ok', beast, re.IGNORECASE):
            print(beast)
        else:
            print(beast_vuln)

    def check_breach():
        breach = str(subprocess.getoutput('cat tmp | grep -i "breach"'))
        print(breach)

    def check_poodle():
        poodle = str(subprocess.getoutput('cat tmp | grep -i "poodle"'))
        print(poodle)

    def check_drown():
        drown = str(subprocess.getoutput('cat tmp | grep -i "drown"'))
        print(drown)

    def check_heartbleed():
        heartbleed = str(subprocess.getoutput('cat tmp | grep -i "heartbleed"'))
        print(heartbleed)

    def check_ticketbleed():
        ticketbleed = str(subprocess.getoutput('cat tmp | grep -i "ticketbleed"'))
        print(ticketbleed)

    def check_lucky13():
        lucky13 = str(subprocess.getoutput('cat tmp | grep -i "lucky13"'))
        print(lucky13)

    def check_logjam():
        logjam = str(subprocess.getoutput('cat tmp | grep -i "logjam"'))
        print(logjam)

    def check_freak():
        freak = str(subprocess.getoutput('cat tmp | grep -i "freak"'))
        print(freak)

    def check_winshock():
        winshock = str(subprocess.getoutput('cat tmp | grep -i "winshock"'))
        print(winshock)

    check_cert_expiry()
    check_trust()
    check_key_length()
    check_sign_algo()
    check_encryption_packages()
    check_secure_renegotiation()
    check_rc4()
    check_sweet32()
    check_beast()
    check_breach()
    check_poodle()
    check_drown()
    check_heartbleed()
    check_ticketbleed()
    check_lucky13()
    check_logjam()
    check_freak()
    check_winshock()

    os.system('rm tmp')

except:
    # Printing the process
    #os.system('bash ./testssl.sh/testssl.sh --colorblind --quiet -S -s -p -R -4 -W -A -B -O -D -H -T -L -J -F -WS ' + args.domain + ' | tee tmp')

    print("Started at", datetime.now().strftime("%d/%m/%Y %H:%M:%S"))
    print("Auditing and Reporting (It may takes 3-5 minutes, PLEASE WAIT!)\n")

    subprocess.getoutput('bash ./testssl.sh/testssl.sh --colorblind --quiet -S -s -p -R -4 -W -A -B -O -D -H -T -L -J -F -WS ' + args.domain + ' | tee tmp')

    def check_cert_expiry():
        cert_expiry = str(subprocess.getoutput('cat tmp | grep -i -m 1 "Certificate Validity"'))
        print(cert_expiry)

    def check_trust():
        trust = str(subprocess.getoutput('cat tmp | grep -i -m 1 "trust"'))
        chain_of_trust = str(subprocess.getoutput('cat tmp | grep -i -m 1 "chain"'))
        print(trust)
        print(chain_of_trust)

    def check_key_length():
        ssl_key_length = str(subprocess.getoutput('cat tmp | grep -i -m 1 "Serial"'))
        print(ssl_key_length)

    def check_sign_algo():
        signature_algo = str(subprocess.getoutput('cat tmp | grep -i "Signature Algorithm"'))
        print(signature_algo)

    def check_encryption_packages():
        null_ciphers = str(subprocess.getoutput("sed -n '/NULL ciphers/p' tmp"))
        anonymous_null = str(subprocess.getoutput("sed -n '/Anonymous NULL/p' tmp"))
        export_ciphers = str(subprocess.getoutput("sed -n '/Export ciphers/p' tmp"))
        low64 = str(subprocess.getoutput("sed -n '/LOW: 64/p' tmp"))
        tripledes = str(subprocess.getoutput("sed -n '/Triple/p' tmp"))
        obsoleted = str(subprocess.getoutput("sed -n '/Obsoleted/p' tmp"))
        strong_encryption = str(subprocess.getoutput("sed -n '/Strong encryption/p' tmp"))
        forward_secrecy = str(subprocess.getoutput("sed -n '/Forward Secrecy/p' tmp"))

        print(null_ciphers)
        print(anonymous_null)
        print(export_ciphers)
        print(low64)
        print(tripledes)
        print(obsoleted)
        print(strong_encryption)
        print(forward_secrecy)

    def check_secure_renegotiation():
        renegotiation = str(subprocess.getoutput('cat tmp | grep -i "Secure Renegotiation"'))
        print(renegotiation)

    def check_rc4():
        rc4 = str(subprocess.getoutput('cat tmp | grep -i "rc4"'))
        print(rc4)

    def check_sweet32():
        sweet32 = str(subprocess.getoutput('cat tmp | grep -i "sweet32"'))
        print(sweet32)

    def check_beast():
        beast = str(subprocess.getoutput('cat tmp | grep -i "beast"'))
        beast_vuln = str(subprocess.getoutput("sed -n '/BEAST/,/VULNERABLE/p' tmp"))
        if re.search('ok', beast, re.IGNORECASE):
            print(beast)
        else:
            print(beast_vuln)

    def check_breach():
        breach = str(subprocess.getoutput('cat tmp | grep -i "breach"'))
        print(breach)

    def check_poodle():
        poodle = str(subprocess.getoutput('cat tmp | grep -i "poodle"'))
        print(poodle)

    def check_drown():
        drown = str(subprocess.getoutput('cat tmp | grep -i "drown"'))
        print(drown)

    def check_heartbleed():
        heartbleed = str(subprocess.getoutput('cat tmp | grep -i "heartbleed"'))
        print(heartbleed)

    def check_ticketbleed():
        ticketbleed = str(subprocess.getoutput('cat tmp | grep -i "ticketbleed"'))
        print(ticketbleed)

    def check_lucky13():
        lucky13 = str(subprocess.getoutput('cat tmp | grep -i "lucky13"'))
        print(lucky13)

    def check_logjam():
        logjam = str(subprocess.getoutput('cat tmp | grep -i "logjam"'))
        print(logjam)

    def check_freak():
        freak = str(subprocess.getoutput('cat tmp | grep -i "freak"'))
        print(freak)

    def check_winshock():
        winshock = str(subprocess.getoutput('cat tmp | grep -i "winshock"'))
        print(winshock)

    check_cert_expiry()
    check_trust()
    check_key_length()
    check_sign_algo()
    check_encryption_packages()
    check_secure_renegotiation()
    check_rc4()
    check_sweet32()
    check_beast()
    check_breach()
    check_poodle()
    check_drown()
    check_heartbleed()
    check_ticketbleed()
    check_lucky13()
    check_logjam()
    check_freak()
    check_winshock()

    os.system('rm tmp')
