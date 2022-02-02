# EZSSLSEC
**EZSSLSEC** is a SSL security checking tool. **testssl.sh** tool is running in the background. (Special thanks to drwetter. You are amazing, God bless you man :D)
* Checking SSL certificate expiration date and time
* Checking SSL certificate CA (Certificate Authority)
* Checking SSL certificate signature algorithms
* Checking SSL certificate key length
* Checking SSL certificate cipher suites & encryption packages
* Checking SSL/TLS renegotiation vulnerabilities
* Checking SSL RC4
* Checking SWEET32
* Checking BEAST
* Checking BREACH
* Checking POODLE
* Checking DROWN
* Checking Heartbleed
* Checking Ticketbleed
* Checking LUCKY13
* Checking LOGJAM
* Checking Freak
* Checking Winshock 
# Installation
1. Clone the repository to your machine : `git clone https://github.com/0x1337root/EZSSLSEC.git`
2. Go to the folder : `cd EZSSLSEC`
3. Make the tool executable : `chmod +x EZSSLSEC.py`
4. Install required modules : `pip3 install -r requirements.txt`
# Note
* Install figlet font "epic" if it does not exists on your system :<br> `wget http://www.figlet.org/fonts/epic.flf -O /usr/share/figlet/epic.flf`
# Usage
To get a list of all options and learn how to use this app, enter the following command :<br>
`./EZSSLSEC.py -h`<br><br>
**General Usage :** `./EZSSLSEC.py <domain>`<br><br>
**Example 1 :** `./EZSSLSEC.py example.com`<br>
