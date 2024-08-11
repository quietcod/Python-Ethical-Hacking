--> Usage for Mac Address Changer --

First save the file with the python (.py) extension.
In terminal write -- python2 <file_name.py> -i -m <mac_addess>
eg. --> python2 mac_changer.py -i eth0 -m 00:11:22:33:44:55

--> Usage for DNS Spoofer --

**# Domain Name Server (DNS)

**# iptables -I FORWARD -j NFQUEUE --queue-num 0  --> run this command in your linux terminal first

**# but if you are testing it in your own machine you would need to use --> iptables - I INPUT -j NFQUEUE --queue-num 0
**# and then Run this --> iptables -I INPUT -j NFQUEUE --queue-num 0

**# then run the arp spoofer, so that you are the man in the middle.
****# After you work is done make sure to delete the iptables using the command -> iptables --flush
**
