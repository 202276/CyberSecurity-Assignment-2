# CyberSecurity-Assignment-2

File 1:
task1.py - This file does not have pkt.show()

File 2:
task1_withPktShow.py - This file has pkt.show() - It will allow one to view the packet details sent by attacker

Program Explanation:
- This python program performs a DNS spoofing attack using the Scapy library, a powerful packet manipulation tool.
- The program listens to all UDP (User Datagram Protocol) packets from a specific source host (10.9.0.5) on a specific interface (br-9bff7edb888c), which are being sent to the DNS port (53), using the sniff() function from Scapy.
- Once a packet is detected, it is sent to the spoof_dns() function.
- Inside the spoof_dns() function, it checks if the incoming packet is a DNS query for www.example.com.
- If it is, the program creates a falsified (spoofed) DNS response packet to trick the source into believing that 'www.example.com' resides at the spoofed IP address 1.1.1.1.
- The program modifies the packet by swapping the source and destination IP addresses, and source and destination port numbers, and sets the source port to 53 (DNS).
- The program then forms a DNS response with an answer section pointing to the IP address 1.1.1.1.
- Finally, the spoofpkt (spoofed packet) is sent back to the source of the original DNS query with the send() method.
- The goal of such a program is often used maliciously to redirect network traffic by changing the IP address in DNS responses. It's commonly used in phishing attacks where an attacker redirects a victim to a malicious website instead of the actual one.

Executing the program:
- Before executing the program on user machine (10.9.0.5), make sure to clear cache in local-dns-server by executing command “rndc flush”
- Then execute the program with command “./task1.py” on seed-attacker
- As user-10.9.0.5. execute the command “dig www.example.com”
- Notice that the answer got is 1.1.1.1 and not the legitimate one

Comparison before and after the attack:
    Before the attack:
    - When user-10.9.0.5 executes command “dig www.example.com”, answer is from the real server and hence IP is 93.184.216.34
    After the attack:
    - As user-10.9.0.5, execute the command “dig www.example.com”
    - Notice that the answer got is 1.1.1.1 and not the legitimate one



File 3:
task2.py

Program Explanation:
- The program is a DNS spoofing attack script that specifically targets queries for 'www.example.com'. Here's how it works:
- The program sniffs UDP packets on a specified network interface (br-9bff7edb888c). It uses a filter to look for packets specifically from a source IP (10.9.0.53) and for packets targeting a specific destination port (53, the standard port for DNS traffic).
- If the program captures a packet that satisfies these conditions (pkt = sniff(iface='br-9bff7edb888c', filter=f, prn=spoof_dns)), it passes it to the function spoof_dns(pkt).
- Inside this spoof_dns function, the program checks if the packet has a DNS layer and if the DNS query (qd.qname) is 'www.example.com'.
- If the condition is true, it first prints out the packet details (pkt.show()).
- Then the program crafts a new malicious DNS response packet.
    IP Layer: It swaps the source and destination IP addresses of the original packet.
    UDP Layer: It sets the source port to 53 (to impersonate a DNS server) and the destination port to the original packet's source port.
    DNS Layer: It mimics the original DNS query but sets the 'answer' (an) to a malicious IP address ('1.1.1.1'). The ttl field is set to 259200 (3 days), suggesting the local DNS server should cache this response for that period. The qr field is set to 1 indicating this is a DNS response not query. The aa field is set to 1 meaning "this server is an authority for the domain", which can make the response more trustworthy.
- Finally, the program sends this spoofed DNS packet back over the network. If successful, the original sender of the DNS query will receive this packet and interpret it as a legitimate response. For the next 3 days, any requests for 'www.example.com' would resolve to '1.1.1.1' on the victims machine.
- This is the essence of a DNS spoofing (or DNS cache poisoning) attack, tricking a system into believing a false IP-Domain association, potentially leading the victim to a malicious site. Though it is important to note, many DNS servers protect against such types of attack through various security mechanisms.

Executing the program:
- Before executing the program, make sure to clear cache in local-dns-server by executing command “rndc flush”
- Stop program that is already running on seed-attacker (if any). Then execute the program with command “./task2.py” on seed-attacker
- As user-10.9.0.5, execute the command “dig www.example.com”
- Notice that the answer got is 1.1.1.1 and not the legitimate one (fake IP address)
- One can also notice how the packet looks like in the seed-attacker
- On the local-dns-server, execute the command “rndc dumpdb -cache”, followed by “cat  /var/cache/bind/dump.db | grep example”
- Notice that the IP address now is 1.1.1.1, screenshot is attached below
- This is the local DNS server cache poisoning attack and if user again does a dig command ($dig www.example.com) then it will again get the same response of 1.1.1.1 for since this is cached in the local dns server


File 4:
task3.py

Program Explanation:
- The idea here is to add an additional "Authority Section" to the DNS response packet that indicates ns.attacker32.com as the Name Server for all queries related to example.com. This would eventually let the attacker control the resolution of all subdomains under example.com.
- To do so, one would add DNS Resource Records (RR) to the Authority Section (ns) of the DNS packet in spoofing function.
- This program is a Python script that conducts a DNS spoofing or DNS cache poisoning attack aiming to divert Internet traffic away from its legitimate destinations. Specifically, it's designed to redirect queries for anything within the example.com domain to 1.1.1.1.
Step-by-step explanation of what the program does:
- Sniffing the Network: The line pkt = sniff(iface='br-9bff7edb888c', filter=f, prn=spoof_dns) tells the program to sniff packets on the network interface br-9bff7edb888c. It's looking specifically for UDP packets from the source host 10.9.0.53 and destination port 53 (DNS port).
- Packet Matching: When a packet is captured, it's processed by the spoof_dns() function. This function first checks if the packet contains a DNS request for the URL www.example.com.
- Creating Spoofed Packet: If the packet matches the DNA requirements for www.example.com, the script then constructs a spoofed DNS response designed to mislead the requestor:
    The source and destination IP addresses are swapped so that it appears the response is coming from the legitimate DNS server queried.
    The source and destination ports are also swapped, with the response coming from port 53, the standard for DNS responses.
    A DNS response message is then constructed, which declares that the IP address for www.example.com (and, in fact, any subdomain of example.com) is 1.1.1.1.
- Injecting Authority Record: The response includes an "Authority" section (NS record), which states that another DNS server, ns.attacker32.com, is also a valid source of information for the example.com domain. This effectively makes ns.attacker32.com a DNS poisoning server because with the spoofed or malicious DNS response it becomes an authority for example.com domain for the set ttl period.
- Sending the Spoofed Response: The spoofed DNS packet is sent back into the network, and if the attack is successful, the requesting host now has poisoned DNS information in its cache.
- Overall, this script manipulates the way that DNS usually works to gain control over the traffic related to example.com.

Program execution:
- Before executing the program, make sure to clear cache in local-dns-server by executing command “rndc flush”
- Then execute the program with command “./task3.py” on seed-attacker
- As user-10.9.0.5, execute the command “dig www.example.com”
- Notice that the answer got is 1.1.1.1 and not the legitimate one, it is a fake address
- This is also shown in the screenshot and highlighted with red
- This is recorded in the cache, now dump the cache in local-dns-server using the command “rndc dumpdb -cache”
- Check the cache content by executing the command “cat  /var/cache/bind/dump.db | grep example” in local-dns-server
- Notice that namespace has changed to ns.attacker32.com. the malicious nameserver is recorded in the cache


File 5:
task4.py

Program Explanation:
- This Python script is performing a DNS spoofing attack.
- It is using the third-party library Scapy to sniff and forge network packets. The script waits for DNS queries for 'www.example.com' that are originating from the IP address '10.9.0.53'. When such packets are detected, the script creates a fake DNS response that contains the wrong mappings for   domain names 'www.example.com' and 'google.com' to their IP addresses.
- def spoof_dns(pkt): This function is called when a packet matches the filter criteria. The packet pkt is passed as an argument to the function.
- In the function, it first checks if the DNS query is for 'www.example.com' and if so, it creates a DNS response.
- The IP packet's source and destination are swapped, so the returned packet appears to the requester as though it came from the legitimate DNS server it originally queried.
- The UDP packet's source and destination ports are swapped, with port 53 as the source, since that's the standard port for DNS.
- It sets the answer in the DNS response ('www.example.com' resolves to '1.1.1.1').
- For the authority section, it is creating two records - first one stating the name server for 'example.com' is 'ns.attacker32.com' and the second one stating the name server for 'google.com' is also 'ns.attacker32.com'.
- It then builds the DNS packet.
- Finally, it packages the entire spoofed packet (spoofpkt) together with the manipulated IP and UDP layers, and the created DNS packet as payload. This packet is sent to the original requester.
- The filter=f part in the sniff function tells Scapy to only capture packets that match this filter, which are UDP packets from source '10.9.0.53' with destination port 53 (DNS).
- The sniffing occurs on network interface 'br-9bff7edb888c'. The sniff function calls the spoof_dns() function for each captured packet.
- The idea behind this script is to deceive the requesting party into believing that they are communicating with the requested domain when they are, in fact, communicating with whoever is running this script.

Program Execution:
- Before executing the program, make sure to clear cache in local-dns-server by executing command “rndc flush”
- Then execute the program with command “./task4.py” on seed-attacker
- As user-10.9.0.5 execute the command “dig www.example.com”
- Notice that the answer got is 1.1.1.1 and not the legitimate one, it is a fake address
- But this time we want to see if google.com is cached or not
- Now dump the cache in local-dns-server using the command “rndc dumpdb -cache”
- Check the cache content by executing the command “cat  /var/cache/bind/dump.db | grep attacker” in local-dns-server -> No record is of google.com is found, we see only example.com record

File 6:
task5.py 

Program Explanation:
- This program listens for DNS queries for "www.example.com" from a host with IP 10.9.0.53 on the interface 'br-9bff7edb888c'.
- When it captures such a query, it creates a DNS Response, falsely suggesting that it comes from the queried DNS Server.
- The response contains:
    An Answer Section that asserts 'www.example.com' resolves to the IP address '1.1.1.1'.
    An Authority Section claiming that 'example.com' is served by two nameservers: 'ns.attacker32.com' and 'ns.example.com'.
    An Additional Section that provides IP addresses for 'ns.attacker32.com', 'ns.example.net', and 'www.facebook.com'. These IP addresses are all fake and the protocol does not require the request.
- After constructing the response, the script sends it to the querying host (10.9.0.53) in order to trick it into accepting the fraudulent mappings. This type of attack is known as DNS Spoofing or DNS Cache Poisoning attack.
- The idea behind such attacks is to divert traffic away from legitimate servers and towards malicious one

Program Execution:
- Before executing the program, make sure to clear cache in local-dns-server by executing command “rndc flush”
- Then execute the program with command “./task5.py” on seed-attacker
- As user-10.9.0.5 execute the command “dig www.example.com”
- Notice that the answer got is 1.1.1.1 and not the legitimate one, it is a fake address
- This is also shown in the screenshot and highlighted with red
- This is recorded in the cache, now dump the cache in local-dns-server using the command “rndc dumpdb -cache”, but the task now is to check if the additional records are cached or not
- Check the cache content by executing the command “cat  /var/cache/bind/dump.db | grep google” in local-dns-server -> No record is found which means additional record is not cached
- Check the cache content by executing the command “cat  /var/cache/bind/dump.db | grep attack” in local-dns-server -> Record is found but this is NS, additional record is not cached
- Check the cache content by executing the command “cat  /var/cache/bind/dump.db | grep example” in local-dns-server ->Record is found but this is NS, additional record is not cached
- Check the cache content by executing the command “cat  var/cache/bind/dump.db | grep facebook” in local-dns-server-> No record is found, additional record is not cached
