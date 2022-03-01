# Overview of DNS
Domain Name Server (DNS) main goal is to resolve domain queries and translates them into IP addresses. Imagine how difficult it would be to remember all IP addresses that you wanted to visit; Default DNS works on port 53 which is unencrypted protocol Known as Do53. If an adversary is sniffing the traffic it could result in knowing which sites are visited by the victim. 
Let’s assume an uncashed scenario Bob wants to go to www.examplevisit.com the client sends a request to the DNS server and it will communicate with other DNS servers that works together like root server, Top level domain (TLD) nameserver and the authoritative nameserver When the IP address is resolved it will return it back to the client.

  
<p align="center">
<img src="https://user-images.githubusercontent.com/78951224/156123662-c4492676-f00f-4585-a993-152c81019a6b.png")

</p>
  
 DNS Server will deal initially with the client request. Then it will get sent to the root nameserver and again assuming that the entered domain has never been cached. The root nameserver will reply to the resolver with IP address of the TLD nameserver (e.g .com, .net) and if it still not found the request will go the Authoritative nameserver and return it back to the client.
  
 # DNS Encryption 
  
  DNS runs on port 53 (Do53) that is unencrypted protocol, adversaries can perform various attacks against DNS servers. Lately DNS has been introduced to various encryption methods that increase privacy on the other hand, DNS encryption results in impacting cyber security defensive capabilities by having minimum visibility to network defenders by decreasing of the capability of monitoring and detection. There are two methods of DNS encryptions DNS over TLS (DoT) and DNS over HTTPS (DoH), DNS encryption is rapidly being adopted by many browsers like firefox and chrome which are being enabled by default. Both encryption methods use TLS however there is a slight difference between DoT and DoH.
  
 # DNS over TLS (DoT)
  DoT was introduced back in May 2016 similar to many other unsecure protocols like IMAP and HTTP these protocols are over Transport layer security (TLS), and DNS is no different. DoT runs on port 853 With TLS 1.3. keep in mind that when configured properly both client and server can run on other ports rather than 853. In order to successfully establish a DoT connection and encrypt DNS traffic, the client will start initiating a TCP three-way handshake followed by a TLS handshake. 
  
  <p align="center">
<img src="https://user-images.githubusercontent.com/78951224/156123935-6e545385-14b5-4ee2-bb2e-4c1512f60080.png")

</p>
    
 When capturing traffic using a protocol analyser like Wireshark. the above sequence will be seen in the capture TCP handshake followed by TLS handshake on port 853 this would be an encrypted DNS request. If would be decrypted you will see the requested DNS query. Now DoT comes with a handful of benefits. As for end users it will provide a significant increase to their privacy and integrity, for analysts detecting DoT would be easy due to the fact that DoT is running on 853 or pre-determined port.
      
    
# DNS over HTTPS (DoH)
  DNS over HTTPS (DoH) slightly differs from DoT. DoH unlike DoT does not have a dedicated port number DoH runs over port 443 which is the port for HTTPS protocol reducing visibility even further, DoH leverages HTTP/2 minimum. Since the traffic appears as HTTPS Observing that a DNS query has occurred can be proven difficult Without TLS inspection. DoH occurs by employing API’s associated with DNS in addition to enabling web clients to access it A client sends an HTTP POST or GET method as normal HTTPS traffic.   
  
  <p align="center">
<img src="https://user-images.githubusercontent.com/78951224/156123419-8881e58d-5280-48e3-9a8c-c0ef24578c7b.png")

</p>
   
If to capture this process on a protocol analyser all what will be observed is pure HTTPS traffic on port 443. However, if this communication was to be decrypted the above figure will be seen, a dns-query POST request  and the Multipurpose Internet Mail Extensions (MIME) content-type set to application/dns-message and server will respond back with http code 200 OK with the IP address. 
    
# DoT VS DoH

  A really simple way to differentiate between DoT and DoH. Think of it DoT just a simple raw cryptography where there is an encryption, port number and traffic is encrypted. Now DoH is slightly different think of it like cryptography in addition to steganography where DNS request is hidden behind normal HTTPS traffic. 

<p align="center">
<img src="https://user-images.githubusercontent.com/78951224/156122583-3c0c8712-1e05-4026-9fbe-5e4a7d5e1a5b.png")

</p>
  
DoH does not provide any additional layer of privacy except the fact you make blue team life more difficult by diminishing visibility of DNS transaction and bypassing enterprises controls. For individuals DoH does not seem as a bad idea however, in an enterprise environment this could reduce dwell time significantly.
  
# DNS Encryption Detection 
 Both DoT and DoH requires TLS inspection, however DNS over TLS is significantly easier via a simple firewall rule to block outbound TCP port 853, this would result it to downgrade to normal unencrypted DNS query. On the other hand DNS over HTTPS is much more difficult specially without TLS inspection, a simple solution would be blocking known DoH resolvers on port 443 such as (Cloudflare, Google, Adguard …etc). The down fall of this solution is that it would be difficult to block unknown DoH resolvers. An ideal solution to prevent DoH is to employ NGFW and ensure configuration to decrypt HTTPS traffic.
  
  <p align="center">
<img src="https://user-images.githubusercontent.com/78951224/156122759-fbb5f35d-c597-478e-b7a6-80b4605be99b.png")

</p>
