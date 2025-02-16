# venkys_project_1
cybersecurity support tools for offensive attacks

1) MAC ADDRESS CHANGER -A MAC (Media Access Control) address is a unique identifier assigned to a network interface card (NIC) of a device. It consists of 12 hexadecimal characters (e.g., 00:1A:2B:3C:4D:5E) and is used for communication within a local network (LAN).Each device connected to a network, such as a computer, smartphone, or router, has a MAC address assigned by the manufacturer. However, it can be changed using software methods.

------Benefits of Changing Your MAC Address-----

a)Privacy & Anonymity

Websites, networks, and tracking systems use MAC addresses to identify devices. Changing your MAC address helps prevent tracking by internet service providers (ISPs), advertisers, or hackers.
Bypassing Network RestrictionsSome networks impose restrictions based on MAC addresses (e.g., public Wi-Fi with limited time access). Changing your MAC can help bypass these restrictions.

b)Enhanced Security

If your device’s MAC address has been blacklisted from a network, changing it allows you to regain access.
It also helps prevent MAC-based attacks, where hackers clone your MAC address for malicious purposes.
Avoiding Bandwidth Throttling
ISPs sometimes throttle (slow down) internet speeds based on MAC addresses. Changing your MAC can help avoid throttling in some cases.

c)Testing and Development

Developers and network engineers often change MAC addresses to test different network configurations without needing multiple physical devices.

THE MAC.PY FILE CAN BE RUN USING THE FOLLOWING COMMAND ON YOUR KALI VM TERMINAL = python3 mac.py -i eth0 -m 00:11:22:33:44:55

eth0 = preferred interface for changing mac
00:11:22:33:44:55 = new mac address


2) ARP SPOOFER- An ARP Spoofer is a tool used to manipulate the Address Resolution Protocol (ARP) to redirect network traffic. It works by sending fake ARP replies to associate a different MAC address with a target’s IP address, effectively intercepting, modifying, or redirecting traffic within a network.This attack is commonly known as ARP Spoofing or ARP Poisoning and is used in Man-in-the-Middle (MITM) attacks.

How ARP Spoofing Works

Devices in a local network use ARP to map IP addresses to MAC addresses.
For example, if a computer wants to communicate with a router, it sends an ARP request asking, “Who has this IP address?” The router responds with its MAC address.

Spoofing the ARP Table

An attacker sends fake ARP replies, tricking devices into thinking the attacker’s MAC address belongs to a trusted device (like a router or another computer).
As a result, traffic meant for the legitimate device is sent to the attacker instead.

------Benefits of ARP Spoofing------
(For Ethical Use & Security Testing Only!)

a)Ethical hackers and cybersecurity professionals use ARP spoofers to test network vulnerabilities.
Helps identify weaknesses in network security and implement countermeasures.
Packet Sniffing & Traffic Monitoring

b)Used for network analysis and debugging by capturing network traffic.
Can help administrators monitor data flows and detect unauthorized data leaks.
Defensive Security Measures

c)Security teams simulate ARP spoofing attacks to train employees and improve network defenses.
Helps develop Intrusion Detection Systems (IDS) and firewalls to detect ARP spoofing attempts.
Bypassing Network Restrictions

d)In some cases, users can manipulate ARP tables to redirect their own traffic through a different gateway.
Can help bypass firewalls or access restrictions in misconfigured networks.

THE ARP1.PY FILE CAN BE RUN USING THE FOLLOWING COMMAND ON YOUR KALI VM TERMINAL = python3 arp1.py -t 192.168.5.133 -g 192.168.5.2

-t 192.168.5.133 =  -t specifies target ip addr
-g 192.168.5.2 = -g implies gateway addr


3) NETWORK SCANNER - A Network Scanner is a tool used to discover, analyze, and monitor devices within a network. It works by scanning the network for active hosts, open ports, services, and vulnerabilities. Network scanners help administrators map network infrastructure, identify security risks, and manage network performance efficiently.

------Benefits of Network Scanners-----
(For Ethical Use & Network Management Only!)

a) Network Security & Penetration Testing
Ethical hackers and security professionals use network scanners to identify vulnerabilities.
Helps detect unsecured devices, outdated software, and misconfigured systems.

b) Network Monitoring & Troubleshooting
IT administrators use scanners to monitor devices, detect outages, and resolve connectivity issues.
Helps in diagnosing slow networks and identifying unauthorized devices.

c) Asset Management & Inventory
Helps organizations keep track of all network-connected devices.
Useful for updating security policies and ensuring compliance.

d) Detecting Unauthorized Devices & Intrusions
Scanners can detect rogue devices or intruders on a network.
Helps prevent unauthorized access and mitigate cybersecurity threats.

THE NETSCAN1.PY FILE CAN BE RUN USING THE FOLLOWING COMMAND ON YOUR KALI VM TERMINAL =  1) python3 netscan1.py
                                                                                        2) 192.168.5.1/24




4) LOGIN FINDER / BRUTE FORCER - A Login Finder / Brute Forcer is a tool used to automate the process of attempting multiple username and password combinations to gain access to a system, application, or online service. It works by systematically guessing login credentials using predefined wordlists, dictionary attacks, or random character combinations.Brute forcing is commonly used for penetration testing to assess the strength of passwords and identify weak authentication mechanisms.

------Benefits of Login Finders / Brute Forcers------
(For Ethical Use & Security Testing Only!)

a) Password Security Testing
Ethical hackers and cybersecurity experts use brute force tools to test password strength.
Helps identify weak or common passwords used in organizations.

b) Identifying Weak Authentication Mechanisms
Security teams use brute force testing to detect vulnerabilities in login forms, CAPTCHAs, and multi-factor authentication (MFA) bypass techniques.
Helps organizations implement stronger authentication policies.

c) Account Recovery & Penetration Testing
Can be used to recover lost passwords (if allowed by the system).
Helps penetration testers simulate real-world attacks to assess system defenses.

d) Improving Cybersecurity Awareness
Organizations train employees about the risks of weak passwords.
Encourages the use of password managers, two-factor authentication (2FA), and complex passwords.

THE  FILE CAN BE RUN USING THE FOLLOWING COMMAND ON YOUR KALI VM TERMINAL = 1)python3 login_finder.py
                                                                            2) http://vulnweb/login.php

WARNING - MAKE SURE TO MODIFY THE CODE BY SAVING THE PWD.TXT FILE IN A SPECIFIC DIRECTORY AND THEN , ADD THE SAME PATH TO THE CODE IN ORDER FOR THE PROGRAM TO RUN PROPERLY





5) FORM EXTRACTOR - A Form Extractor is a tool used to automatically identify and extract input fields from web forms, applications, or documents. It works by analyzing the HTML structure, metadata, and form fields to gather information such as text boxes, dropdowns, checkboxes, and hidden fields.Form extractors are commonly used for web automation, penetration testing, and data collection.

------BENIFITS & USE CASES------

a) Web Automation & Data Entry
Automates form filling for repetitive tasks such as sign-ups, surveys, and registrations.
Helps businesses save time by pre-filling customer data.

b) Penetration Testing & Security Auditing
Ethical hackers use form extractors to analyze web forms for vulnerabilities.
Helps identify security flaws such as missing CSRF tokens, weak encryption, and hidden field manipulation.

c) Competitive Intelligence & Web Scraping
Used to extract data from pricing forms, customer feedback forms, and competitor websites.
Helps businesses analyze trends and gather insights.

d) Digital Document Processing
Extracts fields from PDFs, invoices, and scanned documents for automated data entry.
Improves efficiency in handling large volumes of forms in industries like finance and healthcare. 

THE  FILE CAN BE RUN USING THE FOLLOWING COMMAND ON YOUR KALI VM TERMINAL = 1)python3 vuln_aka-form_extract.py

WARNING - MAKE SURE TO EDIT THE TARGET URL IN THE CODE BEFORE YOU RUN THE CODE TO GET AN ACCURATE RESULT.





6) PORT SCANNER - A Port Scanner is a tool used to identify open ports and services on a target device or network. It works by sending probe requests to a range of ports and analyzing the responses to determine which ports are open, closed, or filtered.Port scanning is commonly used in network security, penetration testing, and system administration to detect vulnerabilities and manage network services.


------Benefits of Port Scanners------
(For Ethical Use & Security Testing Only!)

a) Network Security & Vulnerability Assessment
Identifies open and vulnerable ports that could be exploited by hackers.
Helps firewall configuration and intrusion detection.

b) System & Service Management
Allows administrators to monitor active services and close unnecessary ports.
Helps in troubleshooting network connectivity issues.

c) Ethical Hacking & Penetration Testing
Security professionals use port scanners to simulate cyberattacks and test defense mechanisms.
Helps in assessing firewall effectiveness and network hardening.

d) Detecting Unauthorized Services
Scans for unwanted or malicious services running on a network.
Useful for finding backdoors, botnets, and unauthorized access points.

THE  FILE CAN BE RUN USING THE FOLLOWING COMMAND ON YOUR KALI VM TERMINAL = 1)PYTHON3 PORT.PY
                                                                            2) 192.168.5.134






7) LINK FINDER - A Link Finder is a tool used to analyze and extract URLs (links) from a webpage, website source code, or network traffic. It works by scanning HTML, JavaScript, and API responses to identify internal and external links, hidden endpoints, or sensitive URLs.Link finders are commonly used for web crawling, penetration testing, and SEO analysis.


------Benefits of Link Finders------
(For Ethical Use & Web Analysis Only!)

a) Web Scraping & Data Collection
Extracts links for automated crawling, research, and content indexing.
Useful for collecting data from blogs, e-commerce sites, and public resources.

b) Security Testing & Ethical Hacking
Helps penetration testers find sensitive URLs, API endpoints, and admin panels.
Detects unprotected files, backup directories, and hidden login pages.

c) SEO & Website Optimization
Helps SEO experts find broken links, orphan pages, and duplicate content.
Analyzes website structure for better indexing and ranking.

d) Identifying Hidden & Vulnerable Endpoints
Security researchers use link finders to uncover misconfigured access controls.
Detects API keys, authentication endpoints, and exposed admin areas.


THE  FILE CAN BE RUN USING THE FOLLOWING COMMAND ON YOUR KALI VM TERMINAL = 1)PYTHON3 SPY_AKA_FILL_LINK_FIND.PY

WARNING - MAKE SURE TO EDIT THE TARGET URL IN THE CODE BEFORE YOU RUN THE CODE TO GET AN ACCURATE RESULT.




8) PACKET SNIFFER - A Packet Sniffer is a tool used to capture, analyze, and monitor network traffic in real time. It works by intercepting data packets traveling through a network, allowing users to examine the contents, identify issues, and monitor network activity.Packet sniffing is commonly used for network security, troubleshooting, and penetration testing.


------Benefits of Packet Sniffers------
(For Ethical Use & Network Monitoring Only!)

a) Network Security & Intrusion Detection
Helps security professionals detect unauthorized access, malware, and cyber threats.
Monitors network activity for suspicious behavior and data leaks.

b) Troubleshooting & Performance Optimization
IT administrators use packet sniffers to diagnose network issues, slow connections, and dropped packets.
Identifies bottlenecks and misconfigurations in a network.

c) Protocol & Traffic Analysis
Helps developers and researchers analyze network protocols and understand data flow.
Useful for optimizing network efficiency and identifying inefficient data transfers.

d) Ethical Hacking & Penetration Testing
Ethical hackers use packet sniffers to test network security and identify unencrypted sensitive data.
Helps organizations harden defenses against cyberattacks.

THE  FILE CAN BE RUN USING THE FOLLOWING COMMAND ON YOUR KALI VM TERMINAL = 1)PYTHON3 PACKETSNIFF1.PY

WARNING - MAKE SURE TO EDIT THE TARGET INTERFACE IN THE CODE BEFORE YOU RUN THE CODE TO GET AN ACCURATE RESULT. ALSO RUN THE ARP SPOOFER CODE FIRST ON THE TARGET DEVICE TO GET A MORE ACCURATE REUSLT 




9) DNS SPOOFER- A DNS Spoofer is a tool used to manipulate the Domain Name System (DNS) by redirecting a target’s request for a website to a malicious or unintended IP address. It works by intercepting and altering DNS responses to mislead users into visiting a fake website or diverting network traffic.This attack is commonly known as DNS Spoofing or DNS Poisoning and is often used in Man-in-the-Middle (MITM) attacks.

------Benefits of DNS Spoofers------
(For Ethical Use & Security Testing Only!)

a) Cybersecurity & Penetration Testing
Ethical hackers use DNS spoofers to test DNS vulnerabilities in corporate networks.
Helps identify weak DNS configurations and implement stronger defenses.

b) Web Filtering & Parental Control
Organizations and parents can redirect users away from harmful or restricted websites.
Useful for blocking phishing sites, malware, and social media distractions.

c) Network Traffic Redirection & Testing
IT professionals use DNS spoofing for load balancing, network diagnostics, and monitoring.
Can be used to test how applications handle incorrect DNS responses.

d) Education & Research
Security researchers study DNS spoofing techniques to develop countermeasures.
Helps in training cybersecurity teams on real-world attack scenarios.

THE  FILE CAN BE RUN USING THE FOLLOWING COMMAND ON YOUR KALI VM TERMINAL = 1)PYTHON3 DNS.PY

WARNING - MAKE SURE TO EDIT THE TARGET INTERFACE IN THE CODE BEFORE YOU RUN THE CODE TO GET AN ACCURATE RESULT
WARNING - ALSO RUN THE ARP SPOOFER CODE FIRST ON THE TARGET DEVICE TO GET A MORE ACCURATE REUSLT 
WARNING - MAKE SURE TO MODIFY THE CODE BY SAVING THE BLOCKED_DOMAINS.TXT FILE IN A SPECIFIC DIRECTORY AND THEN , ADD THE SAME PATH TO THE CODE IN ORDER FOR THE PROGRAM TO RUN PROPERLY




10) CAESER CIPHER MAKER - A Caesar Cipher Maker is a tool used to encrypt and decrypt text using the Caesar cipher, a simple substitution cipher that shifts letters in the alphabet by a fixed number of positions. This encryption method was historically used by Julius Caesar to send confidential messages.It is commonly used for basic encryption, educational purposes, and cryptography exercises.

How the Caesar Cipher Works
The cipher shifts each letter in the plaintext by a fixed number (known as the shift key).

Encryption Example (Shift Key = 3)
Plaintext: HELLO
Shift by 3: KHOOR
Each letter moves three places forward in the alphabet (H → K, E → H, etc.).

Decryption Example (Shift Key = 3)
Ciphertext: KHOOR
Shift back by 3: HELLO
By reversing the shift, the original message is recovered.

------Benefits of a Caesar Cipher Maker------
(For Educational & Security Awareness Use Only!)

a) Learning Cryptography Basics
Introduces beginners to encryption concepts and classical ciphers.
Helps in understanding how substitution ciphers work before learning advanced encryption.

b) Secure Simple Messages
Can be used for basic message encryption where strong security isn’t required.
Useful for puzzle-making, secret notes, and basic obfuscation.

c) Programming & Algorithm Development
Useful for learning coding techniques in Python, Java, and other languages.
Helps students and developers practice string manipulation and algorithms.

d) Escape Rooms & Puzzle Games
Frequently used in puzzle challenges, treasure hunts, and escape room games.
Players need to decode messages by identifying the shift value.


THE  FILE CAN BE RUN USING THE FOLLOWING COMMAND ON YOUR KALI VM TERMINAL = 1)PYTHON3 CAESER.PY

WARNING - ALPHABET SET => abcdefghijklmnopqrstuvwxyz0123456789



11) DEAUTHNETICATION ATTACK DETECTOR- A Deauthentication Attack Detector is a tool designed to identify and prevent deauthentication attacks on Wi-Fi networks. These attacks, also known as Wi-Fi deauth attacks, exploit the 802.11 deauthentication frame to forcibly disconnect devices from a network.The detector monitors network traffic for suspicious deauth packets and alerts users or network administrators when an attack is detected.


------Benefits of a Deauthentication Attack Detector------
(For Ethical Use & Network Security Only!)

a) Detecting & Preventing Wi-Fi Attacks
Identifies suspicious deauth packets on the network.
Alerts users when a potential deauthentication attack is happening.

b) Securing Wireless Networks
Helps protect home and enterprise Wi-Fi networks from hackers.
Can be used by IT teams and security professionals to monitor network integrity.

c) Improving Incident Response
Detecting attacks early allows quick response actions like:
Changing Wi-Fi security settings.
Enabling Management Frame Protection (MFP).
Switching to wired connections when under attack.

d) Ethical Hacking & Penetration Testing
Security researchers use deauth detectors to test the resilience of networks.
Helps identify weaknesses in Wi-Fi security configurations.

THE  FILE CAN BE RUN USING THE FOLLOWING COMMAND ON YOUR KALI VM TERMINAL = 1)PYTHON3 DEAUTHENTICATION.PY




12) WEB CRAWLER - A Web Crawler, also known as a Web Spider or Web Scraper, is a tool used to systematically browse and index web pages. It works by following hyperlinks, extracting data, and storing information for search engines, data analysis, or web automation.Web crawlers are widely used by search engines, cybersecurity professionals, and businesses for data collection and web monitoring.

------Benefits of Web Crawlers------
(For Ethical Use & Data Collection Only!)

a) Search Engine Indexing & SEO Optimization
Used by Google, Bing, and other search engines to index web pages.
Helps website owners improve SEO rankings and visibility.

b) Data Extraction & Market Research
Collects pricing, product details, reviews, and competitor information.
Useful for business intelligence, lead generation, and trend analysis.

c) Cybersecurity & Web Monitoring
Security teams use crawlers to scan websites for vulnerabilities (e.g., exposed directories).
Helps detect phishing websites, malware, and unauthorized content.

d) Automating Web Tasks
Automates web scraping, content aggregation, and data entry.
Saves time in news tracking, stock market analysis, and academic research.



THE  FILE CAN BE RUN USING THE FOLLOWING COMMAND ON YOUR KALI VM TERMINAL = 1)PYTHON3 CRAW.PY

WARNING - MAKE SURE TO EDIT THE TARGET URL IN THE CODE BEFORE YOU RUN THE CODE TO GET AN ACCURATE RESULT.

