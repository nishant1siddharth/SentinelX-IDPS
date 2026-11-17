# SentinelX – Real-Time Intelligent Intrusion Detection and Prevention System (IDPS)



**A Network Intrusion Detection, Automated Response, and Monitoring Laboratory**



SentinelX is a laboratory-based Intrusion Detection and Prevention System (IDPS) developed to monitor network traffic, detect configured suspicious activities, generate security alerts, and automatically block selected attack sources.



It integrates **Suricata, Python, nftables, Flask, and VMware Workstation** to demonstrate a practical threat detection and automated response workflow in an isolated virtual environment.



The project demonstrates how network monitoring, intrusion detection, automated firewall enforcement, and web-based security monitoring can work together.



\---



## 1. Key Features



\- Real-time network traffic monitoring using Suricata.

\- Custom Suricata intrusion detection rules.

\- ICMP Echo Request detection.

\- TCP SYN scan detection.

\- Suricata EVE JSON alert processing using Python.

\- Automated source IP blocking using nftables for the configured TCP SYN scan alert.

\- Firewall block verification by the Python response engine.

\- Flask-based web dashboard.

\- Controlled attack simulation using Kali Linux.

\- Connectivity testing before and after automated blocking.

\- Recovery testing after removing a blocked IP address.



## 2. System Architecture



SentinelX operates as an IDPS server between two isolated virtual laboratory networks.



```mermaid

flowchart TD

&#x20;   A\["Kali Linux<br/>Attacker"] --> B\["SentinelX<br/>Ubuntu Server"]

&#x20;   B --> C\["Suricata<br/>Traffic Monitoring and Detection"]

&#x20;   C --> D\["EVE JSON<br/>Security Alerts"]

&#x20;   D --> E\["Python<br/>Automated Response Engine"]

&#x20;   E --> F\["nftables<br/>Firewall and IP Blocking"]

&#x20;   F --> G\["Metasploitable2<br/>Target"]



&#x20;   C --> H\["Flask Web Dashboard"]

&#x20;   E --> H

```



### Detection and Response Workflow



1\. Kali Linux generates controlled network traffic.

2\. Suricata monitors traffic through the configured laboratory interfaces.

3\. Custom rules identify matching network activity.

4\. Suricata records security alerts in its EVE JSON log.

5\. The Python response engine processes the generated alerts.

6\. When the configured TCP SYN scan signature is detected, the response engine requests nftables to block the source IP address.

7\. The response engine verifies the blocking operation.

8\. Connectivity testing confirms the effect of the firewall block.

9\. Removing the block restores connectivity.



## 3. Laboratory Environment



The project was implemented using VMware Workstation Pro with three virtual machines.



| Virtual Machine | Role | IP Address |

|---|---|---|

| SentinelX (Ubuntu Server) | IDPS server | 192.168.56.30 / 192.168.57.1 |

| Kali Linux | Attacker and testing machine | 192.168.56.10 |

| Metasploitable2 | Vulnerable target | 192.168.57.10 |



### Network Segmentation



| Network | Purpose |

|---|---|

| 192.168.56.0/24 | Attacker-side laboratory network |

| 192.168.57.0/24 | Target-side laboratory network |



SentinelX has interfaces connected to both laboratory networks and uses firewall rules to control forwarded traffic.



## 4. Technologies Used



| Technology | Version | Purpose |

|---|---|---|

| Ubuntu Server | 24.04.3 LTS | IDPS server |

| Kali Linux | 2026.2 | Attack simulation |

| Metasploitable2 | — | Vulnerable target |

| Suricata | 7.0.3 | Network intrusion detection |

| Python | 3.12.3 | Automated response engine |

| nftables | — | Firewall and dynamic IP blocking |

| Flask | 3.1.3 | Web dashboard |

| Nmap | — | Network scanning |

| VMware Workstation Pro | — | Virtual laboratory |



## 5. Custom Suricata Detection Rules



SentinelX implements two custom detection rules.



| Signature ID (SID) | Detection | Action |

|---|---|---|

| 1000001 | ICMP Echo Request | Generates a detection alert |

| 1000002 | TCP SYN Scan | Generates an alert and triggers the configured automated response |



**Important:** Automated IP blocking is configured for SID 1000002. The ICMP rule generates alerts but does not independently trigger automatic blocking.



## 6. Automated Response Mechanism



The Python response engine monitors Suricata's EVE JSON events and processes alerts matching its configured response criteria.



For the configured TCP SYN scan alert, it:



\- Extracts the attacker's source IP address.

\- Requests nftables to add the IP address to the blocklist.

\- Verifies whether the blocking operation was successful.

\- Records the response result.



The nftables firewall controls forwarded traffic between the attacker-side and target-side networks.



## 7. Project Structure



```text

SentinelX-IDPS/

│

├── dashboard/

│   ├── app.py

│   ├── templates/

│   │   └── index.html

│   └── static/

│       ├── css/

│       │   └── style.css

│       └── js/

│           └── dashboard.js

│

├── firewall/

│   └── nftables.conf

│

├── response-engine/

│   └── auto\_response.py

│

├── screenshots/

│   ├── 01-Suricata-Alert.png

│   ├── 02-Automated-Response.png

│   ├── 03-NFTables-Blocklist.png

│   ├── 04-Kali-Blocked-Ping.png

│   ├── 05-SentinelX-Dashboard.png

│   └── 06-Network-Monitoring-Topology.png

│

├── suricata/

│   ├── suricata.yaml

│   └── rules/

│       └── local.rules

│

├── systemd/

│   └── sentinelx-response.service

│

├── docs/

│   └── SentinelX\_Labmentix\_Project\_Report.docx

│

├── .gitignore

└── README.md

```



## 8. Screenshots and Implementation Evidence



### 8.1 Suricata Detection Alert



Shows the security alert generated by Suricata.



!\[Suricata Detection Alert](screenshots/01-Suricata-Alert.png)



### 8.2 Python Automated Response



Shows the Python response engine processing a matching security alert.



!\[Automated Response](screenshots/02-Automated-Response.png)



### 8.3 nftables Blocklist



Shows the firewall blocklist containing the blocked source IP.



!\[nftables Blocklist](screenshots/03-NFTables-Blocklist.png)



### 8.4 Blocked Attacker Connectivity



Shows the connectivity test after the attacker's IP address has been blocked.



!\[Blocked Ping](screenshots/04-Kali-Blocked-Ping.png)



### 8.5 SentinelX Dashboard



Shows the Flask-based web dashboard.



!\[SentinelX Dashboard](screenshots/05-SentinelX-Dashboard.png)



### 8.6 Network Monitoring Topology



Shows the virtual laboratory network topology.



!\[Network Topology](screenshots/06-Network-Monitoring-Topology.png)



## 9. Testing and Verification



The following tests were performed in the controlled virtual laboratory.



| Test | Result |

|---|---|

| Suricata TCP SYN scan detection | Successful |

| Python alert processing | Successful |

| Automated nftables IP blocking | Successful |

| Firewall block verification | Successful |

| Connectivity interruption after blocking | Successful |

| Connectivity restoration after block removal | Successful |

| Flask dashboard verification | Successful |



These tests verified the configured detection, response, blocking, and recovery workflow.



## 10. Installation and Configuration Notes



SentinelX was developed for a specifically configured VMware virtual laboratory.



The repository includes the principal implementation files:



\- Suricata configuration and custom rules.

\- Python automated response engine.

\- nftables firewall configuration.

\- systemd response service.

\- Flask dashboard application.



To reproduce the project, the laboratory networks, network interfaces, IP addresses, software dependencies, file paths, permissions, and firewall settings must be configured appropriately.



The supplied configuration files are specific to the demonstrated laboratory environment. They require review and adaptation before use in another environment.



## 11. Project Report



The detailed project report is available in the repository:



\[View SentinelX Project Report](docs/SentinelX\_Labmentix\_Project\_Report.docx)



## 12. Safety and Disclaimer



SentinelX is developed for educational purposes, cybersecurity learning, and authorized security testing.



Attack simulations and response verification were conducted in a controlled virtual laboratory.



Do not use this project to scan, monitor, access, or disrupt systems and networks without explicit authorization.



The supplied configurations are laboratory-specific and should not be deployed in production environments without appropriate security review and testing.



\---



## Author



**Siddharth Kumar**



B.Tech – Computer Science and Engineering



**Project:** SentinelX – Real-Time Intelligent Intrusion Detection and Prevention System (IDPS)



**GitHub Repository:**

https://github.com/nishant1siddharth/SentinelX-IDPS



\---



**SentinelX – Detect. Respond. Protect.**
