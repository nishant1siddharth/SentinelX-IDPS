\# SentinelX – Real-Time Intelligent Intrusion Detection and Prevention System (IDPS)



SentinelX is a laboratory-based Intrusion Detection and Prevention System designed to monitor network traffic, detect suspicious activities, generate security alerts, and automatically block detected attack sources.



Built using Suricata, Python, nftables, Flask, and VMware Workstation.



\## Features

\- Real-time network traffic monitoring.

\- Custom Suricata detection rules.

\- ICMP and TCP SYN scan detection.

\- Python-based automated threat response.

\- Automatic IP blocking using nftables.

\- Flask web dashboard.

\- Controlled attack simulation and recovery testing.



\## Architecture



Kali Linux (Attacker: 192.168.56.10)

→ SentinelX (Ubuntu Server)

→ Suricata Detection

→ Python Response Engine

→ nftables Firewall

→ Metasploitable2 (Target: 192.168.57.10)



\## Technologies



| Technology | Purpose |

|---|---|

| Ubuntu Server 24.04.3 | IDPS server |

| Kali Linux 2026.2 | Attack simulation |

| Metasploitable2 | Vulnerable target |

| Suricata 7.0.3 | Threat detection |

| Python 3.12.3 | Automated response |

| nftables | Firewall and IP blocking |

| Flask 3.1.3 | Web dashboard |

| Nmap | Network scanning |

| VMware Workstation Pro | Virtual lab |



\## Custom Detection Rules



| SID | Detection |

|---|---|

| 1000001 | ICMP Echo Request |

| 1000002 | TCP SYN Scan |



The automated response engine is configured to respond to SID 1000002.



\## Verified Test Results

\- Suricata successfully detected TCP SYN scanning.

\- Python processed the corresponding security alert.

\- nftables successfully blocked the attacker's IP.

\- Connectivity from the blocked attacker to the target failed.

\- Connectivity was restored after removing the blocklist entry.

\- Dashboard functionality was verified.



\## Lab Network



| Component | IP Address |

|---|---|

| Kali Linux | 192.168.56.10 |

| SentinelX attacker interface | 192.168.56.30 |

| SentinelX target interface | 192.168.57.1 |

| Metasploitable2 | 192.168.57.10 |



\## Safety Notice



This project is intended for educational purposes and authorized testing in an isolated virtual laboratory. Do not use it against networks or systems without permission.



Configuration files are specific to the demonstrated lab and must be reviewed before use in another environment.



\## Future Scope

\- Machine-learning-based anomaly detection.

\- Risk-based threat scoring.

\- Security event correlation.

\- Additional detection rules.

\- Improved dashboard analytics and notifications.



These are proposed future enhancements, not implemented features.



\## Author



\*\*Siddharth Kumar\*\*

B.Tech – Computer Science and Engineering



\*\*Project:\*\* SentinelX – Real-Time Intelligent Intrusion Detection and Prevention System (IDPS)
