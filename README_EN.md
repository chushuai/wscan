# wscan
Wscan is a web security scanner that focuses on WEB security. It pays homage to Nmap, which has been open source for 25 years. We also plan to continuously update and keep Wscan open source for the next 25 years. We welcome anyone interested in web security to join our development team.

Our goal is to develop a tool for penetration testing using machine learning. Unlike other tools, our tool can automatically learn attack and defense patterns and launch personalized attacks based on specific targets. This way, our attack efficiency and accuracy will be significantly improved, while also reducing the probability of false positives.

Our tool employs machine learning technology to achieve fully automated web penetration testing. This means there is no need for manual addition and update of rules and signatures; it can automatically learn and adapt to new attack patterns and vulnerabilities.

Machine learning technology can also quickly process large amounts of data and traffic, thereby greatly improving testing efficiency and accuracy. In addition, it can identify and discover vulnerabilities and weaknesses that are difficult for humans to perceive, thus enhancing testing quality and reliability.

We believe that using machine learning technology for penetration testing will be a crucial direction for the future of network security. We hope that our tool can help more people safeguard network security and contribute to the field of network security.
![](https://ctstack-oss.oss-cn-beijing.aliyuncs.com/tool/github/9f9e48711df62c154bde487c989dd3a9.gif)
# Example Usage 
⬇️[Download Link](https://github.com/chushuai/wscan/releases)
```
(1) Active Scan
./wscan --log-level=debug ws --basic-crawler http://testphp.vulnweb.com/
./wscan --log-level=debug ws --url http://testphp.vulnweb.com/listproducts.php?cat=1

(2) Passive Scan
./wscan --log-level=debug ws --listen=127.0.0.1:1000
```




# Project Updates
2023.11.05: Released v1.0.0 binary version, supporting basic web common vulnerability detection.  
2023.11.12: Released v1.0.1 binary version, introducing a static crawler.  
2023.11.12: Released v1.0.2 binary version, adding support for passive scanning.  
2023.11.19: Released v1.0.3 binary version, incorporating JSONP plugin support.  
2023.11.26: Released v1.0.4 binary version, addressing issues related to false negatives in XSS and SQL injection, and now supporting vulnerability detection for individual URLs.  

# The open-source schedule is outlined as follows  
Wscan's goal is to create an open-source and non-profit project. However, due to the substantial workload involved in Wscan,
the code is still undergoing rapid iterations. Premature open-sourcing may lead to the emergence of various modified versions, 
which is not conducive to the tool's dissemination and the future development of the project. 
Therefore, the plan is to open-source the project in stages and modules, using Stars as a metric, 
to ensure the robustness of the project and organized community participation.

1.  YAML POC Scan Module (Open source when Stars > 400)  
2.  Reverse Connection Module (Open source when Stars > 400)  
3.  SQL Injection Module (Open source when Stars > 500)  
4.  Dynamic Crawler (Open source when Stars > 600)  
5.  Directory Scan Module (Open source when Stars > 700)  
6.  Baseline Scan (Open source when Stars > 800)  
7.  Plugin Scheduling Module Based on Message Subscription (Open source when Stars > 900)  
8.  HTTP Parameter Deformation Module; Traditional Scan Modules All Open Source; Users can modify, compile, and build scanners on their own (Open source when Stars > 1k)  
9.  Machine Learning Module to Reduce False Positives (Open source when Stars > 3k)  
10. Machine Learning Module for Automatic Payload Generation (Open source when Stars > 4k)  