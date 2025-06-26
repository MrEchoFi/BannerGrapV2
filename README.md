<div align="center">
    <img src="https://github.com/MrEchoFi/BannerGrapV2/blob/master/BannerGrapV2_Security_Scanner_Tool_1d0e04fd-c100-4173-88b9-52a99f69fc2b.jpeg?raw=true" alt="gif" width="730" height="auto" />

</div>

<div align="center">
  <img src="https://github.com/MrEchoFi/MrEchoFi/raw/4274f537dec313ac7dde4403fe0fae24259beade/Mr.EchoFi-New-Logo-with-ASCII.jpg" alt="logo" width="265" height="auto" />
  <h1>BannerGrapV2</h1>
   
  <p>
    By this DevSecOps Based' tool you can-> Recon, vuln discovery, brute force, attack surface mapping, reporting, exploit probing,Asset inventory, vuln management, credential hygiene, exposure monitoring, IR, compliance.
  </p>


  📫 How to reach me  **http://mrechofi.github.io/Tanjib_portfolio_website/**, **tanjibisham777@gmail.com & tanjibisham888@gmail.com**
## Video For Better Understanding:


https://github.com/user-attachments/assets/d4bfc9ff-5fc2-4932-bc7e-e6d827cabf0b


 </div>

# Deacription:
BannerGrap V2 is a powerful, modular, and extensible Golang & DevSecOps based security scanner designed for advanced reconnaissance and vulnerability assessment across a wide range of network services.
It combines classic banner grabbing with active vulnerability probing, CVE/exploit matching, brute force stubs, and reporting, making it a valuable tool for penetration testers, red teamers, and defenders.

# ### Key Features:
# Red Team (Offensive Security) Uses:
<p>
 <li>Reconnaissance & Enumeration:
Quickly map out all live hosts, open ports, and running services across a target network. </li>
 
<li>Vulnerability Discovery:
Automatically detect outdated, misconfigured, or vulnerable software (Ex:, Apache, Nginx, SSH, FTP, etc.) using banner analysis and CVE matching. </li>

<li>Active Exploitation Probing:
Use built-in probes (Heartbleed, Shellshock, Log4Shell) to safely check for critical vulnerabilities.</li>

<li>Brute Force Attacks:
Attempt SSH brute force with custom or well-known username/password lists to identify weak credentials and gain initial access.</li>

<li>Attack Surface Mapping:
Identify hidden admin panels, anonymous FTP, and other risky exposures for further exploitation.</li>

<li>Automated Reporting:
Generate structured reports (JSON, CSV, HTML) for documentation, pivoting, or sharing with the team.</li>
</p>

# Blue Team (Defensive Security) Uses:
<p>
<li> Asset Inventory:
Continuously scan internal and external networks to maintain an up-to-date inventory of all exposed services and their versions.</li>
 
<li>Vulnerability Management:
Detect and prioritize patching of vulnerable software before attackers can exploit them.</li>

<li>Credential Hygiene:
Test for weak or default SSH credentials across the environment to enforce strong authentication policies.</li>

<li>Exposure Monitoring:
Identify accidental exposures (Ex: open admin panels, anonymous FTP, legacy protocols) and reduce the attack surface.</li>

<li>Incident Response:
Use the tool during or after a breach to quickly assess what services and vulnerabilities were exposed.</li>

<li>Compliance & Audit:
Provide evidence of regular scanning and vulnerability management for compliance frameworks (PCI, HIPAA, etc.).</li>
</p>

# Support:
<li>Multi-Protocol Support:
Scan HTTP, HTTPS, HTTP/2, WebSocket, FTP, SMTP, SSH, Telnet, and more.</li>

<li>Banner Grabbing:
Collects service banners and fingerprints for rapid identification.</li>

<li>Signature-Based Vulnerability Detection:
Detects 50+ popular server products and flags known vulnerable versions.</li>

<li>Active Probes:
Includes safe, practical stubs for Heartbleed, Shellshock, and Log4Shell detection.</li>

<li>CVE/Exploit DB Integration:
Matches banners to known CVEs using regex and can be extended for real DB integration.</li>

<li>Brute Force & Enumeration Stubs:
Framework for credential brute forcing and service enumeration.</li>

<li>Reporting:
Outputs results in JSON, CSV, and HTML formats for easy integration and sharing.</li>

<li>Concurrency:
Fast, multi-threaded scanning for large-scale assessments.</li>

<li>Extensible:
Plugin system and modular codebase for easy feature expansion.</li>

# ## Installation Process:
         //~// You can run this tool in three ways:
         @~1st way: 
         # Install git
           sudo apt install git

         # Install golang
           sudo apt install golang

         # Clone My Repo
         git clone https://github.com/MrEchoFi/BannerGrapV2.git

         # Change Directory
            cd BannerGrapV2

         # run the tool and follow its 'bannerGrap_Guid or Usage.txt'; but specially read & follow this-> 'New_advanced_bashScripts.md' for full usage of guidelines. By             this guidline u can use this tool in aggressive mode, basic mode and intermediate mode.
           
           go run bannerGrap.go

           or, run this as-> go build bannerGrap.go
           then run this,    ./bannerGrap

           //follow the guidline- 'New_advanced_bashScripts.md' for better bash scripting .. 


           @~2nd way using "Docker" for Containerized performence with safety/lab:

           git clone <github link>
           cd BannerGrapV2

           # run the tool and follow its 'bannerGrap_Guid or Usage.txt'; but specially read & follow this-> 'New_advanced_bashScripts.md' for full usage of guidelines. By             this guidline u can use this tool in aggressive mode, basic mode and intermediate mode.

           # Build the Docker image
           docker build -t bannerv2 .

           then run:
           docker run bannerv2

           Test Tool in Container with more clean (Optional):
           docker run --rm bannerv2 

           //follow the guidline- 'New_advanced_bashScripts.md' for better bash scripting .. 


           @~ Using Kubernetes + Decker:

           ### Minikube Setup:
         # This will spin up your local K8s cluster using your WSL2 Docker
         
            minikube start --driver=docker

         # Optional: enable the default storageclass and dashboard
         
            minikube addons enable default-storageclass
            minikube addons enable dashboard

          # Now start the benner or setup the banner.sh:
             
             chmod +x start_banner.sh
        then run: 
             ./start_banner.sh

             # run the tool and follow its 'bannerGrap_Guid or Usage.txt'; but specially read & follow this-> 'New_advanced_bashScripts.md' for full usage of guidelines.  By this guidline u can use this tool in aggressive mode, basic mode and intermediate mode.

           # Convert using 'chmod':
              chmod +x run_bannerv2.sh

         # Run like this:
              ./run_bannerv2.sh <target ip> <port> --proto http https --threads 20 --timeout 8 --o scan.csv --v

         //follow the guidline- 'New_advanced_bashScripts.md' for better bash scripting .. 
              

           
           
           

# How It Helps in the Cyber World:

<li>Penetration Testing:
Quickly identifies exposed and vulnerable services across networks.</li>

<li>Red Team Operations:
Automates reconnaissance and initial access vector discovery.</li>

<li>Blue Team/Defensive Security:
Assists in asset inventory, vulnerability management, and attack surface reduction.</li>

<li>DevSecOps Operation:
Identify vulnerabilities and can do exploits, reconnaissance, find hidden banner & dir etc. </li>

<li>Education & Research:
Teaches protocol analysis, vulnerability detection, and Go security programming.</li>





