```bash
 ▗▄▄▖ ▗▄▄▖ ▗▄▖ ▗▖  ▗▖    ▗▄▄▄▖▗▄▄▄▖ ▗▄▄▖▗▖ ▗▖▗▖  ▗▖▗▄▄▄▖▗▄▄▄▖ ▗▖ ▗▖▗▄▄▄▖ ▗▄▄▖
▐▌   ▐▌   ▐▌ ▐▌▐▛▚▖▐▌      █  ▐▌   ▐▌   ▐▌ ▐▌▐▛▚▖▐▌  █  ▐▌ ▐▌ ▐▌ ▐▌▐▌   ▐▌   
 ▝▀▚▖▐▌   ▐▛▀▜▌▐▌ ▝▜▌      █  ▐▛▀▀▘▐▌   ▐▛▀▜▌▐▌ ▝▜▌  █  ▐▌ ▐▌ ▐▌ ▐▌▐▛▀▀▘ ▝▀▚▖
▗▄▄▞▘▝▚▄▄▖▐▌ ▐▌▐▌  ▐▌      █  ▐▙▄▄▖▝▚▄▄▖▐▌ ▐▌▐▌  ▐▌▗▄█▄▖▐▙▄▟▙▖▝▚▄▞▘▐▙▄▄▖▗▄▄▞▘
                                                                             
```

# Scan Techniques

```bash

  [3.1]
    //Scan 1,000 hosts, all on port 443 via HTTPS, with custom headers, 200 concurrent workers, and dump to CSV:

   go run bannerGrap.go \
  -f thousand_hosts.txt \
  -proto https \
  -port 443 \
  -payload "GET /status HTTP/1.1\r\nHost: %s\r\nUser-Agent: BannerBot/1.0\r\n\r\n" \
  -threads 200 \
  -timeout 3 \
  -o full_scan.csv

  //Scan 1,000 hosts, all on port 443 via HTTPS, with custom headers, 200 concurrent workers, and dump to JSON:

  go run bannerGrap.go \
  -f thousand_hosts.txt \
  -proto https \
  -port 443 \
  -payload "GET /status HTTP/1.1\r\nHost: %s\r\nUser-Agent: BannerBot/1.0\r\n\r\n" \
  -threads 200 \
  -timeout 3 \
  -o full_scan.json

  //Scan 1,000 hosts, all on port 443 via HTTPS, with custom headers, 200 concurrent workers, and dump to console:

  go run bannerGrap.go \
  -f thousand_hosts.txt \
  -proto https \
  -port 443 \
  -payload "GET /status HTTP/1.1\r\nHost: %s\r\nUser-Agent: BannerBot/1.0\r\n\r\n" \
  -threads 200 \
  -timeout 3 \
  -o full_scan.txt

  //Scan 1,000 hosts, all on port 443 via HTTPS, with custom headers, 200 concurrent workers, and dump to console:

  go run bannerGrap.go \
  -f thousand_hosts.txt \
  -proto https \
  -port 443 \
  -payload "GET /status HTTP/1.1\r\nHost: %s\r\nUser-Agent: BannerBot/1.0\r\n\r\n" \
  -threads 200 \
  -timeout 3 \
  -o full_scan.txt


 [3.2] //  Massive HTTPS Scan with Custom Header & CSV Output: Scan 10 000 domains over TLS, 500 threads, 2 s timeout, dump to CSV-
 
 go run bannerGrap.go \
  -f ten_thousand_domains.txt \
  -proto https \
  -port 443 \
  -payload "GET / HTTP/1.1\r\nHost: %s\r\nUser-Agent: AggroBot/5.0\r\nAccept: */*\r\n\r\n" \
  -threads 500 \
  -timeout 2 \
  -o https_scan_results.csv

 //  Massive HTTPS Scan with Custom Header & JSON Output: Scan 10 000 domains over TLS, 500 threads, 2 s timeout, dump to JSON-

 go run bannerGrap.go \
  -f ten_thousand_domains.txt \
  -proto https \
  -port 443 \
  -payload "GET / HTTP/1.1\r\nHost: %s\r\nUser-Agent: AggroBot/5.0\r\nAccept: */*\r\n\r\n" \
  -threads 500 \
  -timeout 2 \
  -o https_scan_results.json

 //  Massive HTTPS Scan with Custom Header & Console Output: Scan 10 000 domains over TLS, 500 threads, 2 s timeout, dump to console-

 go run bannerGrap.go \
  -f ten_thousand_domains.txt \
  -proto https \
  -port 443 \
  -payload "GET / HTTP/1.1\r\nHost: %s\r\nUser-Agent: AggroBot/5.0\r\nAccept: */*\r\n\r\n" \
  -threads 500 \
  -timeout 2 \
  -o https_scan_results.txt

 [3.3] Ultra-Fast HTTP Sweep on IP Range: Hit 192.168.1.1–254 on port 80 with 254 threads and 1 s timeout-

 go run bannerGrap.go \
  -f thousand_hosts.txt \
  -proto http \
  -port 80 \
  -payload "GET / HTTP/1.1\r\nHost: %s\r\nUser-Agent: AggroBot/5.0\r\nAccept: */*\r\n\r\n" \
  -threads 254 \
  -timeout 1 \
  -o http_sweep.csv

//////
go run banner_grabber.go \
  -f <(for i in $(seq 1 254); do echo \"192.168.1.$i\"; done) \
  -proto http \
  -threads 254 \
  -timeout 1
  -o http_sweep.csv
  -o http_sweep.json
  -o http_sweep.txt

[3.4] SMTP Banner Harvesting in Bulk (JSON): Pull EHLO banners from mail servers list, override port to 25, output JSON-
      
//Pull EHLO banners from mail servers list, override port to 25, output JSON-
  go run bannerGrap.go \
  -f mail_hosts.txt \
  -proto smtp \
  -port 25 \
  -threads 100 \
  -timeout 5 \
  -o smtp_banners.json

//Pull HTTP banners from web servers list, override port to 80, output CSV-
  go run bannerGrap.go \
  -f web_hosts.txt \
  -proto http \
  -port 80 \
  -threads 50 \
  -timeout 3 \
  -o http_banners.csv
//Pull FTP banners from FTP servers list, override port to 21, output JSON-
  go run bannerGrap.go \
  -f ftp_hosts.txt \
  -proto ftp \
  -port 21 \
  -threads 20 \
  -timeout 2 \
  -o ftp_banners.json
//Pull SSH banners from SSH servers list, output JSON-
  go run bannerGrap.go \
  -f ssh_hosts.txt \
  -proto ssh \
  -threads 10 \
  -timeout 5 \
  -o ssh_banners.json
//Pull Telnet banners from Telnet servers list, output CSV-
  go run bannerGrap.go \
  -f telnet_hosts.txt \
  -proto telnet \
  -threads 10 \
  -timeout 5 \
  -o telnet_banners.csv
//Pull custom banners from custom servers list, output JSON-
  go run bannerGrap.go \
  -f custom_hosts.txt \
  -proto custom \
  -payload "GET / HTTP/1.1\r\nHost: %s\r\n\r\n" \
  -threads 10 \
  -timeout 5 \
  -o custom_banners.json

[3.5] FTP Anonymous Banner Grab: Scan FTP servers (file lists mixed hostnames & IPs), force port 21, no custom payload needed-

go run bannerGrap.go \
  -f ftp_targets.txt \
  -proto ftp \
  -port 21 \
  -threads 150 \
  -timeout 4 \
  -o ftp_banners.csv

[3.6] SSH Welcome Message Blitz: Read SSH welcomes from 1 000 hosts, port 22, high concurrency, console output-
go run bannerGrap.go \
  -f thousand_hosts.txt \
  -proto ssh \
  -port 22 \
  -threads 300 \
  -timeout 3

[3.7] Telnet Service Fingerprinting: Connect to Telnet on mixed IPv4 & IPv6 targets, port 23-
go run bannerGrap.go \
  -f mixed_targets.txt \
  -proto telnet \
  -port 23 \
  -threads 100 \
  -timeout 5 \
  -o telnet_fingerprints.json

[3.8] Custom TCP Payload for Proprietary Service: Send a proprietary “HELLO\n” payload to a custom daemon on port 9000-
  go run bannerGrap.go \
  -f custom_daemon_hosts.txt \
  -proto custom \
  -port 9000 \
  -payload "HELLO\n" \
  -threads 50 \
  -timeout 6 \
  -o daemon_responses.csv

 [3.9] Mixed-Protocol One-Liner:Scan HTTP, then HTTPS, then SMTP sequentially (three invocations) on a single host:
   go run bannerGrap.go example.com                       # HTTP:80  
   go run bannerGrap.go -proto https example.com          # HTTPS:443  
   go run bannerGrap.go -proto smtp example.com:25        # SMTP:25


[3.10] Internal LAN Audit: Check local hostnames and IPs in internal_targets.txt, console output-
 
 go run banner_grabber.go \
  -f internal_targets.txt \
  -threads 50 \
  -timeout 3
 
 [3.11]IPv6-Only Enumeration:Scan a list of IPv6 hosts on HTTPS, 100 threads-
  
go run bannerGrap.go \
  -f ipv6_hosts.txt \
  -proto https \
  -port 443 \
  -threads 100 \
  -timeout 4 \

[3.12] “All-In-One” Aggressive Sweep:One command to test HTTP, HTTPS, SMTP, SSH, FTP on the same file by chaining flags and targets inline:

go run bannerGrap.go \
-f vip_targets.txt \
  -threads 250 \
  -timeout 3 \
  -o full_report.json \
  && go run bannerGrap.go -f vip_targets.txt -proto https -threads 250 -timeout 3 -o full_report_https.json \
  && go run bannerGrap.go -f vip_targets.txt -proto smtp  -threads 250 -timeout 3 -o smtp_report.json \
  && go run bannerGrap.go -f vip_targets.txt -proto ssh   -threads 250 -timeout 3 -o ssh_report.json \
  && go run bannerGrap.go -f vip_targets.txt -proto ftp   -threads 250 -timeout 3 -o ftp_report.json

[3.13] 10K HTTPS Hosts, CSV, Fast-Fail:
go run bannerGrap.go \
  -f ten_thousand.txt \
  -proto https \
  -port 443 \
  -threads 500 \
  -timeout 2 \
  -max 2048 \
  -o https_fast.csv

[3.14] 254-Thread LAN HTTP Sweep

go run bannerGrap.go \
  -f <(for i in $(seq 1 254); do echo "192.168.1.$i"; done) \
  -threads 254 \
  -timeout 1

[3.15] Bulk SMTP JSON Harvest:

go run bannerGrap.go \
  -f mail_hosts.txt \
  -proto smtp \
  -port 25 \
  -threads 200 \
  -timeout 5 \
  -o smtp_banners.json

[3.16] FTP Anonymous & CSV:

go run bannerGrap.go \
  -f ftp_list.txt \
  -proto ftp \
  -port 21 \
  -threads 150 \
  -o ftp_out.csv

[3.17]SSH Welcome Blitz:

go run bannerGrap.go \
  -f hosts_ipv6_and_ipv4.txt \
  -proto ssh \
  -port 22 \
  -threads 300 \
  -timeout 3 \
  -v

[3.18]Telnet Fingerprinting:

go run bannerGrap.go \
  -f mixed_targets.txt \
  -proto telnet \
  -port 23 \
  -threads 100 \
  -timeout 4 \
  -o telnet.json

[3.19] Custom Daemon Probe:

go run bannerGrap.go \
  -f daemon_hosts.txt \
  -proto custom \
  -port 9000 \
  -payload "HELLO\n" \
  -threads 50 \
  -timeout 6 \
  -o daemon.csv

[3.20] Chained Multi-Protocol Sweep:

# HTTP
go run bannerGrap.go -f vip.txt -threads 250 -timeout 3 -o http.csv \
&& \
# HTTPS
go run bannerGrap.go -f vip.txt -proto https -threads 250 -timeout 3 -o https.csv \
&& \
# SMTP
go run bannerGrap.go -f vip.txt -proto smtp -threads 250 -timeout 3 -o smtp.csv \
&& \
# SSH
go run bannerGrap.go -f vip.txt -proto ssh -threads 250 -timeout 3 -o ssh.csv \
&& \
# FTP
go run bannerGrap.go -f vip.txt -proto ftp -threads 250 -timeout 3 -o ftp.csv

[3.21]IPv6-Only HTTPS Audit:

go run bannerGrap.go \
  -f ipv6_hosts.txt \
  -proto https \
  -threads 100 \
  -timeout 4 \
  -v

[3.22]  Version & Help:

go run bannerGrap.go --version
go run bannerGrap.go -h

```

# 1. Aggressive Scanning with Bash Loops:
// Scan a subnet aggressively with 50 threads and save to CSV

    for ip in 192.168.1.{1..254}; do
    echo "$ip" >> targets.txt
    done

    go run bannerGrap.go -f targets.txt -proto http -threads 50 -timeout 2 -o aggressive_scan.csv


# 2.Combined Bash Scripting: Multiple Protocols:
    // Scan the same targets with different protocols and merge results

    for proto in http https ftp ssh; do
    go run bannerGrap.go -f targets.txt -proto $proto -threads 20 -o scan_$proto.json
    done

    // Combine all JSON results into one (requires jq)
    
    jq -s 'add' scan_*.json > combined_results.json


# 3. Aggressive Bash One-Liner for All Open Ports (with nmap):
// Discover live hosts and open ports, then scan with bannerGrap

    nmap -p- --open -oG - 192.168.1.0/24 | awk '/Up$/{ip=$2} /Ports:/{split($0,a,"Ports: "); split(a[2],b,","); for(i in b) {split(b[i],c,"/"); print ip":"c[1]}}' > all_targets.txt

    go run bannerGrap.go -f all_targets.txt -threads 100 -timeout 2 -o full_aggressive.json



# 4. Chained Bash Scripting: Brute Force and Reporting:
// Run with brute force user/pass lists and HTML report

    go run bannerGrap.go -f targets.txt -proto ssh \
     --brute-userlist users.txt --brute-passlist passwords.txt \
    --report-html report.html -threads 30


# 5. Chained Bash Scripting: Brute Force and Reporting:
// Run with brute force user/pass lists and HTML report
    
    go run bannerGrap.go -f targets.txt -proto ssh \
    --brute-userlist users.txt --brute-passlist passwords.txt \
    --report-html report.html -threads 30



# 6.  Parallel Bash Scanning with GNU Parallel:
  // Run scans in parallel for a list of targets
  
    cat targets.txt | parallel -j 20 "go run bannerGrap.go {} -proto http -timeout 2"



# 7. Aggressive Combined Bash Script Example:

    #!/bin/bash

    // Aggressive multi-protocol, multi-output scan

    TARGETS="targets.txt"

    THREADS=50

    TIMEOUT=2

    for proto in http https ftp ssh smtp; do

    go run bannerGrap.go -f "$TARGETS" -proto $proto -threads $THREADS -timeout $TIMEOUT -o "scan_${proto}.json"
 
    done

    // Merge all results

    jq -s 'add' scan_*.json > all_protocols_combined.json

    // Generate HTML report from combined results

    go run bannerGrap.go -f "$TARGETS" -proto http --report-html all_protocols_report.html



# 8. Intermediate: Scheduled Cron Job for Continuous Monitoring:
 Add to crontab for daily scan at 2am

    0 2 * * * /usr/bin/go run /path/to/bannerGrap.go -f /path/to/targets.txt -proto https -threads 20 -o /path/to/daily_https_scan.json



# 9. Aggressive: Scan and Alert on Vulnerabilities:
// Scan and grep for critical vulnerabilities

    go run bannerGrap.go -f targets.txt -proto http -threads 30 -o temp.json
    grep -i "CVE-" temp.json | tee critical_vulns.txt



# 10. Combine with Other Tools (Nmap, Masscan, etc.):
// Use masscan for fast discovery, then scan with bannerGrap

    masscan 192.168.1.0/24 -p1-65535 --rate=10000 -oG masscan.gnmap
    awk '/Ports:/{split($0,a,"Ports: "); split(a[2],b,","); for(i in b) {split(b[i],c,"/"); print $2":"c[1]}}' masscan.gnmap > masscan_targets.txt

    go run bannerGrap.go -f masscan_targets.txt -threads 100 -timeout 2 -o masscan_bannergrap.json

# 11. How to Use Large Lists (like SecLists) or any lists:

  - Download a username list and a password list from SecLists or any lists.
  - Example :
           - usernames.txt (Ex: SecLists/Usernames/top-usernames-shortlist.txt or, SecLists/Usernames/Names/names.txt)
           - passwords.txt (Ex: SecLists/Passwords/Common-Credentials/       10k-most-common.txt or,ecLists/Passwords/Common-Credentials/10k-most-common.txt
          or rockyou.txt for more coverage.)

  Bash-
       
         go run bannerGrap.go --brute-userlist usernames.txt --brute-passlist passwords.txt -proto ssh 192.168.1.100         

# 12. Scan a full /24 subnet with 100 threads, all protocols, and output to JSON:

    go run bannerGrap.go -f targets.txt -proto http -threads 100 -timeout 2 -o scan_http.json
    go run bannerGrap.go -f targets.txt -proto https -threads 100 -timeout 2 -o scan_https.json
    go run bannerGrap.go -f targets.txt -proto ssh -threads 100 -timeout 2 -o scan_ssh.json

# 13. Brute force SSH with big SecLists:

    go run bannerGrap.go -f ssh_targets.txt -proto ssh --brute-userlist users.txt --brute-passlist passwords.txt -threads 50 -timeout 3 -o ssh_brute.json

# 14. Aggressive scan with max banner size and verbose output:

    go run bannerGrap.go -f targets.txt -proto http -max 16384 -threads 50 -v

# 15. Scan all ports on a single host:

    for p in {1..65535}; do echo "192.168.1.100:$p"; done > allports.txt
    go run bannerGrap.go -f allports.txt -threads 200 -timeout 1 -o allports.json

# 16. Combine brute force, enumeration, and reporting:

    go run bannerGrap.go -f targets.txt -proto ftp --brute-userlist users.txt --brute-passlist passwords.txt --report-html ftp_report.html -threads 30

# 17. Scan with custom payloads for protocol fuzzing:

    go run bannerGrap.go -f targets.txt -proto http --payload "GET /admin HTTP/1.1\r\nHost: %s\r\n\r\n" -threads 20

# 18. Aggressive scan with plugin directory:

    go run bannerGrap.go -f targets.txt -proto http --plugin-dir ./plugins -threads 20

# 19. Scan and output to both JSON and HTML:

    go run bannerGrap.go -f targets.txt -proto http -o output.json --report-html output.html

# 20. Scan with very short timeout for stealth:

    go run bannerGrap.go -f targets.txt -proto http -timeout 1 -threads 100

# 21. Scan with custom port override:

    go run bannerGrap.go -f targets.txt -proto http -port 8080 -threads 50

# 22. Scan with multiple protocols in sequence:

    for proto in http https ftp ssh smtp; do
    go run bannerGrap.go -f targets.txt -proto $proto -threads 30 -o scan_$proto.json
    done

# 23. Aggressive scan with large user/pass lists:

    go run bannerGrap.go -f targets.txt -proto ssh --brute-userlist big_users.txt --brute-passlist big_passwords.txt -threads 100

# 24. Scan and grep for critical vulnerabilities:

    go run bannerGrap.go -f targets.txt -proto http -threads 30 -o temp.json
    grep -i "CVE-" temp.json

# 25. Scan and export results for SIEM integration:

    go run bannerGrap.go -f targets.txt -proto http -o siem_results.json

# 26. Aggressive scan with parallel execution:

    cat targets.txt | parallel -j 50 "go run bannerGrap.go {} -proto http -timeout 2"

# /Bash Scripting Part:

# 1. Full subnet scan with all protocols:

    for proto in http https ftp ssh smtp; do
    go run bannerGrap.go -f targets.txt -proto $proto -threads 100 -timeout 2 -o scan_$proto.json
    done

# 2. Brute force SSH on all discovered hosts:

    go run bannerGrap.go -f ssh_targets.txt -proto ssh --brute-userlist users.txt --brute-passlist passwords.txt -threads 50 -o ssh_brute.json

# 3. Scan all ports on all hosts:

    for ip in $(cat targets.txt); do
    for p in {1..1000}; do
    echo "$ip:$p"
    done
    done > allports.txt
    go run bannerGrap.go -f allports.txt -threads 200 -timeout 1 -o allports.json

# 4. Combine results from multiple protocol scans:

    jq -s 'add' scan_*.json > combined_results.json

# 5. Aggressive scan and HTML report generation:

    go run bannerGrap.go -f targets.txt -proto http --report-html aggressive_report.html -threads 50

# 6. Parallel scan using GNU parallel:

    cat targets.txt | parallel -j 30 "go run bannerGrap.go {} -proto http -timeout 2"

# 7.Daily scheduled scan via cron:

    0 2 * * * /usr/bin/go run /path/to/bannerGrap.go -f /path/to/targets.txt -proto https -threads 20 -o /path/to/daily_https_scan.json

# 8. Scan and alert on critical vulnerabilities:

    go run bannerGrap.go -f targets.txt -proto http -threads 30 -o temp.json
    grep -i "CVE-" temp.json | mail -s "Critical Vulns Found" you@example.com

# 9. Scan with custom payloads for fuzzing:

    go run bannerGrap.go -f targets.txt -proto http --payload "GET /admin HTTP/1.1\r\nHost: %s\r\n\r\n" -threads 20

# 10. Aggressive scan with plugin support:

    go run bannerGrap.go -f targets.txt -proto http --plugin-dir ./plugins -threads 20

# 11. Scan and export to CSV for Excel analysis:

    go run bannerGrap.go -f targets.txt -proto http -o results.csv

# 12. Scan with very short timeout for stealth:

    go run bannerGrap.go -f targets.txt -proto http -timeout 1 -threads 100

# 13. Scan with custom port override:

    go run bannerGrap.go -f targets.txt -proto http -port 8080 -threads 50

# 14. Masscan + BannerGrap combo for aggressive discovery:

    masscan 192.168.1.0/24 -p1-65535 --rate=10000 -oG masscan.gnmap
    awk '/Ports:/{split($0,a,"Ports: "); split(a[2],b,","); for(i in b) {split(b[i],c,"/"); print $2":"c[1]}}' masscan.gnmap > masscan_targets.txt
    go run bannerGrap.go -f masscan_targets.txt -threads 100 -timeout 2 -o masscan_bannergrap.json

# 15. Aggressive scan with all features enabled:

    go run bannerGrap.go -f targets.txt -proto ssh --brute-userlist users.txt --brute-passlist passwords.txt --report-html full_report.html --plugin-dir plugins/ -threads 100 -timeout 2 -o everything.json


# Tips:
- @ Use -threads and -timeout for aggressive speed.
- @ Use -o and --report-html for structured output.
- @ Combine with jq, awk, grep, and other Bash tools for post-processing.
- @ ******Mix, match, and tweak these to your heart’s content.
- @ Always have permission before scanning!
