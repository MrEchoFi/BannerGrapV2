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
@ Use -threads and -timeout for aggressive speed.
@ Use -o and --report-html for structured output.
@ Combine with jq, awk, grep, and other Bash tools for post-processing.
@ ******Mix, match, and tweak these to your heart’s content.
@ Always have permission before scanning!
