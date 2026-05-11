 ### Scan Techniques
 
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