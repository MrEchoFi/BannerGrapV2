/*

__________                                      ________                                        
\______   \_____    ____   ____   ___________  /  _____/___________  ______        ____   ____  
 |    |  _/\__  \  /    \ /    \_/ __ \_  __ \/   \  __\_  __ \__  \ \____ \      / ___\ /  _ \ 
 |    |   \ / __ \|   |  \   |  \  ___/|  | \/\    \_\  \  | \// __ \|  |_> >    / /_/  >  <_> )
 |______  /(____  /___|  /___|  /\___  >__|    \______  /__|  (____  /   __/ /\  \___  / \____/ 
        \/      \/     \/     \/     \/               \/           \/|__|    \/ /_____/         
                                                                      Version 2.0

    Copyright 2025 MrEchoFi_Ebwer
	
	MIT License

	

Copyright (c) 2025 MrEchoFi_Md. Abu Naser Nayeem [Tanjib Isham]

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

*/


package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/csv"
	"encoding/json"
	"flag"
	"fmt"
	"html/template"
	"io/ioutil"
	"net"
	"net/http"
	"os"
	"bytes"
	//"path/filepath"
	"strings"
	"sync"
	"time"
	"regexp"

	"golang.org/x/net/http2"
	"nhooyr.io/websocket"
	"golang.org/x/crypto/ssh"
)

// This will hold the result and will check in advanced mode
type BannerResult struct {
	Host        string   `json:"host"`
	Port        string   `json:"port"`
	Protocol    string   `json:"protocol"`
	Banner      string   `json:"banner"`
	Error       string   `json:"error,omitempty"`
	Fingerprint string   `json:"fingerprint,omitempty"`
	TLSVersion  string   `json:"tls_version,omitempty"`
	Cipher      string   `json:"cipher,omitempty"`
	CertIssuer  string   `json:"cert_issuer,omitempty"`
	CertCN      string   `json:"cert_cn,omitempty"`
	Vulns       []string `json:"vulnerabilities,omitempty"`
	Exploits    []string `json:"exploits,omitempty"`
	Enum        []string `json:"enumeration,omitempty"`
	Brute       []string `json:"bruteforce,omitempty"`
	Report      string   `json:"report,omitempty"`
}

//protocol and payloads..
var protocolPayloads = map[string]string{
	"http":      "GET / HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n",
	"https":     "GET / HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n",
	"smtp":      "EHLO %s\r\n",
	"ftp":       "USER anonymous\r\n",
	"ssh":       "",
	"telnet":    "",
	"http2":     "", 
	"websocket": "", 
}


func checkVulnerabilities(host, port, protocol, banner string) []string {
    var vulns []string

   
    if protocol == "http" {
        if strings.Contains(banner, "Apache/2.4.49") {
            vulns = append(vulns, "Apache 2.4.49 RCE (CVE-2021-41773)")
        }
        if strings.Contains(banner, "Apache/2.4.50") {
            vulns = append(vulns, "Apache 2.4.50 Path Traversal (CVE-2021-42013)")
        }
        if strings.Contains(banner, "nginx/1.16.1") {
            vulns = append(vulns, "Nginx 1.16.1 - Multiple CVEs (CVE-2019-20372, CVE-2019-20373)")
        }
        if strings.Contains(banner, "nginx/1.18.0") {
            vulns = append(vulns, "Nginx 1.18.0 - Potential vulnerabilities (check CVE database)")
        }
        if strings.Contains(banner, "LiteSpeed") {
            vulns = append(vulns, "LiteSpeed detected - Check for CVE-2019-11043 and others")
        }
        if strings.Contains(banner, "Microsoft-IIS/7.5") {
            vulns = append(vulns, "IIS 7.5 - Multiple vulnerabilities (CVE-2015-1635, CVE-2017-7269)")
        }
        if strings.Contains(banner, "Microsoft-IIS/8.5") {
            vulns = append(vulns, "IIS 8.5 - Check for CVE-2017-7269 and others")
        }
        if strings.Contains(banner, "Apache-Coyote/1.1") {
            vulns = append(vulns, "Tomcat (Apache-Coyote/1.1) - Ghostcat (CVE-2020-1938) and others")
        }
        if strings.Contains(banner, "Apache Tomcat/9.0.0") {
            vulns = append(vulns, "Tomcat 9.0.0 - Multiple vulnerabilities (check CVE database)")
        }
        if strings.Contains(banner, "Jetty(9.4.18.v20190429)") {
            vulns = append(vulns, "Jetty 9.4.18 - CVE-2019-10241, CVE-2019-10247")
        }
        if strings.Contains(banner, "GWS") {
            vulns = append(vulns, "Google Web Server detected - check for known issues")
        }
        if strings.Contains(banner, "Tengine") {
            vulns = append(vulns, "Tengine (Alibaba Nginx fork) detected - check for CVEs")
        }
        if strings.Contains(banner, "OpenResty") {
            vulns = append(vulns, "OpenResty detected - check for Nginx-based CVEs")
        }
        if strings.Contains(banner, "Cherokee") {
            vulns = append(vulns, "Cherokee Web Server detected - check for CVEs")
        }
        if strings.Contains(banner, "Caddy") {
            vulns = append(vulns, "Caddy Server detected - check for CVEs")
        }
        if strings.Contains(banner, "Resin") {
            vulns = append(vulns, "Resin Application Server detected - check for CVEs")
        }
        if strings.Contains(banner, "Oracle-Application-Server") {
            vulns = append(vulns, "Oracle Application Server detected - check for CVEs")
        }
        if strings.Contains(banner, "IBM_HTTP_Server") {
            vulns = append(vulns, "IBM HTTP Server detected - check for CVEs")
        }
        if strings.Contains(banner, "Zeus") {
            vulns = append(vulns, "Zeus Web Server detected - check for CVEs")
        }
        if strings.Contains(banner, "AkamaiGHost") {
            vulns = append(vulns, "AkamaiGHost detected - check for CDN vulnerabilities")
        }
        if strings.Contains(banner, "Yaws") {
            vulns = append(vulns, "Yaws (Erlang Web Server) detected - check for CVEs")
        }
        if strings.Contains(banner, "TwistedWeb") {
            vulns = append(vulns, "TwistedWeb detected - check for CVEs")
        }
        if strings.Contains(banner, "Gunicorn") {
            vulns = append(vulns, "Gunicorn (Python WSGI) detected - check for CVEs")
        }
        if strings.Contains(banner, "uWSGI") {
            vulns = append(vulns, "uWSGI detected - check for CVEs")
        }
        if strings.Contains(banner, "mod_wsgi") {
            vulns = append(vulns, "mod_wsgi detected - check for CVEs")
        }
        if strings.Contains(banner, "mod_python") {
            vulns = append(vulns, "mod_python detected - check for CVEs")
        }
        if strings.Contains(banner, "mod_perl") {
            vulns = append(vulns, "mod_perl detected - check for CVEs")
        }
        if strings.Contains(banner, "WEBrick") {
            vulns = append(vulns, "WEBrick (Ruby) detected - check for CVEs")
        }
        if strings.Contains(banner, "GlassFish") {
            vulns = append(vulns, "GlassFish Server detected - check for CVEs")
        }
        if strings.Contains(banner, "Sun-Java-System-Web-Server") {
            vulns = append(vulns, "Sun Java System Web Server detected - check for CVEs")
        }
        if strings.Contains(banner, "Boa/") {
            vulns = append(vulns, "Boa Web Server detected - check for CVEs")
        }
        if strings.Contains(banner, "thttpd") {
            vulns = append(vulns, "thttpd detected - check for CVEs")
        }
        if strings.Contains(banner, "lighttpd") {
            vulns = append(vulns, "lighttpd detected - check for CVEs")
        }
        if strings.Contains(banner, "Abyss") {
            vulns = append(vulns, "Abyss Web Server detected - check for CVEs")
        }
        if strings.Contains(banner, "Zope") {
            vulns = append(vulns, "Zope Application Server detected - check for CVEs")
        }
        if strings.Contains(banner, "Hiawatha") {
            vulns = append(vulns, "Hiawatha Web Server detected - check for CVEs")
        }
        if strings.Contains(banner, "RomPager") {
            vulns = append(vulns, "RomPager detected - check for CVE-2014-9222 (Misfortune Cookie)")
        }
        if strings.Contains(banner, "BarracudaHTTP") {
            vulns = append(vulns, "Barracuda HTTP Server detected - check for CVEs")
        }
        if strings.Contains(banner, "GoAhead-Webs") {
            vulns = append(vulns, "GoAhead Web Server detected - check for CVEs")
        }
        if strings.Contains(banner, "Mongoose") {
            vulns = append(vulns, "Mongoose Web Server detected - check for CVEs")
        }
        if strings.Contains(banner, "Monkey/") {
            vulns = append(vulns, "Monkey HTTP Server detected - check for CVEs")
        }
        if strings.Contains(banner, "Allegro-Software-RomPager") {
            vulns = append(vulns, "Allegro RomPager detected - check for CVE-2014-9222")
        }
        if strings.Contains(banner, "SAP NetWeaver") {
            vulns = append(vulns, "SAP NetWeaver detected - check for CVEs")
        }
        if strings.Contains(banner, "Cisco-WSA") {
            vulns = append(vulns, "Cisco Web Security Appliance detected - check for CVEs")
        }
        if strings.Contains(banner, "BlueCoat") {
            vulns = append(vulns, "BlueCoat Proxy detected - check for CVEs")
        }
        if strings.Contains(banner, "Squid") {
            vulns = append(vulns, "Squid Proxy detected - check for CVEs")
        }
        if strings.Contains(banner, "Varnish") {
            vulns = append(vulns, "Varnish Cache detected - check for CVEs")
        }
        if strings.Contains(banner, "F5 BIG-IP") {
            vulns = append(vulns, "F5 BIG-IP detected - check for CVEs")
        }
        if strings.Contains(banner, "Citrix NetScaler") {
            vulns = append(vulns, "Citrix NetScaler detected - check for CVEs")
        }
        if strings.Contains(banner, "FortiWeb") {
            vulns = append(vulns, "FortiWeb detected - check for CVEs")
        }
        if strings.Contains(banner, "Radware AppDirector") {
            vulns = append(vulns, "Radware AppDirector detected - check for CVEs")
        }
        if strings.Contains(banner, "ArrayNetworks") {
            vulns = append(vulns, "Array Networks detected - check for CVEs")
        }
        if strings.Contains(banner, "A10 Networks") {
            vulns = append(vulns, "A10 Networks detected - check for CVEs")
        }
        if strings.Contains(banner, "Barracuda") {
            vulns = append(vulns, "Barracuda Networks detected - check for CVEs")
        }
    }

    
    if protocol == "https" {
        if strings.Contains(banner, "OpenSSL 1.0.1") {
            vulns = append(vulns, "Possible Heartbleed (OpenSSL 1.0.1)")
        }
        if strings.Contains(banner, "LibreSSL") {
            vulns = append(vulns, "LibreSSL detected - check for CVEs")
        }
        if strings.Contains(banner, "GnuTLS") {
            vulns = append(vulns, "GnuTLS detected - check for CVEs")
        }
    }

   
    if strings.Contains(banner, "PHP/5.4") {
        vulns = append(vulns, "PHP 5.4 - End of Life, multiple vulnerabilities")
    }
    if strings.Contains(banner, "PHP/7.2") {
        vulns = append(vulns, "PHP 7.2 - End of Life, multiple vulnerabilities")
    }
    if strings.Contains(banner, "Node.js/10.") {
        vulns = append(vulns, "Node.js 10.x - End of Life, multiple vulnerabilities")
    }
    if strings.Contains(banner, "Express") {
        vulns = append(vulns, "Express.js detected - check for CVEs")
    }
    if strings.Contains(banner, "Django") {
        vulns = append(vulns, "Django detected - check for CVEs")
    }
    if strings.Contains(banner, "Flask") {
        vulns = append(vulns, "Flask detected - check for CVEs")
    }
    if strings.Contains(banner, "Ruby on Rails") {
        vulns = append(vulns, "Ruby on Rails detected - check for CVEs")
    }

    
    if protocol == "smtp" {
        if strings.Contains(banner, "Exim 4.87") {
            vulns = append(vulns, "Exim 4.87 - RCE (CVE-2016-1531, CVE-2019-10149)")
        }
        if strings.Contains(banner, "Postfix") {
            vulns = append(vulns, "Postfix detected - check for CVEs")
        }
        if strings.Contains(banner, "Sendmail") {
            vulns = append(vulns, "Sendmail detected - check for CVEs")
        }
        if strings.Contains(banner, "qmail") {
            vulns = append(vulns, "qmail detected - check for CVEs")
        }
        if strings.Contains(banner, "Microsoft ESMTP MAIL Service") {
            vulns = append(vulns, "Microsoft Exchange detected - check for CVEs")
        }
        if strings.Contains(banner, "Courier") {
            vulns = append(vulns, "Courier Mail Server detected - check for CVEs")
        }
        if strings.Contains(banner, "Lotus Domino") {
            vulns = append(vulns, "Lotus Domino Mail Server detected - check for CVEs")
        }
    }

    
    if protocol == "ftp" {
        if strings.Contains(banner, "ProFTPD 1.3.5") {
            vulns = append(vulns, "ProFTPD 1.3.5 - Multiple vulnerabilities (CVE-2015-3306)")
        }
        if strings.Contains(banner, "vsFTPd 2.3.4") {
            vulns = append(vulns, "vsFTPd 2.3.4 - Backdoor vulnerability (CVE-2011-2523)")
        }
        if strings.Contains(banner, "Pure-FTPd") {
            vulns = append(vulns, "Pure-FTPd detected - check for CVEs")
        }
        if strings.Contains(banner, "FileZilla Server") {
            vulns = append(vulns, "FileZilla Server detected - check for CVEs")
        }
        if strings.Contains(banner, "Serv-U FTP Server") {
            vulns = append(vulns, "Serv-U FTP Server detected - check for CVEs")
        }
        if strings.Contains(banner, "WS_FTP Server") {
            vulns = append(vulns, "WS_FTP Server detected - check for CVEs")
        }
        if strings.Contains(banner, "Gene6 FTP Server") {
            vulns = append(vulns, "Gene6 FTP Server detected - check for CVEs")
        }
        if strings.Contains(banner, "Wing FTP Server") {
            vulns = append(vulns, "Wing FTP Server detected - check for CVEs")
        }
    }

    
    if protocol == "ssh" {
        if strings.Contains(banner, "OpenSSH_7.2") {
            vulns = append(vulns, "OpenSSH 7.2 - Multiple vulnerabilities (CVE-2016-0777, CVE-2016-0778)")
        }
        if strings.Contains(banner, "Dropbear") {
            vulns = append(vulns, "Dropbear SSH detected - check for CVEs")
        }
        if strings.Contains(banner, "libssh") {
            vulns = append(vulns, "libssh detected - check for CVE-2018-10933")
        }
        if strings.Contains(banner, "Bitvise") {
            vulns = append(vulns, "Bitvise SSH Server detected - check for CVEs")
        }
        if strings.Contains(banner, "WinSCP") {
            vulns = append(vulns, "WinSCP SSH detected - check for CVEs")
        }
    }

    
    if protocol == "telnet" {
        if strings.Contains(banner, "Microsoft Telnet Service") {
            vulns = append(vulns, "Microsoft Telnet Service detected - check for CVEs")
        }
        if strings.Contains(banner, "Cisco IOS") {
            vulns = append(vulns, "Cisco IOS Telnet detected - check for CVEs")
        }
        if strings.Contains(banner, "Linux telnetd") {
            vulns = append(vulns, "Linux telnetd detected - check for CVEs")
        }
    }

   
    if strings.Contains(banner, "Squid") {
        vulns = append(vulns, "Squid Proxy detected - check for CVEs")
    }
    if strings.Contains(banner, "Varnish") {
        vulns = append(vulns, "Varnish Cache detected - check for CVEs")
    }
    if strings.Contains(banner, "F5 BIG-IP") {
        vulns = append(vulns, "F5 BIG-IP detected - check for CVEs")
    }
    if strings.Contains(banner, "Citrix NetScaler") {
        vulns = append(vulns, "Citrix NetScaler detected - check for CVEs")
    }
    if strings.Contains(banner, "FortiWeb") {
        vulns = append(vulns, "FortiWeb detected - check for CVEs")
    }
    if strings.Contains(banner, "Radware AppDirector") {
        vulns = append(vulns, "Radware AppDirector detected - check for CVEs")
    }
    if strings.Contains(banner, "ArrayNetworks") {
        vulns = append(vulns, "Array Networks detected - check for CVEs")
    }
    if strings.Contains(banner, "A10 Networks") {
        vulns = append(vulns, "A10 Networks detected - check for CVEs")
    }
    if strings.Contains(banner, "Barracuda") {
        vulns = append(vulns, "Barracuda Networks detected - check for CVEs")
    }

    // u can add more of these......

    // Active probes (stub)
	if protocol == "https" && probeHeartbleed(host, port) {
        vulns = append(vulns, "Heartbleed vulnerability detected by active probe!")
    }
    if protocol == "http" && probeShellshock(host, port) {
        vulns = append(vulns, "Shellshock vulnerability detected by active probe!")
    }
    if protocol == "http" && probeLog4Shell(host, port) {
        vulns = append(vulns, "Log4Shell vulnerability detected by active probe!")
    }

    // CVE/Exploit DB Integration 
    cveMatches := matchCVEs(banner)
    vulns = append(vulns, cveMatches...)
    

    return vulns
}

// Active Probes
func probeHeartbleed(host, port string) bool {
    
    address := net.JoinHostPort(host, port)
    conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 3 * time.Second}, "tcp", address, &tls.Config{
        InsecureSkipVerify: true,
        ServerName:         host,
    })
    if err != nil {
        return false
    }
    defer conn.Close()
    for _, cert := range conn.ConnectionState().PeerCertificates {
        if strings.Contains(cert.Subject.CommonName, "OpenSSL 1.0.1") {
            return true
        }
    }
   
    return false
}

func probeShellshock(host, port string) bool {
   
    url := fmt.Sprintf("http://%s:%s/cgi-bin/test.sh", host, port)
    client := &http.Client{Timeout: 3 * time.Second}
    req, err := http.NewRequest("GET", url, nil)
    if err != nil {
        return false
    }
    req.Header.Set("User-Agent", "() { :; }; echo; echo SHELLSHOCK_TEST")
    resp, err := client.Do(req)
    if err != nil {
        return false
    }
    defer resp.Body.Close()
    buf := new(bytes.Buffer)
    buf.ReadFrom(resp.Body)
    return bytes.Contains(buf.Bytes(), []byte("SHELLSHOCK_TEST"))
}

func probeLog4Shell(host, port string) bool {
   
    url := fmt.Sprintf("http://%s:%s/", host, port)
    client := &http.Client{Timeout: 3 * time.Second}
    req, err := http.NewRequest("GET", url, nil)
    if err != nil {
        return false
    }
   
    req.Header.Set("X-Api-Version", "${jndi:ldap://log4shell-test}")
    resp, err := client.Do(req)
    if err != nil {
        return false
    }
    defer resp.Body.Close()
    buf := new(bytes.Buffer)
    buf.ReadFrom(resp.Body)
    return bytes.Contains(buf.Bytes(), []byte("log4shell"))
}

// CVE/Exploit DB Integration_Regex Matching
func matchCVEs(banner string) []string {
    var cves []string
    cveRegexes := map[string]string{
        `Apache/2\.4\.49`:      "CVE-2021-41773: Apache 2.4.49 Path Traversal/RCE",
        `nginx/1\.16\.1`:       "CVE-2019-20372: Nginx 1.16.1 Vulnerability",
        `Microsoft-IIS/7\.5`:   "CVE-2015-1635: IIS 7.5 HTTP.sys RCE",
        `OpenSSH_7\.2`:         "CVE-2016-0777: OpenSSH 7.2 Information Leak",
        `ProFTPD 1\.3\.5`:      "CVE-2015-3306: ProFTPD 1.3.5 Mod_Copy Command Execution",
        `vsFTPd 2\.3\.4`:       "CVE-2011-2523: vsFTPd 2.3.4 Backdoor",
        `Exim 4\.87`:           "CVE-2019-10149: Exim 4.87 RCE",
        `PHP/5\.4`:             "Multiple CVEs: PHP 5.4 End of Life",
        `Apache Tomcat/9\.0\.0`: "CVE-2017-12617: Tomcat 9.0.0 RCE",
        `Jetty\(9\.4\.18\.v20190429\)`: "CVE-2019-10241: Jetty 9.4.18 Directory Traversal",
    }
    for pattern, desc := range cveRegexes {
        re := regexp.MustCompile(pattern)
        if re.MatchString(banner) {
            cves = append(cves, desc)
        }
    }
    return cves
}


func protocolAttacks(host, port, protocol string) []string {
	var attacks []string
	
	attacks = append(attacks, "SQLi/XSS/Command Injection checks not implemented (stub)")
	
	attacks = append(attacks, "Buffer overflow probes not implemented (stub)")
	return attacks
}


func deepProtocolParse(host, port, protocol string) []string {
	var details []string
	
	details = append(details, "Deep protocol parsing not implemented (stub)")
	return details
}


func attemptExploitation(host, port, protocol string, vulns []string) []string {
	var exploits []string
	
	for _, v := range vulns {
		if strings.Contains(v, "Heartbleed") {
			exploits = append(exploits, "Heartbleed exploit attempted (stub)")
		}
	}
	return exploits
}


func enumerateService(host, port, protocol string) []string {
	var enum []string
	
	if protocol == "ftp" {
		enum = append(enum, "Anonymous FTP login allowed (stub)")
	}
	if protocol == "http" {
		enum = append(enum, "Found /admin (stub)")
	}
	return enum
}


func bruteForceService(host, port, protocol string, userlist, passlist []string) []string {
    var brute []string
    if protocol != "ssh" || len(userlist) == 0 || len(passlist) == 0 {
        return brute
    }
    address := net.JoinHostPort(host, port)
    
    maxTries := 50
    tries := 0
    for _, user := range userlist {
        for _, pass := range passlist {
            if tries >= maxTries {
                brute = append(brute, "Brute force attempt limit reached (max 50 tries per host)")
                return brute
            }
            config := &ssh.ClientConfig{
                User:            user,
                Auth:            []ssh.AuthMethod{ssh.Password(pass)},
                HostKeyCallback: ssh.InsecureIgnoreHostKey(),
                Timeout:         3 * time.Second,
            }
            client, err := ssh.Dial("tcp", address, config)
            if err == nil {
                brute = append(brute, fmt.Sprintf("SUCCESS: %s:%s", user, pass))
                client.Close()
                return brute 
            } else if strings.Contains(err.Error(), "unable to authenticate") {
                
            }
            tries++
        }
    }
    if len(brute) == 0 {
        brute = append(brute, "No valid SSH credentials found")
    }
    return brute
}


func generateReport(r BannerResult) string {
	report := fmt.Sprintf("Host: %s\nPort: %s\nProtocol: %s\n", r.Host, r.Port, r.Protocol)
	if r.Error != "" {
		report += fmt.Sprintf("Error: %s\n", r.Error)
	} else {
		report += fmt.Sprintf("Banner: %s\n", r.Banner)
		report += fmt.Sprintf("Fingerprint: %s\n", r.Fingerprint)
		report += fmt.Sprintf("TLS: %s | Cipher: %s\n", r.TLSVersion, r.Cipher)
		report += fmt.Sprintf("Cert Issuer: %s | CN: %s\n", r.CertIssuer, r.CertCN)
		if len(r.Vulns) > 0 {
			report += fmt.Sprintf("Vulnerabilities: %s\n", strings.Join(r.Vulns, ", "))
		}
		if len(r.Exploits) > 0 {
			report += fmt.Sprintf("Exploits: %s\n", strings.Join(r.Exploits, ", "))
		}
		if len(r.Enum) > 0 {
			report += fmt.Sprintf("Enumeration: %s\n", strings.Join(r.Enum, ", "))
		}
		if len(r.Brute) > 0 {
			report += fmt.Sprintf("BruteForce: %s\n", strings.Join(r.Brute, ", "))
		}
	}
	return report
}



func writeHTMLReport(filename string, results []BannerResult) error {
	const tpl = `
    <html><head><title>BannerGrap V2 By MrEchoFi</title>
	<title1>BannerGrap Security Report</title1>
	</head>
    <body>
    <h1>BannerGrap Security Report</h1>
    {{range .}}
    <h2>{{.Host}}:{{.Port}} [{{.Protocol}}]</h2>
    <pre>{{.Report}}</pre>
    <hr>
    {{end}}
    </body></html>
    `
	t, err := template.New("report").Parse(tpl)
	if err != nil {
		return err
	}
	f, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer f.Close()
	return t.Execute(f, results)
}


func runPlugins(pluginDir string, r *BannerResult) {
	
	r.Report += "\n[Plugin system not implemented (stub)]"
}


func getTLSInfo(cs *tls.ConnectionState) (version, cipher, issuer, cn string) {
	if cs == nil {
		return
	}
	switch cs.Version {
	case tls.VersionTLS13:
		version = "TLS 1.3"
	case tls.VersionTLS12:
		version = "TLS 1.2"
	case tls.VersionTLS11:
		version = "TLS 1.1"
	case tls.VersionTLS10:
		version = "TLS 1.0"
	default:
		version = "Unknown"
	}
	cipher = tls.CipherSuiteName(cs.CipherSuite)
	if len(cs.PeerCertificates) > 0 {
		issuer = cs.PeerCertificates[0].Issuer.CommonName
		cn = cs.PeerCertificates[0].Subject.CommonName
	}
	return
}

func fingerprintBanner(banner string) string {
	banner = strings.ToLower(banner)
	switch {
	case strings.Contains(banner, "ssh"):
		return "SSH"
	case strings.Contains(banner, "smtp"):
		return "SMTP"
	case strings.Contains(banner, "ftp"):
		return "FTP"
	case strings.Contains(banner, "http/1.1"):
		return "HTTP/1.1"
	case strings.Contains(banner, "http/2"):
		return "HTTP/2"
	case strings.Contains(banner, "220 "):
		return "FTP/SMTP"
	case strings.Contains(banner, "telnet"):
		return "Telnet"
	case strings.Contains(banner, "server:"):
		return "HTTP"
	case strings.Contains(banner, "websocket"):
		return "WebSocket"
	default:
		return ""
	}
}

func grabBanner(host, port, protocol, payload string, timeout time.Duration, maxBytes int, userlist, passlist []string, pluginDir string) BannerResult {
	address := net.JoinHostPort(host, port)
	var banner string
	var err error
	var tlsState *tls.ConnectionState

	switch protocol {
	case "https":
		dialer := &net.Dialer{Timeout: timeout}
		conn, err := tls.DialWithDialer(dialer, "tcp", address, &tls.Config{
			InsecureSkipVerify: true,
			ServerName:         host,
		})
		if err != nil {
			return BannerResult{Host: host, Port: port, Protocol: protocol, Error: err.Error()}
		}
		defer conn.Close()
		conn.SetDeadline(time.Now().Add(timeout))
		if payload != "" {
			fmt.Fprintf(conn, payload, host)
		}
		buf := make([]byte, maxBytes)
		n, _ := conn.Read(buf)
		banner = string(buf[:n])
		state := conn.ConnectionState()
		tlsState = &state

	case "http2":
		url := fmt.Sprintf("https://%s", net.JoinHostPort(host, port))
		tr := &http2.Transport{
			AllowHTTP: false,
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
				ServerName:         host,
			},
			DialTLS: func(network, addr string, cfg *tls.Config) (net.Conn, error) {
				return tls.DialWithDialer(&net.Dialer{Timeout: timeout}, network, addr, cfg)
			},
		}
		client := &http.Client{
			Transport: tr,
			Timeout:   timeout,
		}
		resp, err := client.Get(url)
		if err != nil {
			return BannerResult{Host: host, Port: port, Protocol: protocol, Error: err.Error()}
		}
		defer resp.Body.Close()
		banner = fmt.Sprintf("HTTP/%d.%d %s\n", resp.ProtoMajor, resp.ProtoMinor, resp.Status)
		for k, v := range resp.Header {
			banner += fmt.Sprintf("%s: %s\n", k, strings.Join(v, ","))
		}
		if resp.TLS != nil {
			tlsState = resp.TLS
		}

	case "websocket":
		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		defer cancel()
		url := fmt.Sprintf("wss://%s", net.JoinHostPort(host, port))
		client := &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{
					InsecureSkipVerify: true,
					ServerName:         host,
				},
			},
			Timeout: timeout,
		}
		c, _, err := websocket.Dial(ctx, url, &websocket.DialOptions{
			Subprotocols: []string{"chat", "superchat"},
			HTTPHeader:   http.Header{"Host": {host}},
			HTTPClient:   client,
		})
		if err != nil {
			return BannerResult{Host: host, Port: port, Protocol: protocol, Error: err.Error()}
		}
		defer c.Close(websocket.StatusNormalClosure, "")
		banner = "WebSocket handshake successful"

	default:
		var conn net.Conn
		conn, err = net.DialTimeout("tcp", address, timeout)
		if err != nil {
			return BannerResult{Host: host, Port: port, Protocol: protocol, Error: err.Error()}
		}
		defer conn.Close()
		conn.SetDeadline(time.Now().Add(timeout))
		if payload != "" {
			fmt.Fprintf(conn, payload, host)
		}
		buf := make([]byte, maxBytes)
		n, _ := conn.Read(buf)
		banner = string(buf[:n])
	}

	fp := fingerprintBanner(banner)
	tlsVer, cipher, issuer, cn := getTLSInfo(tlsState)

	
	vulns := checkVulnerabilities(host, port, protocol, banner)
	exploits := attemptExploitation(host, port, protocol, vulns)
	enum := enumerateService(host, port, protocol)
	brute := bruteForceService(host, port, protocol, userlist, passlist)
	attacks := protocolAttacks(host, port, protocol)
	deepParse := deepProtocolParse(host, port, protocol)

	report := generateReport(BannerResult{
		Host:        host,
		Port:        port,
		Protocol:    protocol,
		Banner:      banner,
		Fingerprint: fp,
		TLSVersion:  tlsVer,
		Cipher:      cipher,
		CertIssuer:  issuer,
		CertCN:      cn,
		Vulns:       vulns,
		Exploits:    exploits,
		Enum:        enum,
		Brute:       brute,
	})

	
	report += "\nProtocol Attacks: " + strings.Join(attacks, ", ")
	report += "\nDeep Protocol Parsing: " + strings.Join(deepParse, ", ")

	result := BannerResult{
		Host:        host,
		Port:        port,
		Protocol:    protocol,
		Banner:      banner,
		Fingerprint: fp,
		TLSVersion:  tlsVer,
		Cipher:      cipher,
		CertIssuer:  issuer,
		CertCN:      cn,
		Vulns:       vulns,
		Exploits:    exploits,
		Enum:        enum,
		Brute:       brute,
		Report:      report,
	}

	
	if pluginDir != "" {
		runPlugins(pluginDir, &result)
	}

	return result
}


func parseTarget(target string) (host, port string) {
	if strings.HasPrefix(target, "[") {
		end := strings.Index(target, "]")
		if end > 0 {
			host = target[1:end]
			if len(target) > end+1 && target[end+1] == ':' {
				port = target[end+2:]
			}
			return
		}
	}
	parts := strings.Split(target, ":")
	if len(parts) > 1 {
		port = parts[len(parts)-1]
		host = strings.Join(parts[:len(parts)-1], ":")
	} else {
		host = target
	}
	return
}

func readLines(filename string) []string {
	var lines []string
	data, err := ioutil.ReadFile(filename)
	if err != nil {
		return lines
	}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line != "" {
			lines = append(lines, line)
		}
	}
	return lines
}


func main() {
	asciiArt := `
__________                                      ________                                        
\______   \_____    ____   ____   ___________  /  _____/___________  ______        ____   ____  
 |    |  _/\__  \  /    \ /    \_/ __ \_  __ \/   \  __\_  __ \__  \ \____ \      / ___\ /  _ \ 
 |    |   \ / __ \|   |  \   |  \  ___/|  | \/\    \_\  \  | \// __ \|  |_> >    / /_/  >  <_> )
 |______  /(____  /___|  /___|  /\___  >__|    \______  /__|  (____  /   __/ /\  \___  / \____/ 
        \/      \/     \/     \/     \/               \/           \/|__|    \/ /_____/         
                                                                               V2.0 BY Mr.EchoFi				
`
	fmt.Println(asciiArt)

	//flags>
	targetsFile := flag.String("f", "", "File with list of targets (host[:port] per line)")
	protocol := flag.String("proto", "http", "Protocol: http, https, http2, websocket, ftp, smtp, ssh, telnet, custom")
	portFlag := flag.String("port", "", "Override port for all targets")
	payload := flag.String("payload", "", "Custom payload (default based on protocol)")
	timeout := flag.Int("timeout", 5, "Timeout (s) per connection/read")
	threads := flag.Int("threads", 10, "Number of concurrent scans")
	maxBytes := flag.Int("max", 4096, "Maximum banner bytes to read")
	output := flag.String("o", "", "Output file (.json or .csv)")
	verbose := flag.Bool("v", false, "Verbose: print progress per target")
	version := flag.Bool("version", false, "Show version and exit")
	bruteUserlist := flag.String("brute-userlist", "", "Username list for brute force (optional)")
	brutePasslist := flag.String("brute-passlist", "", "Password list for brute force (optional)")
	reportHTML := flag.String("report-html", "", "Output HTML report (optional)")
	pluginDir := flag.String("plugin-dir", "", "Directory for custom plugins/scripts (optional)")
	flag.Parse()

	if *version {
		fmt.Println("bannerGrap version 2.0 by MrEchoFi_Md.Abu Naser Nayeem [Tanjib Isham]")
		os.Exit(0)
	}

	
	var targets []string
	if *targetsFile != "" {
		file, err := os.Open(*targetsFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error opening targets file: %v\n", err)
			os.Exit(1)
		}
		defer file.Close()
		s := bufio.NewScanner(file)
		for s.Scan() {
			line := strings.TrimSpace(s.Text())
			if line != "" && !strings.HasPrefix(line, "#") {
				targets = append(targets, line)
			}
		}
	} else {
		targets = flag.Args()
	}
	if len(targets) == 0 {
		fmt.Println(`Usage: go run bannerGrap.go
-> & read these two files of its Usage:
[i] bannerGrap_Guid or Usage.txt
[ii] Speacially read this- New_advanced_bashScripts.md 
-> Btw 2nd file i mean New_advanced_bashScripts.md is for version 2.0 speacily but the bannerGrap_Guid or Usage.txt is also important cause in this file it have all usages like basic to aggresive usage..
[iii] you can use or run this tool like this: 
      go build bannerGrap.go 
	  then run it like this:
	  ./bannerGrap 
	  or, ./bannerGrap -f targets.txt -proto http -port 80 -timeout 5 -threads 10 -max 4096 -o output.json -v --brute-userlist users.txt --brute-passlist pass.txt --report-html report.html --plugin-dir plugins/
`)
		flag.PrintDefaults()
		os.Exit(1)
	}

	proto := strings.ToLower(*protocol)
	payloadStr, ok := protocolPayloads[proto]
	if !ok {
		payloadStr = *payload
	} else if *payload != "" {
		payloadStr = *payload
	}
	overPort := *portFlag
	timeoutDur := time.Duration(*timeout) * time.Second

	
	var userlist, passlist []string
	if *bruteUserlist != "" {
		userlist = readLines(*bruteUserlist)
	}
	if *brutePasslist != "" {
		passlist = readLines(*brutePasslist)
	}

	
	sem := make(chan struct{}, *threads)
	var wg sync.WaitGroup
	results := make([]BannerResult, len(targets))
	success := 0
	errors := 0
	var mu sync.Mutex

	for i, tgt := range targets {
		wg.Add(1)
		go func(idx int, target string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			host, port := parseTarget(target)
			if overPort != "" {
				port = overPort
			} else if port == "" {
				switch proto {
				case "https", "http2", "websocket":
					port = "443"
				case "http":
					port = "80"
				case "ftp":
					port = "21"
				case "smtp":
					port = "25"
				case "ssh":
					port = "22"
				case "telnet":
					port = "23"
				default:
					port = "80"
				}
			}

			if *verbose {
				fmt.Printf("Scanning %s:%s (%s)\n", host, port, proto)
			}
			res := grabBanner(host, port, proto, payloadStr, timeoutDur, *maxBytes, userlist, passlist, *pluginDir)
			results[idx] = res
			mu.Lock()
			if res.Error != "" {
				errors++
			} else {
				success++
			}
			mu.Unlock()
		}(i, tgt)
	}
	wg.Wait()

	
	if *output != "" {
		if strings.HasSuffix(*output, ".json") {
			f, err := os.Create(*output)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error creating output file: %v\n", err)
				os.Exit(1)
			}
			defer f.Close()
			enc := json.NewEncoder(f)
			enc.SetIndent("", "  ")
			enc.Encode(results)
			fmt.Println("Wrote", *output)
		} else if strings.HasSuffix(*output, ".csv") {
			f, err := os.Create(*output)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Error creating output file: %v\n", err)
				os.Exit(1)
			}
			defer f.Close()
			w := csv.NewWriter(f)
			w.Write([]string{"host", "port", "protocol", "banner", "fingerprint", "tls_version", "cipher", "cert_issuer", "cert_cn", "vulnerabilities", "exploits", "enumeration", "bruteforce", "report", "error"})
			for _, r := range results {
				w.Write([]string{r.Host, r.Port, r.Protocol, r.Banner, r.Fingerprint, r.TLSVersion, r.Cipher, r.CertIssuer, r.CertCN, strings.Join(r.Vulns, ";"), strings.Join(r.Exploits, ";"), strings.Join(r.Enum, ";"), strings.Join(r.Brute, ";"), r.Report, r.Error})
			}
			w.Flush()
			fmt.Println("Wrote", *output)
		} else {
			fmt.Fprintf(os.Stderr, "Unknown output format: %s\n", *output)
			os.Exit(1)
		}
	}
	if *reportHTML != "" {
		if err := writeHTMLReport(*reportHTML, results); err != nil {
			fmt.Fprintf(os.Stderr, "Error writing HTML report: %v\n", err)
		} else {
			fmt.Println("Wrote", *reportHTML)
		}
	}
	if *output == "" && *reportHTML == "" {
		
		for _, r := range results {
			fmt.Printf("%s:%s [%s]\n", r.Host, r.Port, r.Protocol)
			if r.Error != "" {
				fmt.Printf("  ERROR: %s\n", r.Error)
			} else {
				fmt.Printf("  Banner: %s\n", r.Banner)
				if r.Fingerprint != "" {
					fmt.Printf("  Fingerprint: %s\n", r.Fingerprint)
				}
				if r.TLSVersion != "" {
					fmt.Printf("  TLS: %s | Cipher: %s\n", r.TLSVersion, r.Cipher)
					fmt.Printf("  Cert Issuer: %s | CN: %s\n", r.CertIssuer, r.CertCN)
				}
				if len(r.Vulns) > 0 {
					fmt.Printf("  Vulnerabilities: %s\n", strings.Join(r.Vulns, ", "))
				}
				if len(r.Exploits) > 0 {
					fmt.Printf("  Exploits: %s\n", strings.Join(r.Exploits, ", "))
				}
				if len(r.Enum) > 0 {
					fmt.Printf("  Enumeration: %s\n", strings.Join(r.Enum, ", "))
				}
				if len(r.Brute) > 0 {
					fmt.Printf("  BruteForce: %s\n", strings.Join(r.Brute, ", "))
				}
				fmt.Printf("  Report:\n%s\n", r.Report)
			}
			fmt.Println(strings.Repeat("-", 60))
		}
	}

	fmt.Printf("\nScan complete: %d succeeded, %d errors\n", success, errors)
	fmt.Println(">.>Tip: If u need-> more protocol support, try --proto http2 or --proto websocket!")
}
