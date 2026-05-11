### Output Formats: 

[i] JSON output:

         go run bannerGrap.go -f hosts.txt -o results.json
[ii] CSV output: 

         go run bannerGrap.go -f hosts.txt -o results.csv
[iii] Text output:

         go run bannerGrap.go -f hosts.txt -o results.txt
[iv] Console output:

         go run bannerGrap.go -f hosts.txt
[v] JSON output with custom payload:

         go run bannerGrap.go -f hosts.txt -proto custom -payload "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n" -o results.json
[vi] CSV output with custom payload:

	   	 go run bannerGrap.go -f hosts.txt -proto custom -payload "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n" -o results.csv
[vii] Text output with custom payload:

		 go run bannerGrap.go -f hosts.txt -proto custom -payload "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n" -o results.txt
[viii] Console output with custom payload:

		 go run bannerGrap.go -f hosts.txt -proto custom -payload "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"
[ix] JSON output with custom payload and timeout:
			go run bannerGrap.go -f hosts.txt -proto custom -payload "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n" -timeout 10 -o results.json
[x] CSV output with custom payload and timeout:
		go run bannerGrap.go -f hosts.txt -proto custom -payload "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n" -timeout 10 -o results.csv
[xi] Text output with custom payload and timeout:
	    	go run bannerGrap.go -f hosts.txt -proto custom -payload "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n" -timeout 10 -o results.txt
[xii] Console output with custom payload and timeout:
        	go run bannerGrap.go -f hosts.txt -proto custom -payload "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n" -timeout 10
[xiii] JSON output with custom payload and timeout and threads:
		   go run bannerGrap.go -f hosts.txt -proto custom -payload "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n" -timeout 10 -threads 5 -o results.json
[xiv] CSV output with custom payload and timeout and threads:
			go run bannerGrap.go -f hosts.txt -proto custom -payload "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n" -timeout 10 -threads 5 -o results.csv
    [xv] Text output with custom payload and timeout and threads:
			go run bannerGrap.go -f hosts.txt -proto custom -payload "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n" -timeout 10 -threads 5 -o results.txt
[xvi] Console output with custom payload and timeout and threads:
		go run bannerGrap.go -f hosts.txt -proto custom -payload "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n" -timeout 10 -threads 5
[xvii] JSON output with custom payload and timeout and threads and port:
        go run bannerGrap.go -f hosts.txt -proto custom -payload "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n" -timeout 10 -threads 5 -port 80 -o results.json
  [xviii] CSV output with custom payload and timeout and threads and port:
        go run bannerGrap.go -f hosts.txt -proto custom -payload "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n" -timeout 10 -threads 5 -port 80 -o results.csv
  [xix] Text output with custom payload and timeout and threads and port:
	    go run bannerGrap.go -f hosts.txt -proto custom -payload "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n" -timeout 10 -threads 5 -port 80 -o results.txt
  [xx] Console output with custom payload and timeout and threads and port:
       go run bannerGrap.go -f hosts.txt -proto custom -payload "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n" -timeout 10 -threads 5 -port 80
  [xxi] JSON output with custom payload and timeout and threads and port and protocol:
       go run bannerGrap.go -f hosts.txt -proto custom -payload "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n" -timeout 10 -threads 5 -port 80 -proto http -o results.json
  [xxii] CSV output with custom payload and timeout and threads and port and protocol:
       go run bannerGrap.go -f hosts.txt -proto custom -payload "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n" -timeout 10 -threads 5 -port 80 -proto http -o results.csv
  [xxiii] Text output with custom payload and timeout and threads and port and protocol:
       go run bannerGrap.go -f hosts.txt -proto custom -payload "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n" -timeout 10 -threads 5 -port 80 -proto http -o results.txt