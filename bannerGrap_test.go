package main

import (
	"encoding/binary"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestCompareVersions(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		{"2.4.49", "2.4.50", -1},
		{"2.4.50", "2.4.49", 1},
		{"2.4.49", "2.4.49", 0},
		{"8.5", "8.4", 1},
		{"8.4", "8.5", -1},
		{"1.0.1", "1.0.1e", 0}, // trailing letters ignored - documented simplification
	}
	for _, c := range cases {
		if got := compareVersions(c.a, c.b); got != c.want {
			t.Errorf("compareVersions(%q, %q) = %d, want %d", c.a, c.b, got, c.want)
		}
	}
}

func TestVersionInRange(t *testing.T) {
	// Mirrors the real CVE-2021-41773 affected range: Apache httpd
	// [2.4.49, 2.4.50) - i.e. exactly 2.4.49, fixed in 2.4.50.
	inRange := func(v string) bool {
		return versionInRange(v, "2.4.49", "", "", "2.4.50")
	}
	if !inRange("2.4.49") {
		t.Error("2.4.49 should be in range [2.4.49, 2.4.50)")
	}
	if inRange("2.4.50") {
		t.Error("2.4.50 should NOT be in range [2.4.49, 2.4.50) - versionEndExcluding")
	}
	if inRange("2.4.48") {
		t.Error("2.4.48 should NOT be in range [2.4.49, 2.4.50)")
	}
	if inRange("2.5.0") {
		t.Error("2.5.0 should NOT be in range [2.4.49, 2.4.50)")
	}
}

// syntheticApacheCVE builds a fixture resembling NVD's real API 2.0 shape
// for CVE-2021-41773 (Apache path traversal / RCE), affecting Apache
// httpd 2.4.49 specifically (versionStartIncluding=2.4.49,
// versionEndExcluding=2.4.50).
func syntheticApacheCVE() *nvdCVE {
	return &nvdCVE{
		ID: "CVE-2021-41773",
		Descriptions: []struct {
			Lang  string `json:"lang"`
			Value string `json:"value"`
		}{
			{Lang: "en", Value: "A flaw was found in a change made to path normalization in Apache HTTP Server 2.4.49."},
		},
		Configurations: []nvdConfiguration{
			{
				Nodes: []nvdConfigNode{
					{
						CPEMatch: []nvdCPEMatch{
							{
								Vulnerable:            true,
								Criteria:              "cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*",
								VersionStartIncluding: "2.4.49",
								VersionEndExcluding:   "2.4.50",
							},
						},
					},
				},
			},
		},
	}
}

func TestNVDCheckVersionRange_InRange(t *testing.T) {
	cve := syntheticApacheCVE()
	got := nvdCheckVersionRange(cve, "apache:http_server", "2.4.49")
	if got != nvdVerdictMatch {
		t.Errorf("version 2.4.49 (the actual vulnerable version) should be nvdVerdictMatch, got %v", got)
	}
}

func TestNVDCheckVersionRange_OutOfRange(t *testing.T) {
	cve := syntheticApacheCVE()
	// This is the exact false-positive scenario reported during manual testing:
	// checkVulnerabilities' string-contains match would flag ANY "Apache/2.4.x"
	// banner, but CVE-2021-41773 only affects 2.4.49 specifically.
	got := nvdCheckVersionRange(cve, "apache:http_server", "2.4.51")
	if got != nvdVerdictNoMatch {
		t.Errorf("version 2.4.51 (patched, outside range) should be nvdVerdictNoMatch, got %v", got)
	}
	got = nvdCheckVersionRange(cve, "apache:http_server", "2.4.41")
	if got != nvdVerdictNoMatch {
		t.Errorf("version 2.4.41 (older, outside range) should be nvdVerdictNoMatch, got %v", got)
	}
}

func TestNVDCheckVersionRange_UnrelatedProduct(t *testing.T) {
	cve := syntheticApacheCVE()
	got := nvdCheckVersionRange(cve, "nginx:nginx", "1.18.0")
	if got != nvdVerdictUnknown {
		t.Errorf("unrelated vendor:product should be nvdVerdictUnknown (no matching CPE criteria), got %v", got)
	}
}

func TestNVDCheckVersionRange_ExactVersionNoRange(t *testing.T) {
	// Some CVEs encode an exact version directly in the criteria string
	// instead of using versionStart/End fields.
	cve := &nvdCVE{
		ID: "CVE-TEST-0001",
		Configurations: []nvdConfiguration{
			{Nodes: []nvdConfigNode{{CPEMatch: []nvdCPEMatch{
				{Vulnerable: true, Criteria: "cpe:2.3:a:proftpd:proftpd:1.3.5:*:*:*:*:*:*:*"},
			}}}},
		},
	}
	if got := nvdCheckVersionRange(cve, "proftpd:proftpd", "1.3.5"); got != nvdVerdictMatch {
		t.Errorf("exact-version criteria match should be nvdVerdictMatch, got %v", got)
	}
	if got := nvdCheckVersionRange(cve, "proftpd:proftpd", "1.3.6"); got != nvdVerdictNoMatch {
		t.Errorf("differing exact version should be nvdVerdictNoMatch, got %v", got)
	}
}

func TestNVDFormatEntry_TagsAndFields(t *testing.T) {
	cve := syntheticApacheCVE()
	cve.Metrics.CvssMetricV31 = []struct {
		CvssData struct {
			BaseScore    float64 `json:"baseScore"`
			BaseSeverity string  `json:"baseSeverity"`
		} `json:"cvssData"`
	}{
		{CvssData: struct {
			BaseScore    float64 `json:"baseScore"`
			BaseSeverity string  `json:"baseSeverity"`
		}{BaseScore: 9.8, BaseSeverity: "CRITICAL"}},
	}

	verified := nvdFormatEntry(cve, "VERIFIED")
	if verified.ID != "CVE-2021-41773" {
		t.Errorf("ID = %q, want CVE-2021-41773", verified.ID)
	}
	wantPrefix := "[VERIFIED] CVE-2021-41773 [CRITICAL 9.8]:"
	if !strings.HasPrefix(verified.Entry, wantPrefix) {
		t.Errorf("Entry = %q, want prefix %q", verified.Entry, wantPrefix)
	}

	unverified := nvdFormatEntry(cve, "UNVERIFIED")
	if !strings.HasPrefix(unverified.Entry, "[UNVERIFIED]") {
		t.Errorf("Entry = %q, want to start with [UNVERIFIED]", unverified.Entry)
	}
}

func TestExtractNVDCandidates_SkipsHTTPStatusLine(t *testing.T) {
	// The bug that caused the original false-empty-result report: the
	// extractor must NOT pick "HTTP/1.1" (from the status line) as a
	// candidate over the real "Server: Microsoft-IIS/8.5" header.
	banner := "HTTP/1.1 200 OK\r\nServer: Microsoft-IIS/8.5\r\nX-Powered-By: ASP.NET\r\nDate: Mon, 01 Jan 2024 00:00:00 GMT\r\n\r\n"
	candidates := extractNVDCandidates(banner)
	if len(candidates) == 0 {
		t.Fatal("expected candidates, got none")
	}
	for _, c := range candidates {
		if c.Product == "HTTP" {
			t.Errorf("HTTP status line should never be extracted as a candidate, got %+v", c)
		}
	}
	found := false
	for _, c := range candidates {
		if c.Product == "Microsoft-IIS" && c.Version == "8.5" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected a Microsoft-IIS/8.5 candidate, got %+v", candidates)
	}
}

func TestBuildCPEName_KnownAndUnknownProducts(t *testing.T) {
	cpeName, vendorProduct, ok := buildCPEName("Microsoft-IIS", "8.5")
	if !ok {
		t.Fatal("expected Microsoft-IIS to be in nvdCPEProductMap")
	}
	wantCPE := "cpe:2.3:a:microsoft:internet_information_services:8.5:*:*:*:*:*:*:*"
	if cpeName != wantCPE {
		t.Errorf("cpeName = %q, want %q", cpeName, wantCPE)
	}
	if vendorProduct != "microsoft:internet_information_services" {
		t.Errorf("vendorProduct = %q", vendorProduct)
	}

	if _, _, ok := buildCPEName("SomeRandomUnknownServer", "1.0"); ok {
		t.Error("unknown product should not build a CPE name")
	}
}

func TestAJPPackString(t *testing.T) {
	empty := ajpPackString("")
	if len(empty) != 2 || empty[0] != 0xFF || empty[1] != 0xFF {
		t.Errorf("empty string should encode as the 0xFFFF null marker, got %v", empty)
	}

	s := ajpPackString("hi")
	if len(s) != 5 { // 2-byte length + "hi" + null terminator
		t.Fatalf("len(ajpPackString(\"hi\")) = %d, want 5", len(s))
	}
	if gotLen := binary.BigEndian.Uint16(s[0:2]); gotLen != 2 {
		t.Errorf("length prefix = %d, want 2", gotLen)
	}
	if string(s[2:4]) != "hi" {
		t.Errorf("string body = %q, want \"hi\"", s[2:4])
	}
	if s[4] != 0 {
		t.Errorf("missing null terminator, got %v", s[4])
	}
}

// TestBuildGhostcatProbePacket_Structure decodes the AJP13 packet built for
// the Ghostcat (CVE-2020-1938) probe field-by-field and checks it against
// the AJP13 "Forward Request" wire format, since there's no way to validate
// this against a live Tomcat AJP connector from this environment.
func TestBuildGhostcatProbePacket_Structure(t *testing.T) {
	packet := buildGhostcatProbePacket("/WEB-INF/web.xml")

	if len(packet) < 4 {
		t.Fatalf("packet too short: %d bytes", len(packet))
	}
	if packet[0] != 0x12 || packet[1] != 0x34 {
		t.Errorf("packet magic = %x %x, want 12 34 (AJP13 client->container)", packet[0], packet[1])
	}
	declaredLen := int(binary.BigEndian.Uint16(packet[2:4]))
	body := packet[4:]
	if declaredLen != len(body) {
		t.Errorf("declared body length = %d, actual body length = %d", declaredLen, len(body))
	}
	if len(body) < 2 || body[0] != 0x02 || body[1] != 0x02 {
		t.Fatalf("body should start with prefix=0x02 (FORWARD_REQUEST) method=0x02 (GET), got %v", body[:2])
	}

	pos := 2
	readString := func() string {
		l := int(binary.BigEndian.Uint16(body[pos : pos+2]))
		pos += 2
		s := string(body[pos : pos+l])
		pos += l + 1 // + null terminator
		return s
	}

	if got := readString(); got != "HTTP/1.1" {
		t.Errorf("protocol = %q, want HTTP/1.1", got)
	}
	if got := readString(); got != "/" {
		t.Errorf("req_uri = %q, want /", got)
	}
	if got := readString(); got != "127.0.0.1" {
		t.Errorf("remote_addr = %q, want 127.0.0.1", got)
	}
	if body[pos] != 0xFF || body[pos+1] != 0xFF {
		t.Errorf("remote_host should be null marker 0xFFFF, got %x %x", body[pos], body[pos+1])
	}
	pos += 2
	if got := readString(); got != "localhost" {
		t.Errorf("server_name = %q, want localhost", got)
	}
	serverPort := binary.BigEndian.Uint16(body[pos : pos+2])
	pos += 2
	if serverPort != 80 {
		t.Errorf("server_port = %d, want 80", serverPort)
	}
	isSSL := body[pos]
	pos++
	if isSSL != 0 {
		t.Errorf("is_ssl = %d, want 0", isSSL)
	}
	numHeaders := binary.BigEndian.Uint16(body[pos : pos+2])
	pos += 2
	if numHeaders != 0 {
		t.Errorf("num_headers = %d, want 0", numHeaders)
	}

	type attr struct{ name, value string }
	var attrs []attr
	for pos < len(body) && body[pos] == 0x0A {
		pos++
		name := readString()
		value := readString()
		attrs = append(attrs, attr{name, value})
	}
	if pos >= len(body) || body[pos] != 0xFF {
		t.Errorf("expected 0xFF terminator after attributes at pos %d", pos)
	}

	want := []attr{
		{"javax.servlet.include.request_uri", "/"},
		{"javax.servlet.include.path_info", "/WEB-INF/web.xml"},
		{"javax.servlet.include.servlet_path", "/"},
	}
	if len(attrs) != len(want) {
		t.Fatalf("got %d attributes, want %d: %+v", len(attrs), len(want), attrs)
	}
	for i, w := range want {
		if attrs[i] != w {
			t.Errorf("attr[%d] = %+v, want %+v", i, attrs[i], w)
		}
	}
}

func TestProbeGhostcat_MockServer_Match(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to start mock listener: %v", err)
	}
	defer ln.Close()

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		buf := make([]byte, 4096)
		conn.Read(buf) // discard the request; we only care about our own response here

		// Synthetic AJP13 SEND_BODY_CHUNK response containing web.xml-looking content.
		resp := []byte{0x41, 0x42, 0x00, 0x00, 0x03}
		resp = append(resp, []byte("<web-app>mock content for test</web-app>")...)
		conn.Write(resp)
	}()

	_, portStr, err := net.SplitHostPort(ln.Addr().String())
	if err != nil {
		t.Fatalf("failed to split listener addr: %v", err)
	}

	if !probeGhostcat("127.0.0.1", portStr) {
		t.Error("probeGhostcat should return true against a mock server returning web.xml-like content")
	}
}

func TestProbeGhostcat_MockServer_NoMatch(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to start mock listener: %v", err)
	}
	defer ln.Close()

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		buf := make([]byte, 4096)
		conn.Read(buf)
		// Not a matching AJP body-chunk response (wrong magic/prefix, no file content).
		conn.Write([]byte{0x41, 0x42, 0x00, 0x01, 0x04, 0x00})
	}()

	_, portStr, err := net.SplitHostPort(ln.Addr().String())
	if err != nil {
		t.Fatalf("failed to split listener addr: %v", err)
	}

	if probeGhostcat("127.0.0.1", portStr) {
		t.Error("probeGhostcat should return false against a non-matching response")
	}
}

func TestProbeApachePathTraversal_Vulnerable(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "etc/passwd") {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	host, portStr := mustSplitHostPort(t, srv.URL)
	if !probeApachePathTraversal(host, portStr) {
		t.Error("probeApachePathTraversal should return true when /etc/passwd content is returned")
	}
}

func TestProbeApachePathTraversal_Patched(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		w.Write([]byte("403 Forbidden"))
	}))
	defer srv.Close()

	host, portStr := mustSplitHostPort(t, srv.URL)
	if probeApachePathTraversal(host, portStr) {
		t.Error("probeApachePathTraversal should return false against a patched/non-vulnerable server")
	}
}

// TestCheckVulnerabilities_ApacheProbeConfirmation exercises the full wiring
// end-to-end: checkVulnerabilities flags CVE-2021-41773 from the banner
// string, which should trigger probeApachePathTraversal against the mock
// server, which returns /etc/passwd content, which should tag the existing
// finding "(confirmed via active probe)" in place.
func TestCheckVulnerabilities_ApacheProbeConfirmation(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "etc/passwd") {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("root:x:0:0:root:/root:/bin/bash\n"))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	host, portStr := mustSplitHostPort(t, srv.URL)
	banner := "HTTP/1.1 200 OK\r\nServer: Apache/2.4.49\r\n\r\n"
	vulns := checkVulnerabilities(host, portStr, "http", banner)

	found := false
	for _, v := range vulns {
		if strings.Contains(v, "CVE-2021-41773") && strings.Contains(v, "confirmed via active probe") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected CVE-2021-41773 to be tagged confirmed via active probe, got %v", vulns)
	}
}

// TestCheckVulnerabilities_ApacheProbeUnconfirmed verifies the inverse: when
// the version-match fires but the probe can't confirm exploitability (e.g.
// already patched), the original finding must survive untouched - not
// removed, not silently upgraded.
func TestCheckVulnerabilities_ApacheProbeUnconfirmed(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer srv.Close()

	host, portStr := mustSplitHostPort(t, srv.URL)
	banner := "HTTP/1.1 200 OK\r\nServer: Apache/2.4.49\r\n\r\n"
	vulns := checkVulnerabilities(host, portStr, "http", banner)

	foundUnconfirmed := false
	for _, v := range vulns {
		if strings.Contains(v, "CVE-2021-41773") {
			if strings.Contains(v, "confirmed via active probe") {
				t.Errorf("should not be tagged confirmed when the probe can't verify it: %q", v)
			}
			foundUnconfirmed = true
		}
	}
	if !foundUnconfirmed {
		t.Errorf("expected CVE-2021-41773 finding to still be present (unconfirmed), got %v", vulns)
	}
}

func mustSplitHostPort(t *testing.T, rawURL string) (string, string) {
	t.Helper()
	trimmed := strings.TrimPrefix(strings.TrimPrefix(rawURL, "http://"), "https://")
	host, port, err := net.SplitHostPort(trimmed)
	if err != nil {
		t.Fatalf("failed to split %q: %v", rawURL, err)
	}
	return host, port
}

func TestBuildCPEName_ContentFingerprintedProducts(t *testing.T) {
	for _, tc := range []struct{ product, wantVendorProduct string }{
		{"WordPress", "wordpress:wordpress"},
		{"phpMyAdmin", "phpmyadmin:phpmyadmin"},
		{"Django", "djangoproject:django"},
	} {
		_, vp, ok := buildCPEName(tc.product, "1.0")
		if !ok {
			t.Errorf("expected %s to be in nvdCPEProductMap", tc.product)
			continue
		}
		if vp != tc.wantVendorProduct {
			t.Errorf("%s vendorProduct = %q, want %q", tc.product, vp, tc.wantVendorProduct)
		}
	}
}

func TestFetchContentCandidates_NonHTTPProtocolSkipped(t *testing.T) {
	if got := fetchContentCandidates("example.com", "22", "ssh"); got != nil {
		t.Errorf("fetchContentCandidates should skip non-http(s) protocols, got %+v", got)
	}
}

func TestFetchContentCandidates_WordPressMetaGeneratorAndAsset(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`<html><head><meta name="generator" content="WordPress 6.4.2" /></head>` +
			`<body><link rel="stylesheet" href="/wp-content/themes/twentytwentyfour/style.css?ver=6.4.2"></body></html>`))
	})
	mux.HandleFunc("/wp-login.php", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`<html><body><form id="loginform" action="wp-login.php">WordPress Login</form></body></html>`))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	host, portStr := mustSplitHostPort(t, srv.URL)
	candidates := fetchContentCandidates(host, portStr, "http")

	found := false
	for _, c := range candidates {
		if strings.EqualFold(c.Product, "WordPress") && c.Version == "6.4.2" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected a WordPress/6.4.2 candidate from meta generator or versioned asset, got %+v", candidates)
	}
}

func TestFetchContentCandidates_PHPMyAdminLoginPage(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/phpmyadmin/", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`<html><body><input name="pma_username"><input name="pma_password"><!-- phpMyAdmin 5.2.1 --></body></html>`))
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	host, portStr := mustSplitHostPort(t, srv.URL)
	candidates := fetchContentCandidates(host, portStr, "http")

	found := false
	for _, c := range candidates {
		if strings.EqualFold(c.Product, "phpMyAdmin") && c.Version == "5.2.1" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected a phpMyAdmin/5.2.1 candidate from the login page, got %+v", candidates)
	}
}

func TestFetchContentCandidates_TomcatDefault404(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte(`<html><body><h1>HTTP Status 404 - Not Found</h1><hr/><p><i>Apache Tomcat/9.0.65</i></p></body></html>`))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	host, portStr := mustSplitHostPort(t, srv.URL)
	candidates := fetchContentCandidates(host, portStr, "http")

	found := false
	for _, c := range candidates {
		if strings.EqualFold(c.Product, "Apache Tomcat") && c.Version == "9.0.65" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected an Apache Tomcat/9.0.65 candidate from the default 404 page, got %+v", candidates)
	}
}

func TestFetchContentCandidates_DjangoDebug404(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte("Page not found (404)\nRequest Method: GET\nDjango Version: 4.2.7\n"))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	host, portStr := mustSplitHostPort(t, srv.URL)
	candidates := fetchContentCandidates(host, portStr, "http")

	found := false
	for _, c := range candidates {
		if strings.EqualFold(c.Product, "Django") && c.Version == "4.2.7" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected a Django/4.2.7 candidate from the debug 404 page, got %+v", candidates)
	}
}

// TestCheckVulnerabilitiesNVD_MergesContentAndHeaderCandidates is a
// lightweight end-to-end sanity check that checkVulnerabilitiesNVD's new
// (host, port, protocol, banner) signature actually merges
// fetchContentCandidates results with the header-based ones - it can't hit
// the real NVD API from this environment, so it only asserts the function
// doesn't panic and short-circuits cleanly with no NVD_API_KEY set.
func TestCheckVulnerabilitiesNVD_NoAPIKeyReturnsNil(t *testing.T) {
	t.Setenv("NVD_API_KEY", "")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`<meta name="generator" content="WordPress 6.4.2" />`))
	}))
	defer srv.Close()

	host, portStr := mustSplitHostPort(t, srv.URL)
	banner := "HTTP/1.1 200 OK\r\nServer: Apache/2.4.49\r\n\r\n"
	if got := checkVulnerabilitiesNVD(host, portStr, "http", banner); got != nil {
		t.Errorf("expected nil with no NVD_API_KEY set, got %v", got)
	}
}
