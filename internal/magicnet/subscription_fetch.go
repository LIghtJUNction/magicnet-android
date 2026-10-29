package magicnet

import (
	"compress/gzip"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"
)

type SubscriptionUsage struct {
	Upload   *int64 `json:"upload_bytes"`
	Download *int64 `json:"download_bytes"`
	Total    *int64 `json:"total_bytes"`
	Expire   *int64 `json:"expire_epoch"`
	Updated  *int64 `json:"updated_epoch"`
}

func ParseSubscriptionUsage(headers []string, now time.Time) SubscriptionUsage {
	u := SubscriptionUsage{}
	if len(headers) == 0 {
		return u
	}
	values := map[string][]string{}
	for _, h := range headers {
		for _, segment := range strings.Split(h, ";") {
			k, v, ok := strings.Cut(strings.TrimSpace(segment), "=")
			if ok {
				k = strings.ToLower(strings.TrimSpace(k))
				values[k] = append(values[k], strings.TrimSpace(v))
			}
		}
	}
	for key, dest := range map[string]**int64{"upload": &u.Upload, "download": &u.Download, "total": &u.Total, "expire": &u.Expire} {
		vs := values[key]
		if len(vs) != 1 {
			continue
		}
		s := vs[0]
		if len(s) < 1 || len(s) > 16 {
			continue
		}
		valid := true
		for _, c := range s {
			if c < '0' || c > '9' {
				valid = false
			}
		}
		if !valid {
			continue
		}
		n, e := strconv.ParseInt(s, 10, 64)
		if e != nil || n > 9007199254740991 {
			continue
		}
		if key == "expire" && (n <= 0 || n > 253402300799) {
			continue
		}
		v := n
		*dest = &v
	}
	n := now.Unix()
	if n > 0 && n <= 253402300799 {
		u.Updated = &n
	}
	return u
}

func sanitizeUsage(u SubscriptionUsage) SubscriptionUsage {
	for _, p := range []**int64{&u.Upload, &u.Download, &u.Total} {
		if *p != nil && (**p < 0 || **p > 9007199254740991) {
			*p = nil
		}
	}
	for _, p := range []**int64{&u.Expire, &u.Updated} {
		if *p != nil && (**p <= 0 || **p > 253402300799) {
			*p = nil
		}
	}
	return u
}

type FetchedSubscription struct {
	Body  []byte
	Usage SubscriptionUsage
}

// SubscriptionFetcher uses Go's direct transport with no environment proxies,
// no curlrc/loader process and a new DNS/IP binding for every redirect.
type SubscriptionFetcher struct {
	Resolver func(context.Context, string) ([]netip.Addr, error)
	// DialAddress is a test seam. Production leaves it nil and dials only the
	// already validated literal IP address supplied here.
	DialAddress    func(context.Context, string, string) (net.Conn, error)
	TLSConfig      *tls.Config
	TotalTimeout   time.Duration
	ConnectTimeout time.Duration
}

func ResolveSubscriptionHost(ctx context.Context, host string, port int) ([]netip.Addr, error) {
	if port < 1 || port > 65535 {
		return nil, E("subscription.url_policy", "Invalid destination port")
	}
	if ip, e := netip.ParseAddr(host); e == nil {
		if !PublicSubscriptionAddress(ip) {
			return nil, E("subscription.url_policy", "Non-public subscription destination is prohibited")
		}
		return []netip.Addr{ip}, nil
	}
	host, e := canonicalDomain(host)
	if e != nil {
		return nil, E("subscription.url_policy", "Invalid destination hostname")
	}
	ips, e := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
	if e != nil {
		return nil, E("subscription.dns_failed", "Subscription DNS resolution failed")
	}
	if e = validateResolvedAddresses(ips); e != nil {
		return nil, e
	}
	sort.Slice(ips, func(i, j int) bool { return ips[i].Less(ips[j]) })
	return ips, nil
}

func validateResolvedAddresses(ips []netip.Addr) error {
	if len(ips) == 0 {
		return E("subscription.dns_failed", "Subscription hostname has no addresses")
	}
	if len(ips) > 128 {
		return E("subscription.url_policy", "Subscription destination has too many addresses")
	}
	for _, ip := range ips {
		if !PublicSubscriptionAddress(ip) {
			return E("subscription.url_policy", "Non-public subscription destination is prohibited")
		}
	}
	return nil
}

func (f *SubscriptionFetcher) Fetch(ctx context.Context, normalizedURL, ua string) (FetchedSubscription, error) {
	var empty FetchedSubscription
	u, e := NormalizeSubscriptionURL(normalizedURL)
	if e != nil || u != normalizedURL {
		return empty, E("subscription.url_policy", "Source identity must be canonical before download")
	}
	total := f.TotalTimeout
	if total == 0 {
		total = 45 * time.Second
	}
	connect := f.ConnectTimeout
	if connect == 0 {
		connect = 10 * time.Second
	}
	if total < time.Second || total > 120*time.Second || connect < time.Second || connect > 30*time.Second {
		return empty, E("subscription.input_invalid", "Invalid subscription timeout budget")
	}
	ctx, cancel := context.WithTimeout(ctx, total)
	defer cancel()
	for attempt := 0; attempt < 3; attempt++ {
		body, usage, retry, err := f.fetchAttempt(ctx, u, ua, connect)
		if err == nil {
			return FetchedSubscription{body, usage}, nil
		}
		if !retry || attempt == 2 {
			return empty, err
		}
		select {
		case <-ctx.Done():
			return empty, E("subscription.download_timeout", "Subscription download exceeded its deadline")
		case <-time.After(time.Duration(attempt+1) * time.Second):
		}
	}
	return empty, E("subscription.download_failed", "Subscription download failed")
}

func (f *SubscriptionFetcher) fetchAttempt(ctx context.Context, start, ua string, connect time.Duration) ([]byte, SubscriptionUsage, bool, error) {
	current := start
	for redirect := 0; redirect <= 5; redirect++ {
		u, e := url.Parse(current)
		if e != nil {
			return nil, SubscriptionUsage{}, false, E("subscription.url_policy", "Invalid redirect URL")
		}
		port := 443
		if u.Port() != "" {
			port, _ = strconv.Atoi(u.Port())
		}
		dnsCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
		var ips []netip.Addr
		if ip, err := netip.ParseAddr(u.Hostname()); err == nil {
			ips = []netip.Addr{ip}
		} else if f.Resolver != nil {
			ips, e = f.Resolver(dnsCtx, u.Hostname())
		} else {
			ips, e = net.DefaultResolver.LookupNetIP(dnsCtx, "ip", u.Hostname())
		}
		dnsTimedOut := dnsCtx.Err() != nil
		cancel()
		if e != nil {
			if ctx.Err() != nil || dnsTimedOut {
				return nil, SubscriptionUsage{}, true, E("subscription.download_timeout", "Subscription DNS resolution timed out")
			}
			return nil, SubscriptionUsage{}, true, E("subscription.dns_failed", "Subscription DNS resolution failed")
		}
		if e = validateResolvedAddresses(ips); e != nil {
			return nil, SubscriptionUsage{}, false, e
		}
		tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12, ServerName: u.Hostname()}
		if f.TLSConfig != nil {
			tlsConfig = f.TLSConfig.Clone()
			tlsConfig.ServerName = u.Hostname()
			if tlsConfig.InsecureSkipVerify {
				return nil, SubscriptionUsage{}, false, E("subscription.url_policy", "TLS verification cannot be disabled")
			}
		}
		transport := &http.Transport{Proxy: nil, DisableCompression: true, DisableKeepAlives: true, TLSClientConfig: tlsConfig, TLSHandshakeTimeout: connect, ResponseHeaderTimeout: connect, MaxResponseHeaderBytes: 64 << 10, ForceAttemptHTTP2: true}
		transport.DialContext = func(dialCtx context.Context, network, address string) (net.Conn, error) {
			// The request hostname is never resolved by DialContext.
			// All resolved addresses share one connection budget; a long DNS
			// answer must not multiply the advertised connect timeout.
			dialCtx, cancelDial := context.WithTimeout(dialCtx, connect)
			defer cancelDial()
			var last error
			for _, ip := range ips {
				target := net.JoinHostPort(ip.String(), strconv.Itoa(port))
				var conn net.Conn
				if f.DialAddress != nil {
					conn, last = f.DialAddress(dialCtx, network, target)
				} else {
					d := net.Dialer{Timeout: connect, KeepAlive: -1}
					conn, last = d.DialContext(dialCtx, network, target)
				}
				if last == nil {
					return conn, nil
				}
				if dialCtx.Err() != nil {
					break
				}
			}
			return nil, last
		}
		client := &http.Client{Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
		req, e := http.NewRequestWithContext(ctx, http.MethodGet, current, nil)
		if e != nil {
			transport.CloseIdleConnections()
			return nil, SubscriptionUsage{}, false, E("subscription.url_policy", "Invalid subscription request")
		}
		req.Header.Set("Accept-Encoding", "gzip")
		if ua != "" {
			req.Header.Set("User-Agent", ua)
		} else {
			req.Header.Set("User-Agent", "MagicNet/"+Version)
		}
		resp, e := client.Do(req)
		if e != nil {
			transport.CloseIdleConnections()
			code, retry := classifyFetchError(ctx, e)
			return nil, SubscriptionUsage{}, retry, E("subscription."+code, "Subscription request failed at the indicated stage")
		}
		if resp.StatusCode >= 300 && resp.StatusCode <= 308 && resp.StatusCode != 304 {
			location := resp.Header.Get("Location")
			resp.Body.Close()
			transport.CloseIdleConnections()
			if redirect == 5 || location == "" {
				return nil, SubscriptionUsage{}, false, E("subscription.url_policy", "Subscription redirect limit or policy violation")
			}
			rel, e := url.Parse(location)
			if e != nil {
				return nil, SubscriptionUsage{}, false, E("subscription.url_policy", "Invalid subscription redirect")
			}
			next := u.ResolveReference(rel).String()
			current, e = NormalizeSubscriptionURL(next)
			if e != nil {
				return nil, SubscriptionUsage{}, false, e
			}
			continue
		}
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			resp.Body.Close()
			transport.CloseIdleConnections()
			retry := false
			switch resp.StatusCode {
			case 408, 429, 500, 502, 503, 504:
				retry = true
			}
			return nil, SubscriptionUsage{}, retry, E("subscription.download_failed", "Subscription server returned an unsuccessful status")
		}
		reader := io.Reader(resp.Body)
		var gz *gzip.Reader
		switch strings.ToLower(strings.TrimSpace(resp.Header.Get("Content-Encoding"))) {
		case "", "identity":
		case "gzip":
			gz, e = gzip.NewReader(resp.Body)
			if e != nil {
				resp.Body.Close()
				transport.CloseIdleConnections()
				return nil, SubscriptionUsage{}, false, E("subscription.download_failed", "Invalid compressed subscription response")
			}
			reader = gz
		default:
			resp.Body.Close()
			transport.CloseIdleConnections()
			return nil, SubscriptionUsage{}, false, E("subscription.download_failed", "Unsupported subscription response encoding")
		}
		body, e := io.ReadAll(io.LimitReader(reader, SubscriptionDocumentLimit+1))
		if gz != nil {
			gz.Close()
		}
		resp.Body.Close()
		transport.CloseIdleConnections()
		if int64(len(body)) > SubscriptionDocumentLimit {
			return nil, SubscriptionUsage{}, false, E("subscription.response_too_large", "Subscription response exceeds 8 MiB after decompression")
		}
		if e != nil {
			code, retry := classifyFetchError(ctx, e)
			return nil, SubscriptionUsage{}, retry, E("subscription."+code, "Subscription response could not be read completely")
		}
		if len(body) == 0 {
			return nil, SubscriptionUsage{}, false, E("subscription.download_failed", "Subscription response is empty")
		}
		usage := ParseSubscriptionUsage(resp.Header.Values("Subscription-Userinfo"), time.Now())
		return body, usage, false, nil
	}
	return nil, SubscriptionUsage{}, false, E("subscription.url_policy", "Subscription redirect policy failed")
}

func classifyFetchError(ctx context.Context, e error) (string, bool) {
	if errors.Is(ctx.Err(), context.Canceled) {
		return "interrupted", false
	}
	if ctx.Err() != nil {
		return "download_timeout", true
	}
	// net/http intentionally keeps these transport limit errors unexported.
	// Classify locally without ever exposing their request-bearing text.
	if strings.Contains(e.Error(), "server response headers exceeded") || strings.Contains(e.Error(), "response header list larger than advertised limit") {
		return "response_too_large", false
	}
	var unknown x509.UnknownAuthorityError
	var invalid x509.CertificateInvalidError
	var hostname x509.HostnameError
	var verification *tls.CertificateVerificationError
	var record tls.RecordHeaderError
	if errors.As(e, &unknown) || errors.As(e, &invalid) || errors.As(e, &hostname) || errors.As(e, &verification) || errors.As(e, &record) {
		return "tls_failed", false
	}
	var dns *net.DNSError
	if errors.As(e, &dns) {
		return "dns_failed", true
	}
	var ne net.Error
	if errors.As(e, &ne) && ne.Timeout() {
		return "download_timeout", true
	}
	return "download_failed", true
}
