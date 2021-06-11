package warnlist

import (
	"fmt"
	"net"
	"strings"
	"time"
	"unicode/utf8"
)

var redirectIP = "127.0.0.1"

// Map contains the IPv4/IPv6 and reverse mapping.
type Map struct {
	// Key for the list of literal IP addresses must be a FQDN lowercased host name.
	name4 map[string][]net.IP
	name6 map[string][]net.IP

	// Key for the list of host names must be a literal IP address
	// including IPv6 address without zone identifier.
	// We don't support old-classful IP address notation.
	addr map[string][]string
}

func newMap() *Map {
	return &Map{
		name4: make(map[string][]net.IP),
		name6: make(map[string][]net.IP),
		addr:  make(map[string][]string),
	}
}

type Warnlist interface {
	Add(rr string)
	Contains(key string) bool
	lookupStaticHost(list map[string][]net.IP, host string) []net.IP
	LookupStaticAddr(addr string) []string
	LookupStaticHostV4(host string) []net.IP
	LookupStaticHostV6(host string) []net.IP
	Close() error
	Len() int
	Open()
}

func NewWarnlist() Warnlist {
	b := &GoMapWarnlist{}
	b.Open()
	return b
}

//
//func NewRadixWarnlist() Warnlist {
//	b := &RadixWarnlist{}
//	b.Open()
//	return b
//}

//
//
//type RadixWarnlist struct {
//	warnlist *iradix.Tree
//}
//
//func (r *RadixWarnlist) Add(key string) {
//	// Add the domain in reverse so we can pretend it's a prefix.
//	key = reverseString(key)
//
//	b, _, _ := r.warnlist.Insert([]byte(key), 1)
//	r.warnlist = b
//}
//
//func (r *RadixWarnlist) Contains(key string) bool {
//	keyR := reverseString(key)
//
//	m, _, ok := r.warnlist.Root().LongestPrefix([]byte(keyR))
//	if !ok {
//		return false
//	}
//	return isFullPrefixMatch(keyR, string(m))
//}
//
//func (r *RadixWarnlist) Close() error {
//	// Nothing to do to close an iradix
//	return nil
//}
//
//func (r *RadixWarnlist) Len() int {
//	return r.warnlist.Len()
//}
//
//func (r *RadixWarnlist) Open() {
//	tree := iradix.New()
//	r.warnlist = tree
//}
//

type GoMapWarnlist struct {
	warnlist *Map
}

func (m *GoMapWarnlist) Add(rr string) {
	items := strings.Split(rr, " ")
	var domain string
	var addr net.IP
	if len(items) > 1 {
		domain = items[1]
		addr = parseIP(items[0])
		if addr == nil {
			addr = parseIP(redirectIP)
		}
	} else {
		domain = items[0]
		addr = parseIP(redirectIP)

	}

	if addr.To4() != nil {
		m.warnlist.name4[domain] = append(m.warnlist.name4[domain], addr)
	} else {
		m.warnlist.name6[domain] = append(m.warnlist.name4[domain], addr)
	}
	m.warnlist.addr[addr.String()] = append(m.warnlist.addr[addr.String()], domain)

}

func (m *GoMapWarnlist) Contains(key string) bool {
	_, ip4 := m.warnlist.name4[key]
	_, ip6 := m.warnlist.name6[key]
	return ip4 || ip6
}

func (m *GoMapWarnlist) Close() error {
	// Nothing to do to close a map
	return nil
}

func (m *GoMapWarnlist) Len() int {
	return len(m.warnlist.name4) + len(m.warnlist.name6)
}

func (m *GoMapWarnlist) Open() {
	m.warnlist = newMap()
}

func (m *GoMapWarnlist) LookupStaticAddr(addr string) []string {
	addr = parseIP(addr).String()
	if addr == "" {
		return nil
	}

	blacklists1 := m.warnlist.addr[addr]
	return blacklists1
}

// lookupStaticHost looks up the IP addresses for the given host from the blacklists file.
func (m *GoMapWarnlist) lookupStaticHost(list map[string][]net.IP, host string) []net.IP {
	if len(list) == 0 {
		return nil
	}

	ips, ok := list[host]
	if !ok {
		return nil
	}
	ipsCp := make([]net.IP, len(ips))
	copy(ipsCp, ips)
	return ipsCp
}

func (m *GoMapWarnlist) LookupStaticHostV4(host string) []net.IP {
	host = strings.ToLower(host)
	ip := m.lookupStaticHost(m.warnlist.name4, host)
	return ip
}

// LookupStaticHostV6 looks up the IPv6 addresses for the given host from the blacklists file.
func (m *GoMapWarnlist) LookupStaticHostV6(host string) []net.IP {
	host = strings.ToLower(host)
	ip := m.lookupStaticHost(m.warnlist.name6, host)
	return ip
}

func buildCacheFromFile(options PluginOptions) (Warnlist, error) {
	// Print a log message with the time it took to build the cache
	defer logTime("Building warnlist cache took %s", time.Now())

	var warnlist Warnlist
	{
		if options.MatchSubdomains {
			//warnlist = NewRadixWarnlist()
			warnlist = NewWarnlist()
		} else {
			warnlist = NewWarnlist()
		}
	}

	for domain := range domainsFromSource(options.DomainSource, options.DomainSourceType, options.FileFormat) {
		warnlist.Add(domain)
	}

	err := warnlist.Close()
	if err == nil {
		log.Infof("added %d domains to warnlist", warnlist.Len())
	}

	return warnlist, err
}

// isFullPrefixMatch is a radix helper to determine if the prefix match is valid.
func isFullPrefixMatch(input string, match string) bool {
	// Either we matched the full input,
	// or this is a subdomain, so the next character should be "."
	return len(input) == len(match) || string(input[len(match)]) == "."
}

// Prints the elapsed time in the pre-formatted message
func logTime(msg string, since time.Time) {
	elapsed := time.Since(since)
	msg = fmt.Sprintf(msg, elapsed)
	log.Info(msg)
}

func rebuildWarnlist(wp *WarnlistPlugin) {
	// Rebuild the cache for the warnlist
	warnlist, err := buildCacheFromFile(wp.Options)
	if err != nil {
		log.Errorf("error rebuilding warnlist: %v#", err)

		if wp.serverName != "" {
			reloadsFailedCount.WithLabelValues(wp.serverName).Inc()
		}

		// Don't update the existing warnlist
	} else {
		reloadTime := time.Now()
		wp.warnlist = warnlist
		wp.lastReloadTime = reloadTime
	}
	if wp.serverName != "" {
		warnlistSize.WithLabelValues(wp.serverName).Set(float64(wp.warnlist.Len()))
	}

}

// reverseString returns a reversed representation of the input, including unicode.
// Shamelessly taken from https://stackoverflow.com/a/34521190
func reverseString(s string) string {
	// It may be necessary to handle punycode in here at some point.
	size := len(s)
	buf := make([]byte, size)
	for start := 0; start < size; {
		r, n := utf8.DecodeRuneInString(s[start:])
		start += n
		utf8.EncodeRune(buf[size-start:], r)
	}
	return string(buf)
}

// parseIP calls discards any v6 zone info, before calling net.ParseIP.
func parseIP(addr string) net.IP {
	if i := strings.Index(addr, "%"); i >= 0 {
		// discard ipv6 zone
		addr = addr[0:i]
	}

	return net.ParseIP(addr)
}
