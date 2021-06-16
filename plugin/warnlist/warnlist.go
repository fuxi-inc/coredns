package warnlist

import (
	"fmt"
	"github.com/miekg/dns"
	"net"
	"strings"
	"time"
	"unicode/utf8"

	"database/sql"
	_ "github.com/mattn/go-sqlite3"
)

var redirectIP = "127.0.0.1"
var redirectDomain = "block.localhost"

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
	lookupStaticHost(host string, qtype uint16) []net.IP
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

func NewWarnlistFile() Warnlist {
	b := &NewWarnlistDB{}
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

type NewWarnlistDB struct {
	db *sql.DB
}

func (d *NewWarnlistDB) Add(rr string) {
	items := strings.Split(rr, " ")
	rows, err := d.db.Query("SELECT count(*) FROM abnormal_domain_all where abnormal_domain=? and IP = ?", items[1], items[0])
	if err != nil {
		log.Errorf("query error: %v#", err)
	}

	var count int
	for rows.Next() {
		err = rows.Scan(&count)
		if err != nil {
			log.Errorf("query error: %v#", err)
		}
	}
	if count > 0 {
		stmt, err := d.db.Prepare("UPDATE abnormal_domain_all SET redirectIP=?")
		if err != nil {
			log.Errorf("prepare sql error: %v#", err)
		}
		_, err = stmt.Exec(redirectIP)
		if err != nil {
			log.Errorf("update error: %v#", err)
		}
	} else {
		stmt, err := d.db.Prepare("INSERT INTO abnormal_domain_all(abnormal_domain, IP, qtype, redirectIP)  values(?, ?, ?, ?)")
		if err != nil {
			log.Errorf("prepare sql error: %v#", err)
		}

		var queryType uint16
		if items[0] != "" {
			if parseIP(items[0]).To4() != nil {
				queryType = dns.TypeA
			} else {
				queryType = dns.TypeA
			}
		}
		_, err = stmt.Exec(items[1], items[0], queryType, redirectIP)
		if err != nil {
			log.Errorf("insertd error: %v#", err)
		}
	}

}

func (d *NewWarnlistDB) Contains(key string) bool {
	rows, err := d.db.Query("SELECT count(*) FROM abnormal_domain_all where abnormal_domain=?", key)
	if err != nil {
		log.Errorf("query error: %v#", err)
	}

	var count int
	for rows.Next() {
		err = rows.Scan(&count)
		if err != nil {
			log.Errorf("query error: %v#", err)
		}
	}
	return count > 0
}

func (d *NewWarnlistDB) Close() error {
	// Nothing to do to close a map
	return d.db.Close()
}

func (d *NewWarnlistDB) Len() int {
	rows, err := d.db.Query("SELECT count(*) FROM abnormal_domain_all")
	if err != nil {
		log.Errorf("query length error: %v#", err)
	}
	var count int
	for rows.Next() {
		err = rows.Scan(&count)
		if err != nil {
			log.Errorf("query length error: %v#", err)
		}
	}
	return count
}

func (d *NewWarnlistDB) Open() {
	database, err := sql.Open("sqlite3", "./blacklists.db")
	d.db = database
	table := `
    CREATE TABLE IF NOT EXISTS abnormal_domain_all (
    	id INTEGER PRIMARY KEY AUTOINCREMENT,
    	abnormal_domain VARCHAR(256) NOT NULL,
        IP VARCHAR(256) NULL,
        qtype SMALLINT unsigned NULL,
        redirectIP varchar(256) DEFAULT('127.0.0.1'),
        redirectDomain varchar(256) DEFAULT('block.localhost')
    );
    `
	_, err = d.db.Exec(table)
	if err != nil {
		log.Errorf("create table error: %v#", err)
	}
}

func (d *NewWarnlistDB) LookupStaticAddr(addr string) []string {
	//log.Infof(addr)

	if addr == "" {
		return nil
	}

	if d.Len() == 0 {
		return nil
	}

	rows, err := d.db.Query("SELECT redirectDomain FROM abnormal_domain_all where IP like ?", "%"+addr+"%")
	if err != nil {
		log.Errorf("lookup addr error: %v#", err)
	}
	var blacklist []string
	for rows.Next() {
		var domain string
		err = rows.Scan(&domain)
		if err != nil {
			log.Errorf("lookup addr error: %v#", err)
		}
		blacklist = append(blacklist, domain)
	}
	//log.Infof("a", string((len(blacklist))))
	return removeDuplicationDomain(blacklist)
}

// lookupStaticHost looks up the IP addresses for the given host from the blacklists file.
func (d *NewWarnlistDB) lookupStaticHost(host string, qtype uint16) []net.IP {
	if d.Len() == 0 {
		return nil
	}

	rows, err := d.db.Query("SELECT redirectIP FROM abnormal_domain_all where abnormal_domain=? and qtype = ?", host, qtype)
	if err != nil {
		log.Errorf("lookup host error: %v#", err)
	}
	var IPs []net.IP
	for rows.Next() {
		var redirectIP string
		err = rows.Scan(&redirectIP)
		if err != nil {
			log.Errorf("lookup host error: %v#", err)
		}
		IPs = append(IPs, parseIP(redirectIP))
	}
	return removeDuplicationIP(IPs)
}

func (d *NewWarnlistDB) LookupStaticHostV4(host string) []net.IP {
	host = strings.ToLower(host)
	ip := d.lookupStaticHost(host, dns.TypeA)
	return ip
}

// LookupStaticHostV6 looks up the IPv6 addresses for the given host from the blacklists file.
func (d *NewWarnlistDB) LookupStaticHostV6(host string) []net.IP {
	host = strings.ToLower(host)
	ip := d.lookupStaticHost(host, dns.TypeAAAA)
	return ip
}

type GoMapWarnlist struct {
	warnlist *Map
}

func (m *GoMapWarnlist) Add(rr string) {
	items := strings.Split(rr, " ")
	var domain string
	var addr net.IP
	var targetIP net.IP
	var targetDomain string

	if len(items) == 1 {
		domain = items[0]
		targetIP = parseIP(redirectIP)
	} else if len(items) == 2 {
		domain = items[1]
		targetIP = parseIP(items[0])
		if targetIP == nil {
			targetIP = parseIP(redirectIP)
		}
	} else {
		domain = items[1]
		addr = parseIP(items[0])
		targetIP = parseIP(items[2])
		targetDomain = items[3]
	}

	if addr.To4() != nil {
		m.warnlist.name4[domain] = append(m.warnlist.name4[domain], targetIP)
	} else {
		m.warnlist.name6[domain] = append(m.warnlist.name4[domain], targetIP)
	}
	if addr != nil {
		m.warnlist.addr[addr.String()] = append(m.warnlist.addr[addr.String()], targetDomain)
	}
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
	return removeDuplicationDomain(blacklists1)
}

// lookupStaticHost looks up the IP addresses for the given host from the blacklists file.
func (m *GoMapWarnlist) lookupStaticHost(host string, qtype uint16) []net.IP {
	if qtype == dns.TypeA && len(m.warnlist.name4) == 0 {
		return nil
	}
	if qtype == dns.TypeAAAA && len(m.warnlist.name4) == 0 {
		return nil
	}

	var ips []net.IP
	if qtype == dns.TypeA {
		ips = m.warnlist.name4[host]
	} else {
		ips = m.warnlist.name6[host]
	}
	ipsCp := make([]net.IP, len(ips))
	copy(ipsCp, ips)
	return ipsCp
}

func (m *GoMapWarnlist) LookupStaticHostV4(host string) []net.IP {
	host = strings.ToLower(host)
	ip := m.lookupStaticHost(host, dns.TypeA)
	return ip
}

// LookupStaticHostV6 looks up the IPv6 addresses for the given host from the blacklists file.
func (m *GoMapWarnlist) LookupStaticHostV6(host string) []net.IP {
	host = strings.ToLower(host)
	ip := m.lookupStaticHost(host, dns.TypeAAAA)
	return ip
}

func buildCacheFromFile(options PluginOptions) (Warnlist, error) {
	// Print a log message with the time it took to build the cache
	defer logTime("Building warnlist cache took %s", time.Now())

	var warnlist Warnlist
	{
		warnlist = NewWarnlist()
		//if options.MatchSubdomains {
		//warnlist = NewRadixWarnlist()
		//} else {
		//	warnlist = NewWarnlist()
		//}
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

func buildDBFromFile(options PluginOptions) (Warnlist, error) {
	// Print a log message with the time it took to build the cache
	defer logTime("Building warnlist file took %s", time.Now())

	var warnlist Warnlist
	{
		warnlist = NewWarnlistFile()
	}

	for domain := range domainsFromSource(options.DomainSource, options.DomainSourceType, options.FileFormat) {
		warnlist.Add(domain)
	}

	count := warnlist.Len()
	log.Infof("added %d domains to warnlist", count)

	return warnlist, nil
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
	var warnlist Warnlist
	var err error
	if wp.Options.StorageType == DomainStorageTypeMemory {
		warnlist, err = buildCacheFromFile(wp.Options)
	} else if wp.Options.StorageType == DomainStorageTypeFileDB {
		warnlist, err = buildDBFromFile(wp.Options)
	}
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

func removeDuplicationDomain(arr []string) []string {
	set := make(map[string]struct{}, len(arr))
	j := 0
	for _, v := range arr {
		_, ok := set[v]
		if ok {
			continue
		}
		set[v] = struct{}{}
		arr[j] = v
		j++
	}

	return arr[:j]
}

func removeDuplicationIP(arr []net.IP) []net.IP {
	set := make(map[string]struct{}, len(arr))
	j := 0
	for _, v := range arr {
		_, ok := set[v.String()]
		if ok {
			continue
		}
		set[v.String()] = struct{}{}
		arr[j] = v
		j++
	}

	return arr[:j]
}
