package warnlist

import (
	"context"
	"github.com/coredns/coredns/plugin/pkg/dnstest"
	"github.com/coredns/coredns/plugin/pkg/replacer"
	"io"
	"net"
	"os"
	"strconv"
	"time"

	"github.com/coredns/coredns/request"

	"github.com/coredns/coredns/plugin"
	"github.com/coredns/coredns/plugin/metrics"
	clog "github.com/coredns/coredns/plugin/pkg/log"

	"github.com/miekg/dns"
)

// Define log to be a logger with the plugin name in it. This way we can just use log.Info and
// friends to log.
var log = clog.NewWithPlugin("warnlist")

// WarnlistPlugin is a plugin which counts requests to warnlisted domains
type WarnlistPlugin struct {
	Next           plugin.Handler
	warnlist       Warnlist
	lastReloadTime time.Time
	Options        PluginOptions
	serverName     string
	quit           chan bool
}

// ServeDNS implements the plugin.Handler interface. This method gets called when warnlist is used
// in a Server.
func (wp *WarnlistPlugin) ServeDNS(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) (int, error) {
	req := request.Request{W: w, Req: r}
	qname := req.Name()
	qtype := req.QType()
	answers := []dns.RR{}

	//log.Infof("qname:", qname)
	//log.Infof("qtype:", qtype)

	// Update the server name from context if it has changed
	if metrics.WithServer(ctx) != wp.serverName {
		wp.serverName = metrics.WithServer(ctx)
	}

	if wp.warnlist != nil {
		// See if the requested domain is in the cache
		retrievalStart := time.Now()

		hit := false

		switch qtype {
		case dns.TypePTR:
			//log.Infof(qname)
			//log.Infof(dnsutil.ExtractAddressFromReverse(qname))
			names := wp.warnlist.LookupStaticAddr(qname[:len(qname)-1])
			if len(names) == 0 {
				// If this doesn't match we need to fall through regardless of b.Fallthrough
				return plugin.NextOrFailure(wp.Name(), wp.Next, ctx, w, r)
			}
			hit = true
			answers = ptr(qname, 3600, names)
		case dns.TypeA:
			ips := wp.warnlist.LookupStaticHostV4(qname)
			if len(ips) == 0 {
				// If this doesn't match we need to fall through regardless of b.Fallthrough
				return plugin.NextOrFailure(wp.Name(), wp.Next, ctx, w, r)
			}
			hit = true
			answers = a(qname, 3600, ips)
		case dns.TypeAAAA:
			ips := wp.warnlist.LookupStaticHostV6(qname)
			if len(ips) == 0 {
				// If this doesn't match we need to fall through regardless of b.Fallthrough
				return plugin.NextOrFailure(wp.Name(), wp.Next, ctx, w, r)
			}
			hit = true
			answers = aaaa(qname, 3600, ips)
		}

		// Record the duration for the query
		warnlistCheckDuration.WithLabelValues(metrics.WithServer(ctx)).Observe(time.Since(retrievalStart).Seconds())
		// Update the current warnlist size metric
		warnlistSize.WithLabelValues(metrics.WithServer(ctx)).Set(float64(wp.warnlist.Len()))

		if hit {
			// Warn and increment the counter for the hit
			warnlistCount.WithLabelValues(metrics.WithServer(ctx), req.IP(), req.Name()).Inc()

			m := new(dns.Msg)
			m.SetReply(r)
			m.Authoritative = true
			m.Answer = answers
			w.WriteMsg(m)

			//rrw := dnstest.NewRecorder(w)
			// If we don't set up a class in config, the default "all" will be added
			// and we shouldn't have an empty rule.Class.
			var repl replacer.Replacer
			state := request.Request{W: w, Req: r}
			rrw := dnstest.NewRecorder(w)
			format := `{remote}:{port} ` + replacer.EmptyValue + ` {>id} "{type} {class} {name} {proto} {size} {>do} {>bufsize}" {rcode} {>rflags} {rsize} {duration}`
			timestamp := strconv.FormatInt(time.Now().UnixNano()/1e6, 10)
			logstr := timestamp + " " + repl.Replace(ctx, state, rrw, format)

			log.Infof("%s ", logstr)

			return dns.RcodeSuccess, nil
		}

	} else {
		log.Debug("no warnlist has been loaded")
		// Update the current warnlist size metric to 0
		warnlistSize.WithLabelValues(metrics.WithServer(ctx)).Set(float64(0))
	}

	// Wrap the response when it returns from the next plugin
	pw := NewResponsePrinter(w)

	// Call next plugin (if any).
	return plugin.NextOrFailure(wp.Name(), wp.Next, ctx, pw, r)
}

// Name implements the Handler interface.
func (wp WarnlistPlugin) Name() string { return "warnlist" }

// ResponsePrinter wraps a dns.ResponseWriter and will let the plugin inspect the response.
type ResponsePrinter struct {
	dns.ResponseWriter
}

// NewResponsePrinter returns ResponseWriter.
func NewResponsePrinter(w dns.ResponseWriter) *ResponsePrinter {
	return &ResponsePrinter{ResponseWriter: w}
}

// WriteMsg calls the underlying ResponseWriter's WriteMsg method and handles our future response logic.
func (r *ResponsePrinter) WriteMsg(res *dns.Msg) error {
	return r.ResponseWriter.WriteMsg(res)
}

// Make out a reference to os.Stdout so we can easily overwrite it for testing.
var out io.Writer = os.Stdout // nolint: unused

// a takes a slice of net.IPs and returns a slice of A RRs.
func a(zone string, ttl uint32, ips []net.IP) []dns.RR {
	answers := make([]dns.RR, len(ips))
	for i, ip := range ips {
		r := new(dns.A)
		r.Hdr = dns.RR_Header{Name: zone, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: ttl}
		r.A = ip
		answers[i] = r
	}
	return answers
}

// aaaa takes a slice of net.IPs and returns a slice of AAAA RRs.
func aaaa(zone string, ttl uint32, ips []net.IP) []dns.RR {
	answers := make([]dns.RR, len(ips))
	for i, ip := range ips {
		r := new(dns.AAAA)
		r.Hdr = dns.RR_Header{Name: zone, Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: ttl}
		r.AAAA = ip
		answers[i] = r
	}
	return answers
}

// ptr takes a slice of host names and filters out the ones that aren't in Origins, if specified, and returns a slice of PTR RRs.
func ptr(zone string, ttl uint32, names []string) []dns.RR {
	answers := make([]dns.RR, len(names))
	for i, n := range names {
		r := new(dns.PTR)
		r.Hdr = dns.RR_Header{Name: zone, Rrtype: dns.TypePTR, Class: dns.ClassINET, Ttl: ttl}
		r.Ptr = dns.Fqdn(n)
		answers[i] = r
	}
	return answers
}
