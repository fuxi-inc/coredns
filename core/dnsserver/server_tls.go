package dnsserver

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"time"

	"github.com/coredns/caddy"
	"github.com/coredns/coredns/plugin/pkg/dnstest"
	"github.com/coredns/coredns/plugin/pkg/reuseport"
	"github.com/coredns/coredns/plugin/pkg/transport"
	"github.com/coredns/coredns/request"

	"github.com/miekg/dns"
)

// ServerTLS represents an instance of a TLS-over-DNS-server.
type ServerTLS struct {
	*Server
	tlsConfig *tls.Config
}

// NewServerTLS returns a new CoreDNS TLS server and compiles all plugin in to it.
func NewServerTLS(addr string, group []*Config) (*ServerTLS, error) {
	s, err := NewServer(addr, group)
	if err != nil {
		return nil, err
	}
	// The *tls* plugin must make sure that multiple conflicting
	// TLS configuration returns an error: it can only be specified once.
	var tlsConfig *tls.Config
	for _, conf := range s.zones {
		// Should we error if some configs *don't* have TLS?
		tlsConfig = conf.TLSConfig
	}

	return &ServerTLS{Server: s, tlsConfig: tlsConfig}, nil
}

// Compile-time check to ensure Server implements the caddy.GracefulServer interface
var _ caddy.GracefulServer = &Server{}

// Serve implements caddy.TCPServer interface.
func (s *ServerTLS) Serve(l net.Listener) error {
	s.m.Lock()

	if s.tlsConfig != nil {
		l = tls.NewListener(l, s.tlsConfig)
	}

	// Only fill out the TCP server for this one.
	s.server[tcp] = &dns.Server{Listener: l, Net: "tcp-tls", Handler: dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		ctx := context.WithValue(context.Background(), Key{}, s.Server)
		s.ServeDNS(ctx, w, r)
		DoTLog(w, r)
	})}
	s.m.Unlock()

	return s.server[tcp].ActivateAndServe()
}

// ServePacket implements caddy.UDPServer interface.
func (s *ServerTLS) ServePacket(p net.PacketConn) error { return nil }

// Listen implements caddy.TCPServer interface.
func (s *ServerTLS) Listen() (net.Listener, error) {
	l, err := reuseport.Listen("tcp", s.Addr[len(transport.TLS+"://"):])
	if err != nil {
		return nil, err
	}
	return l, nil
}

// ListenPacket implements caddy.UDPServer interface.
func (s *ServerTLS) ListenPacket() (net.PacketConn, error) { return nil, nil }

// OnStartupComplete lists the sites served by this server
// and any relevant information, assuming Quiet is false.
func (s *ServerTLS) OnStartupComplete() {
	if Quiet {
		return
	}

	out := startUpZones(transport.TLS+"://", s.Addr, s.zones)
	if out != "" {
		fmt.Print(out)
	}
}

// DoT Log handler with its items and format.
func DoTLog(w dns.ResponseWriter, msg *dns.Msg) {
	state := request.Request{W: w, Req: msg}
	rrw := dnstest.NewRecorder(w)
	//format := `{remote}:{port} ` + replacer.EmptyValue + ` {>id} "{type} {class} {name} {proto} {size} {>do} {>bufsize}" {rcode} {>rflags} {rsize} {duration}`
	timestamp := strconv.FormatInt(time.Now().UnixNano()/1e6, 10)
	replace := make(map[string]string)
	replace["{remote}:{port}"] = state.RemoteAddr()
	replace["emptyValue"] = "-"
	replace["id"] = strconv.FormatInt(int64(state.Req.Id), 10)
	replace["type"] = state.Type()
	replace["class"] = state.Class()
	replace["name"] = state.Name()
	replace["proto"] = state.Proto()
	replace["size"] = strconv.FormatInt(int64(state.Req.Len()), 10)
	replace["do"] = strconv.FormatBool(state.Do())
	replace["bufsize"] = strconv.FormatInt(int64(state.Size()), 10)
	if rrw == nil {
		replace["rcode"] = "-"
	} else if rcode := dns.RcodeToString[rrw.Rcode]; rcode != "" {
		replace["rcode"] = rcode
	} else {
		replace["rcode"] = strconv.FormatInt(int64(rrw.Rcode), 10)
	}
	replace["rflags"] = "-"
	if w == nil {
		replace["rsize"] = "-"
	} else {
		replace["rsize"] = strconv.FormatInt(int64(rrw.Len), 10)
	}
	if rrw == nil {
		replace["duration"] = "-"
	} else {
		secs := time.Since(rrw.Start).Seconds()
		replace["duration"] = strconv.FormatFloat(secs, 'f', -1, 64) + "s"
	}
	//format := `{remote}:{port} ` + replacer.EmptyValue + ` {>id} "{type} {class} {name} {proto} {size} {>do} {>bufsize}" {rcode} {>rflags} {rsize} {duration}`
	logstr := "[INFO] " + timestamp + " " + replace["{remote}:{port}"] + " " + replace["emptyValue"] + " " + replace["id"] + " \"" + replace["type"] + " " + replace["class"] + " " + replace["name"] + " " + replace["proto"] + " " + replace["size"] + " " + replace["do"] + " " + replace["bufsize"] + "\" " + replace["rcode"] + " " + replace["rflags"] + " " + replace["rsize"] + " " + replace["duration"]
	WriteDoTLog(logstr)
}

// Write log in DoT log file.
func WriteDoTLog(LogItem string) error {
	filePath := "/home/fuxi/coredns/"
	fileName := "coredns_dot.log"
	lineFeed := "\r\n"
	f, err := os.OpenFile(filePath+fileName, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
	if err != nil {
		fmt.Println("DoT log file create failed. err: " + err.Error())
		return err
	} else {
		_, err := io.WriteString(f, LogItem+lineFeed)
		if err != nil {
			fmt.Println("DoT log writing failed. err: " + err.Error())
			return err
		}
	}
	defer f.Close()
	return nil
}
