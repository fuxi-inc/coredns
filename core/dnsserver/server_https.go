package dnsserver

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/miekg/dns"

	"github.com/coredns/caddy"
	"github.com/coredns/coredns/plugin/pkg/dnsutil"
	"github.com/coredns/coredns/plugin/pkg/doh"
	"github.com/coredns/coredns/plugin/pkg/response"
	"github.com/coredns/coredns/plugin/pkg/reuseport"
	"github.com/coredns/coredns/plugin/pkg/transport"

	"github.com/coredns/coredns/plugin/pkg/dnstest"
	"github.com/coredns/coredns/request"
)

// ServerHTTPS represents an instance of a DNS-over-HTTPS server.
type ServerHTTPS struct {
	*Server
	httpsServer *http.Server
	listenAddr  net.Addr
	tlsConfig   *tls.Config
}

// NewServerHTTPS returns a new CoreDNS GRPC server and compiles all plugins in to it.
func NewServerHTTPS(addr string, group []*Config) (*ServerHTTPS, error) {
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

	srv := &http.Server{
		ReadTimeout:  120 * time.Second,
		WriteTimeout: 120 * time.Second,
		IdleTimeout:  120 * time.Second,
	}
	sh := &ServerHTTPS{Server: s, tlsConfig: tlsConfig, httpsServer: srv}
	sh.httpsServer.Handler = sh

	return sh, nil
}

// Compile-time check to ensure Server implements the caddy.GracefulServer interface
var _ caddy.GracefulServer = &Server{}

// Serve implements caddy.TCPServer interface.
func (s *ServerHTTPS) Serve(l net.Listener) error {
	s.m.Lock()
	s.listenAddr = l.Addr()
	s.m.Unlock()

	if s.tlsConfig != nil {
		l = tls.NewListener(l, s.tlsConfig)
	}
	return s.httpsServer.Serve(l)
}

// ServePacket implements caddy.UDPServer interface.
func (s *ServerHTTPS) ServePacket(p net.PacketConn) error { return nil }

// Listen implements caddy.TCPServer interface.
func (s *ServerHTTPS) Listen() (net.Listener, error) {

	l, err := reuseport.Listen("tcp", s.Addr[len(transport.HTTPS+"://"):])
	if err != nil {
		return nil, err
	}
	return l, nil
}

// ListenPacket implements caddy.UDPServer interface.
func (s *ServerHTTPS) ListenPacket() (net.PacketConn, error) { return nil, nil }

// OnStartupComplete lists the sites served by this server
// and any relevant information, assuming Quiet is false.
func (s *ServerHTTPS) OnStartupComplete() {
	if Quiet {
		return
	}

	out := startUpZones(transport.HTTPS+"://", s.Addr, s.zones)
	if out != "" {
		fmt.Print(out)
	}
}

// Stop stops the server. It blocks until the server is totally stopped.
func (s *ServerHTTPS) Stop() error {
	s.m.Lock()
	defer s.m.Unlock()
	if s.httpsServer != nil {
		s.httpsServer.Shutdown(context.Background())
	}
	return nil
}

// ServeHTTP is the handler that gets the HTTP request and converts to the dns format, calls the plugin
// chain, converts it back and write it to the client.
func (s *ServerHTTPS) ServeHTTP(w http.ResponseWriter, r *http.Request) {

	if r.URL.Path != doh.DoHPath && r.URL.Path != doh.JsonPath {
		http.Error(w, "", http.StatusNotFound)
		return
	}

	msg, err := doh.RequestToMsg(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Create a DoHWriter with the correct addresses in it.
	h, p, _ := net.SplitHostPort(r.RemoteAddr)
	port, _ := strconv.Atoi(p)
	dw := &DoHWriter{laddr: s.listenAddr, raddr: &net.TCPAddr{IP: net.ParseIP(h), Port: port}}

	// We just call the normal chain handler - all error handling is done there.
	// We should expect a packet to be returned that we can send to the client.
	ctx := context.WithValue(context.Background(), Key{}, s.Server)
	s.ServeDNS(ctx, dw, msg)

	// See section 4.2.1 of RFC 8484.
	// We are using code 500 to indicate an unexpected situation when the chain
	// handler has not provided any response message.
	if dw.Msg == nil {
		http.Error(w, "No response", http.StatusInternalServerError)
		return
	}

	buf, _ := dw.Msg.Pack()

	mt, _ := response.Typify(dw.Msg, time.Now().UTC())
	age := dnsutil.MinimalTTL(dw.Msg, mt)

	if doh.IsJsonRequest(r) {
		resp := doh.Response{Status: dns.RcodeToString[dw.Msg.Rcode], TC: dw.Msg.Truncated, RD: dw.Msg.RecursionDesired, RA: dw.Msg.RecursionAvailable, AD: dw.Msg.AuthenticatedData, CD: dw.Msg.CheckingDisabled}

		for _, q := range dw.Msg.Question {
			resp.Question = append(resp.Question, doh.Question{Name: q.Name, Type: dns.TypeToString[q.Qtype]})
		}
		for _, rr := range dw.Msg.Answer {
			content := rr.String()
			header := rr.Header().String()
			data := strings.TrimPrefix(content, header)
			resp.Answer = append(resp.Answer, doh.RR{Name: rr.Header().Name, Type: dns.TypeToString[rr.Header().Rrtype], TTL: rr.Header().Ttl, Data: data})
		}

		for _, rr := range dw.Msg.Ns {
			content := rr.String()
			header := rr.Header().String()
			data := strings.TrimPrefix(content, header)
			resp.Authority = append(resp.Authority, doh.RR{Name: rr.Header().Name, Type: dns.TypeToString[rr.Header().Rrtype], TTL: rr.Header().Ttl, Data: data})
		}

		for _, rr := range dw.Msg.Extra {
			content := rr.String()
			header := rr.Header().String()
			data := strings.TrimPrefix(content, header)
			if rr.Header().Rrtype == dns.TypeOPT {
				opt := rr.(*dns.OPT)
				data, _ = doh.OPTtoString(opt)
				data = strings.Replace(data, "\"", "", -1)
			}
			resp.Additional = append(resp.Additional, doh.RR{Name: rr.Header().Name, Type: dns.TypeToString[rr.Header().Rrtype], TTL: rr.Header().Ttl, Data: data})
		}

		w.Header().Set("Content-Type", doh.JsonType)
		data, err := json.Marshal(resp)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
		} else {
			w.WriteHeader(http.StatusOK)
			w.Header().Set("Cache-Control", fmt.Sprintf("max-age=%f", age.Seconds()))
			w.Header().Set("Content-Length", strconv.Itoa(len(data)))
			w.Write(data)
		}
	} else {
		w.Header().Set("Content-Type", doh.MimeType)
		w.Header().Set("Cache-Control", fmt.Sprintf("max-age=%f", age.Seconds()))
		w.Header().Set("Content-Length", strconv.Itoa(len(buf)))
		w.WriteHeader(http.StatusOK)

		w.Write(buf)
	}

	DoHLog(dw, w, msg)
}

// Shutdown stops the server (non gracefully).
func (s *ServerHTTPS) Shutdown() error {
	if s.httpsServer != nil {
		s.httpsServer.Shutdown(context.Background())
	}
	return nil
}

// DoH Log handler with its items and format.
func DoHLog(dw *DoHWriter, w http.ResponseWriter, msg *dns.Msg) {
	state := request.Request{W: dw, Req: msg}
	rrw := dnstest.NewRecorder(dw)
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
	WriteDoHLog(logstr)
}

// Write log in DoH log file.
func WriteDoHLog(LogItem string) error {
	filePath := "/home/fuxi/coredns/"
	fileName := "coredns_doh.log"
	lineFeed := "\r\n"
	f, err := os.OpenFile(filePath+fileName, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
	if err != nil {
		fmt.Println("DoH log file create failed. err: " + err.Error())
		return err
	} else {
		_, err := io.WriteString(f, LogItem+lineFeed)
		if err != nil {
			fmt.Println("DoH log writing failed. err: " + err.Error())
			return err
		}
	}
	defer f.Close()
	return nil
}
