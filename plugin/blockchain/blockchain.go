// Package blockchain implements a plugin that returns information held in the Ethereum Name Service.
package blockchain

import (
	"context"
	"github.com/coredns/coredns/plugin"
	"github.com/coredns/coredns/request"
	"github.com/miekg/dns"
	"strings"
)

type Blockchain struct {
	Next              plugin.Handler
	FabricNameServers []string
	IPFSGatewayAs     []string
	IPFSGatewayAAAAs  []string
}

var domains = make(map[string][]dns.RR)

func init() {
	requestor := "requestor.data.heze."
	requestorCert := dns.CERT{
		Hdr: dns.RR_Header{
			Name:     requestor,
			Rrtype:   dns.TypeCERT,
			Class:    dns.ClassINET,
			Ttl:      108,
			Rdlength: 100,
		},
		Type:        1,
		KeyTag:      1,
		Algorithm:   1,
		Certificate: "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDVA2gkONVS5y3W6cnEaERuPsGNqD8kG14+sWjoquToTC7dlAIdNZzF3+a+Ak+bWaHZqF0f+3rVh/bD7uFO4riRyuRZVha09riDPFbsAb1S8//20v59dk+cfx0LskbUzne8U4dS0MCAA8TLhI/wnjJ0KAOeCAC8S1dFt0GwckOSlwIDAQAB",
	}
	requestorRRs := make([]dns.RR, 0)
	requestorRRs = append(requestorRRs, &requestorCert)
	domains[requestor] = requestorRRs

	dataProvider := "provider.data.heze."
	dataProviderCert := dns.CERT{
		Hdr: dns.RR_Header{
			Name:     requestor,
			Rrtype:   dns.TypeCERT,
			Class:    dns.ClassINET,
			Ttl:      108,
			Rdlength: 100,
		},
		Type:        1,
		KeyTag:      1,
		Algorithm:   1,
		Certificate: "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDVA2gkONVS5y3W6cnEaERuPsGNqD8kG14+sWjoquToTC7dlAIdNZzF3+a+Ak+bWaHZqF0f+3rVh/bD7uFO4riRyuRZVha09riDPFbsAb1S8//20v59dk+cfx0LskbUzne8U4dS0MCAA8TLhI/wnjJ0KAOeCAC8S1dFt0GwckOSlwIDAQAB",
	}
	dataProviderRRs := make([]dns.RR, 0)
	dataProviderRRs = append(dataProviderRRs, &dataProviderCert)
	domains[dataProvider] = dataProviderRRs

	dataService := "api.data.heze."
	dataServiceUri := dns.URI{
		Hdr: dns.RR_Header{
			Name:     dataService,
			Rrtype:   dns.TypeURI,
			Class:    dns.ClassINET,
			Ttl:      36,
			Rdlength: 100,
		},
		Priority: 1,
		Weight:   1,
		Target:   "http://192.168.10.252:5000/auth?&response_type=code&redirect_uri=http://192.168.10.252:9009/v/1&client_id=did.fuxi.city/jinzhongze@fxzk.org",
	}
	dataServiceRRs := make([]dns.RR, 0)
	dataServiceRRs = append(dataServiceRRs, &dataServiceUri)
	domains[dataService] = dataServiceRRs
}

// ServeDNS implements the plugin.Handler interface.
func (e Blockchain) ServeDNS(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) (int, error) {
	state := request.Request{W: w, Req: r}
	a := new(dns.Msg)
	a.SetReply(r)
	a.Compress = true
	a.Authoritative = true
	var result Result
	a.Answer, a.Ns, a.Extra, result = e.Lookup(state)
	switch result {
	case Success:
		state.SizeAndDo(a)
		w.WriteMsg(a)
		return dns.RcodeSuccess, nil
	case NoData:
		if e.Next == nil {
			state.SizeAndDo(a)
			w.WriteMsg(a)
			return dns.RcodeSuccess, nil
		}
		return plugin.NextOrFailure(e.Name(), e.Next, ctx, w, r)
	case NameError:
		a.Rcode = dns.RcodeNameError
	case ServerFailure:
		return dns.RcodeServerFailure, nil
	}
	// Unknown result...
	return dns.RcodeServerFailure, nil

}

// Name implements the Handler interface.
func (e Blockchain) Name() string { return "blockchain" }

func (e Blockchain) handleDomain(name string, domain string) ([]dns.RR, error) {
	return domains[name], nil
}

// Result of a lookup
type Result int

const (
	// Success is a successful lookup.
	Success Result = iota
	// NameError indicates a nameerror
	NameError
	// Delegation indicates the lookup resulted in a delegation.
	Delegation
	// NoData indicates the lookup resulted in a NODATA.
	NoData
	// ServerFailure indicates a server failure during the lookup.
	ServerFailure
)

// Lookup contains the logic required to move through A DNS hierarchy and
// gather the appropriate records
func (e Blockchain) Lookup(state request.Request) ([]dns.RR, []dns.RR, []dns.RR, Result) {
	answerRrs := make([]dns.RR, 0)
	authorityRrs := make([]dns.RR, 0)
	additionalRrs := make([]dns.RR, 0)

	// Work out the domain against which to query
	name := strings.ToLower(state.Name())
	if !strings.HasSuffix(name, ".") {
		name = name + "."
	}

	rrs, err := e.handleDomain(name, state.QName())
	if err != nil {
		return nil, nil, nil, ServerFailure
	}
	if len(rrs) == 0 {
		return nil, nil, nil, NoData
	}
	answerRrs = append(answerRrs, rrs...)
	if len(answerRrs) == 0 {
		return answerRrs, authorityRrs, additionalRrs, NoData
	}
	return answerRrs, authorityRrs, additionalRrs, Success
}
