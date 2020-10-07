package resolver

import (
	"context"
	"fmt"
	"github.com/coredns/coredns/plugin"
	"github.com/coredns/coredns/plugin/metrics"
	clog "github.com/coredns/coredns/plugin/pkg/log"
	"github.com/coredns/coredns/request"
	"strconv"

	"github.com/miekg/dns"
	"github.com/miekg/unbound"
)

var log = clog.NewWithPlugin("unbound")

// Unbound is a plugin that resolves requests using libunbound.
type resolver struct {
	u *unbound.Unbound
	t *unbound.Unbound

	from   []string
	except []string

	Next plugin.Handler
}

// options for unbound, see unbound.conf(5).
var options = map[string]string{
	"msg-cache-size":   "0",
	"rrset-cache-size": "0",
}

// New returns a pointer to an initialzed Unbound.
func New() *resolver {
	udp := unbound.New()
	tcp := unbound.New()
	tcp.SetOption("tcp-upstream:", "yes")

	u := &resolver{u: udp, t: tcp}

	for k, v := range options {
		if err := u.setOption(k, v); err != nil {
			log.Warningf("Could not set option: %s", err)
		}
	}

	return u
}

// Stop stops unbound and cleans up the memory used.
func (re *resolver) Stop() error {
	re.u.Destroy()
	re.t.Destroy()
	return nil
}

// setOption sets option k to value v in u.
func (re *resolver) setOption(k, v string) error {
	// Add ":" as unbound expects it
	k += ":"
	// Set for both udp and tcp handlers, return the error from the latter.
	re.u.SetOption(k, v)
	err := re.t.SetOption(k, v)
	if err != nil {
		return fmt.Errorf("failed to set option %q with value %q: %s", k, v, err)
	}
	return nil
}

// config reads the file f and sets unbound configuration
func (re *resolver) config(f string) error {
	var err error

	err = re.u.Config(f)
	if err != nil {
		return fmt.Errorf("failed to read config file (%s) UDP context: %s", f, err)
	}

	err = re.t.Config(f)
	if err != nil {
		return fmt.Errorf("failed to read config file (%s) TCP context: %s", f, err)
	}
	return nil
}

// ServeDNS implements the plugin.Handler interface.
func (re *resolver) ServeDNS(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) (int, error) {
	state := request.Request{W: w, Req: r}

	if !re.match(state) {
		return plugin.NextOrFailure(re.Name(), re.Next, ctx, w, r)
	}

	var (
		res *unbound.Result
		err error
	)
	switch state.Proto() {
	case "tcp":
		res, err = re.t.Resolve(state.QName(), state.QType(), state.QClass())
	case "udp":
		res, err = re.u.Resolve(state.QName(), state.QType(), state.QClass())
	}

	rcode := dns.RcodeServerFailure
	if err == nil {
		rcode = res.AnswerPacket.Rcode
	}
	rc, ok := dns.RcodeToString[rcode]
	if !ok {
		rc = strconv.Itoa(rcode)
	}
	log.Info("rcode:", rc)

	//maybe other types
	var isChain int = 0
	if rcode == dns.RcodeServerFailure {
		res, err = re.getFromChain(r)
		isChain = 1
		log.Info("get from chain")
	}

	server := metrics.WithServer(ctx)
	RcodeCount.WithLabelValues(server, rc).Add(1)
	RequestDuration.WithLabelValues(server).Observe(res.Rtt.Seconds())

	if err != nil {
		return dns.RcodeServerFailure, err
	}

	// If the client *didn't* set the opt record, and specifically not the DO bit,
	// strip this from the reply (unbound default to setting DO).
	if !state.Do() {
		// technically we can still set bufsize and fluff, for now remove the entire OPT record.
		for i := 0; i < len(res.AnswerPacket.Extra); i++ {
			rr := res.AnswerPacket.Extra[i]
			if _, ok := rr.(*dns.OPT); ok {
				res.AnswerPacket.Extra = append(res.AnswerPacket.Extra[:i], res.AnswerPacket.Extra[i+1:]...)
				break // TODO(miek): more than one? Think TSIG?
			}
		}
		filter(res.AnswerPacket, dnssec)
	}

	res.AnswerPacket.Id = r.Id
	w.WriteMsg(res.AnswerPacket)

	if isChain == 0 {
		re.saveIntoChain(res.AnswerPacket)
	}

	return 0, nil
}

// Name implements the Handler interface.
func (re *resolver) Name() string { return "resolver" }

// getFromChain works when authoritative servers fail
func (re *resolver) getFromChain(r *dns.Msg) (*unbound.Result, error) {

	/*
		//call api to lookup on chain, return the answer and error type
		res,err = chain.get(r)
		//transfer the answer to dns.Msg format
	*/
	return nil, nil
}

// saveIntoChain
func (re *resolver) saveIntoChain(res *dns.Msg) error {
	/*
		//save the response from authoritative servers from
			chain.save(res)
	*/
	log.Info("save into chain:", res.Answer)
	return nil
}
