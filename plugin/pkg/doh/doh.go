package doh

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"strconv"
	"strings"

	"github.com/miekg/dns"
)

// MimeType is the DoH mimetype that should be used.
const MimeType = "application/dns-message"
const JsonType = "application/dns-json"

// Path is the URL path that should be used.
const Path = "/dns-query"

// NewRequest returns a new DoH request given a method, URL (without any paths, so exclude /dns-query) and dns.Msg.
func NewRequest(method, url string, m *dns.Msg) (*http.Request, error) {
	buf, err := m.Pack()
	if err != nil {
		return nil, err
	}

	switch method {
	case http.MethodGet:
		b64 := base64.RawURLEncoding.EncodeToString(buf)

		req, err := http.NewRequest(http.MethodGet, "https://"+url+Path+"?dns="+b64, nil)
		if err != nil {
			return req, err
		}

		req.Header.Set("content-type", MimeType)
		req.Header.Set("accept", MimeType)
		return req, nil

	case http.MethodPost:
		req, err := http.NewRequest(http.MethodPost, "https://"+url+Path+"?bla=foo:443", bytes.NewReader(buf))
		if err != nil {
			return req, err
		}

		req.Header.Set("content-type", MimeType)
		req.Header.Set("accept", MimeType)
		return req, nil

	default:
		return nil, fmt.Errorf("method not allowed: %s", method)
	}

}

// ResponseToMsg converts a http.Response to a dns message.
func ResponseToMsg(resp *http.Response) (*dns.Msg, error) {
	defer resp.Body.Close()

	return toMsg(resp.Body)
}

// RequestToMsg converts a http.Request to a dns message.
func RequestToMsg(req *http.Request) (*dns.Msg, error) {
	switch req.Method {
	case http.MethodGet:
		return requestToMsgGet(req)

	case http.MethodPost:
		return requestToMsgPost(req)

	default:
		return nil, fmt.Errorf("method not allowed: %s", req.Method)
	}

}

// requestToMsgPost extracts the dns message from the request body.
func requestToMsgPost(req *http.Request) (*dns.Msg, error) {
	defer req.Body.Close()
	return toMsg(req.Body)
}

// requestToMsgGet extract the dns message from the GET request.
func requestToMsgGet(req *http.Request) (*dns.Msg, error) {
	if IsJsonRequest(req) {
		values := req.URL.Query()
		name, ok := values["name"]
		if !ok {
			return nil, fmt.Errorf("no 'name' query parameter found")
		}
		types, ok := values["type"]
		if !ok {
			return nil, fmt.Errorf("no 'type' query parameter found")
		}
		if len(types) > 1 {

		}
		rType := strings.ToUpper(types[0])
		var qType uint16
		if result, err := strconv.Atoi(rType); err == nil {
			qType = uint16(result)
		} else {
			qType = dns.StringToType[rType]
		}
		m := new(dns.Msg)
		m.Opcode = dns.OpcodeQuery
		m.Question = append(m.Question, dns.Question{Name: name[0] + ".", Qtype: qType, Qclass: dns.ClassINET})

		msg, err := m.Pack()
		if err != nil {
		}
		return base64ToMsg(base64.RawURLEncoding.EncodeToString(msg))
	} else {
		values := req.URL.Query()
		b64, ok := values["dns"]
		if !ok {
			return nil, fmt.Errorf("no 'dns' query parameter found")
		}
		if len(b64) != 1 {
			return nil, fmt.Errorf("multiple 'dns' query values found")
		}
		return base64ToMsg(b64[0])
	}

}

func toMsg(r io.ReadCloser) (*dns.Msg, error) {
	buf, err := ioutil.ReadAll(r)
	if err != nil {
		return nil, err
	}
	m := new(dns.Msg)
	err = m.Unpack(buf)
	return m, err
}

func base64ToMsg(b64 string) (*dns.Msg, error) {
	buf, err := b64Enc.DecodeString(b64)
	if err != nil {
		return nil, err
	}

	m := new(dns.Msg)
	err = m.Unpack(buf)

	return m, err
}

var b64Enc = base64.RawURLEncoding

type Question struct {
	Name string `json:"name"`
	Type uint16 `json:"type"`
}

type Answer struct {
	Name string `json:"name"`
	Type uint16 `json:"type"`
	TTL  uint32 `json:"TTL"`
	Data string `json:"data"`
}

type Response struct {
	Status   int        `json:"Status"`
	TC       bool       `json:"TC"`
	RD       bool       `json:"RD"`
	RA       bool       `json:"RA"`
	AD       bool       `json:"AD"`
	CD       bool       `json:"CD"`
	Question []Question `json:"Question"`
	Answer   []Answer   `json:"Answer"`
}

func IsJsonRequest(req *http.Request) bool {
	acceptHeader := req.Header.Get("Accept")
	if acceptHeader == JsonType {
		return true
	}
	return false
}
