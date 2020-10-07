package resolver

import (
	"github.com/coredns/coredns/plugin"
	"github.com/coredns/coredns/request"
)

func (re *resolver) match(state request.Request) bool {
	for _, f := range re.from {
		if plugin.Name(f).Matches(state.Name()) {
			return true
		}
	}

	if re.isAllowedDomain(state.Name()) {
		return true

	}

	return false
}

func (re *resolver) isAllowedDomain(name string) bool {
	for _, except := range re.except {
		if plugin.Name(except).Matches(name) {
			return false
		}
	}
	return true
}
