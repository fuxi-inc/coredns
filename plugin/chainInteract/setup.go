package chainInteract

import (
	"github.com/coredns/coredns/core/dnsserver"
	"github.com/coredns/coredns/plugin"

	"github.com/caddyserver/caddy"
)

// init registers this plugin.
func init() { plugin.Register("chainInteract", setup) }

// setup is the function that gets called when the config parser see the token "chainInteract". Setup is responsible
// for parsing any extra options this plugin may have.
func setup(c *caddy.Controller) error {
	c.Next() // Ignore "chainInteract" and give us the next token.
	if c.NextArg() {
		// If there was another token, return an error, because we don't have any configuration.
		// Any errors returned from this setup function should be wrapped with plugin.Error, so we
		// can present a slightly nicer error message to the user.
		return plugin.Error("chainInteract", c.ArgErr())
	}

	// Add the Plugin to CoreDNS, so Servers can use it in their plugin chain.
	dnsserver.GetConfig(c).AddPlugin(func(next plugin.Handler) plugin.Handler {
		return chainInteract{Next: next}
	})

	// All OK, return a nil error.
	return nil
}
