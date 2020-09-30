package blockchain

import (
	"strings"

	"github.com/coredns/caddy"
	"github.com/coredns/coredns/core/dnsserver"
	"github.com/coredns/coredns/plugin"
)

func init() {
	plugin.Register("blockchain", setup)
}

func setup(c *caddy.Controller) error {
	_, fabricNameServers, ipfsGatewayAs, ipfsGatewayAAAAs, err := ensParse(c)
	if err != nil {
		return plugin.Error("blockchain", err)
	}

	dnsserver.GetConfig(c).AddPlugin(func(next plugin.Handler) plugin.Handler {
		return Blockchain{
			Next:              next,
			FabricNameServers: fabricNameServers,
			IPFSGatewayAs:     ipfsGatewayAs,
			IPFSGatewayAAAAs:  ipfsGatewayAAAAs,
		}
	})

	return nil
}

func ensParse(c *caddy.Controller) (string, []string, []string, []string, error) {
	var connection string
	fabricNameServers := make([]string, 0)
	ipfsGatewayAs := make([]string, 0)
	ipfsGatewayAAAAs := make([]string, 0)

	c.Next()
	for c.NextBlock() {
		switch strings.ToLower(c.Val()) {
		case "connection":
			args := c.RemainingArgs()
			if len(args) == 0 {
				return "", nil, nil, nil, c.Errf("invalid connection; no value")
			}
			if len(args) > 1 {
				return "", nil, nil, nil, c.Errf("invalid connection; multiple values")
			}
			connection = args[0]
		case "fabricnameservers":
			args := c.RemainingArgs()
			if len(args) == 0 {
				return "", nil, nil, nil, c.Errf("invalid fabricNameServers; no value")
			}
			fabricNameServers = make([]string, len(args))
			copy(fabricNameServers, args)
		case "ipfsgatewaya":
			args := c.RemainingArgs()
			if len(args) == 0 {
				return "", nil, nil, nil, c.Errf("invalid IPFS gateway A; no value")
			}
			ipfsGatewayAs = make([]string, len(args))
			copy(ipfsGatewayAs, args)
		case "ipfsgatewayaaaa":
			args := c.RemainingArgs()
			if len(args) == 0 {
				return "", nil, nil, nil, c.Errf("invalid IPFS gateway AAAA; no value")
			}
			ipfsGatewayAAAAs = make([]string, len(args))
			copy(ipfsGatewayAAAAs, args)
		default:
			return "", nil, nil, nil, c.Errf("unknown value %v", c.Val())
		}
	}
	if connection == "" {
		return "", nil, nil, nil, c.Errf("no connection")
	}
	if len(fabricNameServers) == 0 {
		return "", nil, nil, nil, c.Errf("no fabricNameServers")
	}
	for i := range fabricNameServers {
		if !strings.HasSuffix(fabricNameServers[i], ".") {
			fabricNameServers[i] = fabricNameServers[i] + "."
		}
	}
	return connection, fabricNameServers, ipfsGatewayAs, ipfsGatewayAAAAs, nil
}
