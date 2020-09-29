## Install cert
### Install mkcert tool
brew install mkcert

### Create new local CA
mkcert -install

### Create new certificate
mkcert dns.heze "*.heze" localhost 127.0.0.1 ::1

## Appendix

Please refer to "https://github.com/FiloSottile/mkcert" to fetch more details.

