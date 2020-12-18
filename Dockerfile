FROM debian:stable-slim

RUN apt-get update && apt-get -uy upgrade
RUN apt-get -y install ca-certificates && update-ca-certificates

FROM scratch

COPY --from=0 /etc/ssl/certs /etc/ssl/certs

ADD coredns /coredns/coredns
COPY deployment/ /coredns/deployment

EXPOSE 1153
EXPOSE 1443
EXPOSE 1953
ENTRYPOINT ["/coredns/coredns"]
