FROM golang:1.26.7 AS build

WORKDIR /src/coredns
ADD https://github.com/coredns/coredns.git\#v1.14.7 /src/coredns
COPY <<EOF /src/coredns/plugin.cfg
errors:errors
log:log
cache:cache
rewrite:rewrite
header:header
auto:auto
forward:forward
template:template
view:view
EOF
RUN go mod vendor
ENV CGO_ENABLED=0
ENV GOFLAGS="-buildvcs=false '-gcflags=all=-N -l'"
RUN make LDFLAGS= gen && make LDFLAGS=

WORKDIR /src/dlv
ENV GOFLAGS=
ENV GOBIN=/src/dlv
RUN go install github.com/go-delve/delve/cmd/dlv@latest

FROM gcr.io/distroless/static-debian12
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=build /src/coredns/coredns /bin/coredns
COPY --from=build /src/dlv/dlv /bin/dlv
USER root
WORKDIR /etc/coredns
EXPOSE 53 53/udp
ENTRYPOINT ["/bin/dlv", "--listen=:8080", "--headless=true", "--api-version=2", "--accept-multiclient", "exec", "/bin/coredns"]

# VSCode Debug Configuration
#
# {
#     "version": "0.2.0",
#     "configurations": [
#         {
#             "name": "Attach to CoreDNS",
#             "type": "go",
#             "request": "attach",
#             "mode": "remote",
#             "port": 8080,
#             "host": "2001:db8::53",
#             "substitutePath": [
#                 {
#                     "from": "${workspaceFolder}",
#                     "to": "/src/coredns"
#                 }
#             ]
#         },
#     ]
# }
