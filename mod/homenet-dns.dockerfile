FROM golang:1.26.7 AS build
WORKDIR /src
ADD https://github.com/coredns/coredns.git\#v1.14.7 /src
COPY <<EOF /src/plugin.cfg
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
ENV GOFLAGS="-buildvcs=false"
RUN make gen && make

FROM gcr.io/distroless/static-debian12
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=build /src/coredns /bin/coredns
USER root
WORKDIR /etc/coredns
EXPOSE 53 53/udp
ENTRYPOINT ["/bin/coredns"]
