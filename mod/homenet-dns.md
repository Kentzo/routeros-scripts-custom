# Authoritative DNS Server on RouterOS with CoreDNS

- Prevent leaks of queries for domains in Locally-Served DNS zones
- Comprehensive *A/AAAA/PTR* resource records for hosts
- *PTR/SRV/TXT* resource records for Wide-Area DNS-Based Service Discovery

Introduction and discussion: https://gist.github.com/Kentzo/36dee5b82ba1b25bec0167a5e07c565f

For each item in "hosts" you provide a hostname and at least one IPv4 or IPv6 address that is used for the corresponding "A"
or "AAAA" resource record. Additional IP and MAC addresses are used to produce a comprehensive list of PTR records.
Router's local interfaces as well as ARP and ND tables are considered. Setting "ipARPStatusRegex", "ip6NeighborStatusRegex"
and "interfacesRegex" narrows the search.

For each item in "services" you provide instance name, service name, hostname and port as well as contents for the corresponding
TXT record(s) as needed. Values must follow encodings and constraints as specified in RFC 6763, speficially Sections 4 and 6.

The list of locally-served zones includes IANA assignments as well as "ipNetworksExtra", "ip6NetworksExtra" and "domainsExtra".
Queries for these domains (and subdomains) will be authoritatively answered by the nameserver. NXDOMAIN will be returned
for names that do exist.

Each zone is represented by two files: "db.*" with SOA and NS that $INCLUDEs "data.*" with the remaining resource records.
This separation allows the script to minimize disk writes.

When there is a change in zone files or CoreDNS configuration, the default is to restart the container. This behavior
can be changed by setting "useZeroDowntime" at the expense of more disk reads.

If RouterOS's DNS Resolver is set to allow remote requests, the script assumes that router's DNS server is used in the LAN.
DNS forwarders are added to redirect requests for delegated domains and networks to the CoreDNS instance. This behavior is
controlled by "useDNSForwarder".

Additional zones and resource records can be set verbatim via "zonesExtra". Additional CoreDNS configuration can be set via
"corefileExtra". You can completely override default Corefile with "corefileOverride" where the default server block configuration
can be referenced by `import homenet-dns-default`.

```rsc
:global HomenetDNSConfig ({
    # (str): Regex-escaped unique ID of the managed objects
    "managedID"="01234567-1337-dead-beef-0123456789ab";

    # (str): Name of the CoreDNS container
    "nsContainer"="...";

    # (str): Optional path to the CoreDNS working directory that will be mounted into the container; defaults to the container's first mount
    # "nsRoot"="";

    # (ip, str): Optional IPv4 address of the DNS server in zone files; defaults to the container's first IPv4 address
    # "nsIPAddress"=;

    #(ip, str): Optional IPv6 address of the DNS server in zone files; defaults to the container's first IPv6 address
    # "nsIP6Address"=;

    # (str): Optional default domain name for hosts and services; defaults to global-config's $Domain, if present, otherwise "home.arpa."
    # "domain"="home.arpa.";

    # (num): Optional TTL in seconds for DNS resource records; defaults to 3600
    # "ttl"=3600;

    # (array): Optional array of hosts for address resource records; defaults to empty
    #   - name: Hostname (and subdomain) relative to the "domain"
    #   - [domain]: Optional domain of the host; defaults to config's "domain"
    #   - addresses: An array of IPv4, IPv6 or MAC addresses
    # "hosts"={
    #     {"name"="gateway" ; "addresses"={192.0.2.1 ; 2001:db8::1}};
    # };

    # (array): Optional array of DNS-SD services (RFC 6763); defaults to empty
    #   - name: <Instance> of Service Instance Name, encoded and escaped, e.g. "Home\\ Media"
    #   - service: <Service> of Service Instance Name, e.g. "_smb._tcp"
    #   - [domain]: Optional <Domain> of Service Instance Name, e.g. "home.arpa."; defaults to config's "domain"
    #   - host: Hostname that provides service, e.g. "gateway" (relative to "domain") or "gateway.home.arpa." (absolute)
    #   - port: Port on the "host" where the service is available, e.g. "445"
    #   - [txt]: Optional TXT record(s) associated with the service instance
    #     - {str}: one TXT record with multiple values, e.g. {"path"="/usb1-part2/media" ; "u=guest"} -> TXT ("path=/usb1-part2/media" "u=guest")
    #     - {{str}}: Multiple TXT records where each follows the rule above
    # "services"={
    #     {"name"="Home\\ Media" ; "service"="_smb._tcp" ; "host"="gateway" ; "port"=445 ; txt={"path=/media" ; "u"="guest"}};
    # };

    # (bool): Optional flag to control whether /ip/dns/forwdarder for all configured zones is set up; defaults to `/ip/dns/get value-name=allow-remote-requests`
    # "useDNSForwarder"=yes;

    # (bool, num, time): Optional flag or refresh interval to control whether CoreDNS uses zero-downtime deployment; defaults to no
    #   - yes or >0 interval causes CoreDNS to re-read configuration and zones every so often; defaults to 60s
    #   - no or <=0 interval disables zero-downtime behavior; instead the container gets restarted on changes
    # "useZeroDowntime"=no;

    # (str): Optional regex to filter IPv4 ARP when resolving hosts; defaults to "(permanent|reachable|stale)"
    # "ipARPStatusRegex"="(permanent|reachable|stale)";

    # (str): Optional regex to filter IPv6 neighbors when resolving hosts; defaults to "(noarp|reachable|stale)"
    # "ip6NeighborStatusRegex"="(noarp|reachable|stale)";

    # (str): Optional regex to filter interfaces when resolving addresses of hosts and delegated networks; defaults to ".*"
    # "interfacesRegex"=".*";

    # (array): Optional array of additional IPv4 networks delegated to the router; defaults to advertised prefixes
    # "ipNetworksExtra"={};

    # (array): Optional array of additional IPv6 networks delegated to the router; defaults to delegated and advertised prefixes
    # "ip6NetworksExtra"={};

    # (array): Optional array of additional domains delegated to the router
    # "domainsExtra"={};

    # (array): Optional array of additional resource records
    #   - key: Zone domain name
    #   - value: An array of additional resource records to append to the zone file
    # "zonesExtra"={
    #     "home.arpa."={
    #         "samba CNAME gateway";
    #     }
    # };

    # (str): Optional additional CoreDNS configuration for the main server block, passed verbatim
    # "corefileExtra"="";

    # (str): Optional CoreDNS configuration override, passed verbatim; contents of the default main server block is available via the "homenet-dns-default" snippet
    # "corefileOverride"="";
})
 ```

 ## Affects:
   - /container
   - /file
   - /ip/dns/forwarders
   - /ip/dns/static

 ## Policy:
   - read,write,sensitive

 ## Requirements:
   - mod/ipv4-structured
   - mod/ipv6-structured
   - mod/kentzo-functions

 ## Caveats and Known Bugs:
   - RouterOS's (7.18.2) DNS Resolver rewrites NXDOMAIN responses from a forwarder as NODATA and removes the authority section
   - macOS (15.4) cannot discover services over unicast DNS when iCloud Private Relay is on
   - When using TLS in CoreDNS, make sure that the container image is built with up to date CA certificates

 ## Example:
*On the Host:*
```
$ docker build -t routeros_coredns:latest --platform linux/arm64 -f - . <<'END'
    FROM --platform=$BUILDPLATFORM golang:1.26.7 AS build
    WORKDIR /src
    ADD https://github.com/coredns/coredns.git\#v1.14.7 /src
    COPY <<EOF /src/plugin.cfg
    reload:reload
    errors:errors
    log:log
    cache:cache
    rewrite:rewrite
    auto:auto
    forward:forward
    template:template
    EOF
    RUN sh -c 'GOFLAGS="-buildvcs=false" make gen && GOFLAGS="-buildvcs=false" make'

    FROM --platform=$TARGETPLATFORM gcr.io/distroless/static-debian12
    COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
    COPY --from=build /src/coredns /bin/coredns
    USER root
    WORKDIR /etc/coredns
    EXPOSE 53 53/udp
    ENTRYPOINT ["/bin/coredns"]
    END
$ docker save routeros_coredns:latest | gzip > routeros_coredns.tar.gz
$ scp routeros_coredns.tar.gz <router-address>:/
```

*On the Router:*
```
> /interface/veth/add address=192.0.2.53/31,2001:db8:53::1/127 gateway=192.0.2.52 gateway6=2001:db8:53:: name=veth-coredns
> /ip/address/add address=192.0.2.52/31 interface=veth-coredns
> /ipv6/address/add address=2001:db8:53::/127 advertise=no interface=veth-coredns no-dad=yes
> /container/add file=routeros_coredns.tar.gz interface=veth-coredns root-dir=usb1-part2/coredns/root mount=/usb1-part2/coredns/config/:/etc/coredns/:ro workdir=/etc/coredns logging=yes start-on-boot=yes
> # Add $HomeDNSConfig definition in global-config-override
> /system/scheduler/add name=update-homenet-dns interval=24h start-time=03:00:00 on-event=setup-homenet-dns policy=read,write,sensitive
> # Also run it in /ipv6/dhcp-client's script
> /system/script/run setup-homenet-dns
```
