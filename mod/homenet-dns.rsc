#!rsc by RouterOS

# Homenet authoritative nameserver with DNS-Based Service Discovery
#
# - Authoritative answers for IANA's Locally-Served DNS Zones (RFC 6303) and delegated IPv6 prefixes
#   that avoid leakage of queries to the upstream DNS resolver
# - Support for Wide-Area DNS-Based Service Discovery (aka Wide-Area Bonjour)
# - Powered by CoreDNS: flexible, lightweight and extendable DNS server
#
# For each item in "hosts" you provide a hostname and at least one IPv4 or IPv6 address that is used for the corresponding "A"
# or "AAAA" resource record. Additional IP addresses and MAC addresses are used to gather a comprehensive list of PTR records.
# Router's local interfaces as well as ARP and ND tables are considered. Setting "ipARPStatusRegex", "ip6NeighborStatusRegex"
# and "interfacesRegex" narrows the seach.
#
# For each item in "services" you provide instance and service names, hostname and port as well as contents for the corresponding
# TXT record(s) as needed. Values must follow encodings and constraints as specified in RFC 6763, speficially Sections 4 and 6.
#
# The list of locally-served zones includes IANA assignments as well as "ipNetworksExtra", "ip6NetworksExtra" and "domainsExtra".
# Queries for these domains (and subdomains) will be authoritatively answered by the nameserver. NXDOMAIN will be returned
# for names that do exist.
#
# Each zone is represented by two files: "db.*" with SOA and NS that $INCLUDEs "data.*" with the remaining resource records.
# This separation allows the script to minimize disk writes and avoid unnecessary container restarts by maintaing hashes of
# all data files in the "state.json" file.
#
# By default the script checks whether RouterOS's DNS Resolver is set to allow remote requests and if so a forwarder will be set up.
#
# Additional zones and resource records can be set verbatim via "zonesExtra". Additional CoreDNS configuration can be set via
# "corefileExtra".
#
# $HomenetDNSConfig:
#   - managedID (str): Regex-escaped unique ID of the managed objects
#   - nsContainer (str): Name of the CoreDNS container
#   - [nsRoot] (str): Optional Path to the CoreDNS working directory on an attached disk that will be mounted into the container; defaults to the container's first mount
#   - [nsIPAddress] (ip, str): Optional IPv4 address of the nameserver; defaults to the container's first IPv4 address
#   - [nsIP6Address] (ip, str): Optional IPv6 address of the nameserver; defaults to the container's first IPv6 address
#   - [domain] (str): Optional default domain name for hosts and services; defaults to global-config's $Domain, if present, otherwise "home.arpa."
#   - [ttl] (num): Optional TTL in seconds for DNS resource records; defaults to 3600
#   - [hosts] (array): Optional array of hosts
#       - name: Hostname (and subdomain) relative to the "domain"
#       - [domain]: Optional domain of the host; defaults to config's "domain"
#       - addresses: An array of IPv4, IPv6 or MAC addresses
#   - [services] (array): Optional array of DNS-SD services (RFC 6763)
#       - name: <Instance> of Service Instance Name, encoded and escaped, e.g. "Home\\ Media"
#       - service: <Service> of Service Instance Name, e.g. "_smb._tcp"
#       - [domain]: Optional <Domain> of Service Instance Name, e.g. "home.arpa."; defaults to config's "domain"
#       - host: Hostname that provides service, e.g. "gateway" (relative to "domain") or "gateway.home.arpa." (absolute)
#       - port: Port on the "host" where the service is available, e.g. "445"
#       - [txt]: Optional TXT record(s) associated with the service instance
#           - {str}: one TXT record with multiple values, e.g. {"path"="/usb1-part2/media" ; "u=guest"} -> TXT ("path=/usb1-part2/media" "u=guest")
#           - {{str}}: Multiple TXT records where each follows the rule above
#   - [useDNSForwarder] (bool): Option flag to control whether /ip/dns/forwdarder for all configured zones is set up; defaults to `/ip/dns`'s allow-remote-requests
#   - [ipARPStatusRegex] (str): Optional regex to filter IPv4 ARP when resolving hosts; defaults to "(permanent|reachable|stale)"
#   - [ip6NeighborStatusRegex] (str): Optional regex to filter IPv6 neighbors when resolving hosts; defaults to "(noarp|reachable|stale)"
#   - [interfacesRegex] (str): Optional regex to filter interfaces when resolving addresses of hosts and delegated networks; defaults to ".*"
#   - [ipNetworksExtra] (array): Optional array of additional IPv4 networks delegated to the router; defaults to `/ip/dhcp-server/network`
#   - [ip6NetworksExtra] (array): Optional array of additional IPv6 networks delegated to the router; defaults to `/ipv6/dhcp-server` and `/ipv6/nd/prefix`
#   - [domainsExtra] (array): Optional array of additional domains delegated to the router
#   - [zonesExtra] (array): Optional array of additional resource records
#       - key: Zone domain name
#       - value: An array of additional resource records to append to the zone file
#   - [corefileExtra] (str): Optional additional configuration for CoreDNS, passed verbatim
#
# Affects:
#   - /container
#   - /file
#   - /ip/dns/forwarders
#   - /ip/dns/static
#
# Policy:
#   - read,write,sensitive
#
# Requirements:
#   - mod/ipv4-structured
#   - mod/ipv6-structured
#   - mod/kentzo-functions
#
# Caveats and Known Bugs:
#   - RouterOS (7.18.2) returns incorrect IPv6 address for a veth interface: specify manually
#   - RouterOS's (7.18.2) DNS Resolver rewrites NXDOMAIN responses from a forwarder as NODATA and removes the authority section
#   - macOS (15.4) cannot discover services over unicast DNS when iCloud Private Relay is on
#   - When using TLS in CoreDNS, make sure that the container image is built with up to date CA certificates
#
# Example:
#   # On the Host
#   $ docker build -t routeros_coredns:latest -f - . <<'END'
#       FROM --platform=$BUILDPLATFORM golang:1.23.8 AS build
#       WORKDIR /src
#       ADD https://github.com/coredns/coredns.git\#v1.12.1 /src
#       COPY <<EOF /src/plugin.cfg
#       errors:errors
#       log:log
#       cache:cache
#       rewrite:rewrite
#       auto:auto
#       forward:forward
#       template:template
#       EOF
#       RUN sh -c 'GOFLAGS="-buildvcs=false" make gen && GOFLAGS="-buildvcs=false" make'
#
#       FROM --platform=$TARGETPLATFORM gcr.io/distroless/static-debian12
#       COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
#       COPY --from=build /src/coredns /bin/coredns
#       COPY <<EOF /Corefile
#       . {
#           errors
#
#           import /etc/coredns/Corefile.extra
#           import /etc/coredns/Corefile.dns-sd
#           auto {
#               directory /etc/coredns/zones
#           }
#           template ANY ANY {
#               rcode REFUSED
#           }
#       }
#       EOF
#       WORKDIR /
#       ENTRYPOINT ["/bin/coredns"]
#       END
#   $ docker save routeros/coredns:latest | gzip > routeros_coredns.tar.gz
#   $ scp routeros_coredns.tar.gz <router-address>:/
#   $ cat << 'END' > SetupHomenetDNS.rsc
#       :local varJobName [:jobname]
#
#       :global GlobalFunctionsReady;
#       :while ($GlobalFunctionsReady != true) do={ :delay 500ms; }
#
#       :global ScriptLock
#       :if ([$ScriptLock $varJobName] = false) do={ :error false }
#
#       :global HomenetDNS
#       :global HomenetDNSConfig {
#           "managedID"="...";
#           "nsContainer"="...";
#           "hosts"={
#               {"name"="gateway" ; "addresses"={192.0.2.1 ; 2001:db8::1}};
#           };
#           "services"={
#               {"name"="Media" ; "service"="_smb._tcp" ; "host"="samba" ; "port"=445 ; txt={"path=/media" ; "u"="guest"}};
#           };
#           "zonesExtra"={
#               "home.arpa."={
#                   "samba CNAME gateway";
#               };
#           };
#       }
#       ($HomenetDNS->"Main")
#     END
#   $ scp SetupHomenetDNS.rsc <router-address>:/
#
#   # On the Router
#   > /interface/veth/add address=192.0.2.53/31,2001:db8:53::1/127 gateway=192.0.2.52 gateway6=2001:db8:53:: name=veth-coredns
#   > /ip/address/add address=192.0.2.52/31 interface=veth-coredns
#   > /ipv6/address/add address=2001:db8:53::/127 advertise=no interface=veth-coredns no-dad=yes
#   > /container/mounts/add dst=/etc/coredns/ name=coredns src=/usb1-part2/coredns/config
#   > /container/add file=routeros_coredns.tar.gz interface=veth-coredns root-dir=usb1-part2/coredns/root mounts=coredns workdir=/ logging=yes start-on-boot=yes
#   > /container/print where interface=veth-coredns; # note container name in the output
#   > /system/script/add name=SetupHomenetDNS source=[/file/get SetupHomenetDNS.rsc contents] policy=read,write,sensitive
#   > /system/script/edit SetupHomenetDNS value-name=source; # set "nsContainer" to the container name
#   > /system/script/run SetupHomenetDNS
#   > /system/scheduler/add name=UpdateHomenetDNS interval=24h on-event=SetupHomenetDNS policy=read,write,sensitive

:global HomenetDNS
:global HomenetDNSConfig

:set HomenetDNS ({})

# Sorted by "address" for binary search.
:set ($HomenetDNS->"constRFC6303IPDomainsLookupTable") {
    {"network"=0.0.0.0/8 ; "address"=0.0.0.0 ; "domain"="0.in-addr.arpa."};
    {"network"=10.0.0.0/8 ; "address"=10.0.0.0 ; "domain"="10.in-addr.arpa."};
    {"network"=100.64.0.0/16 ; "address"=100.64.0.0 ; "domain"="64.100.in-addr.arpa."};
    {"network"=100.65.0.0/16 ; "address"=100.65.0.0 ; "domain"="65.100.in-addr.arpa."};
    {"network"=100.66.0.0/16 ; "address"=100.66.0.0 ; "domain"="66.100.in-addr.arpa."};
    {"network"=100.67.0.0/16 ; "address"=100.67.0.0 ; "domain"="67.100.in-addr.arpa."};
    {"network"=100.68.0.0/16 ; "address"=100.68.0.0 ; "domain"="68.100.in-addr.arpa."};
    {"network"=100.69.0.0/16 ; "address"=100.69.0.0 ; "domain"="69.100.in-addr.arpa."};
    {"network"=100.70.0.0/16 ; "address"=100.70.0.0 ; "domain"="70.100.in-addr.arpa."};
    {"network"=100.71.0.0/16 ; "address"=100.71.0.0 ; "domain"="71.100.in-addr.arpa."};
    {"network"=100.72.0.0/16 ; "address"=100.72.0.0 ; "domain"="72.100.in-addr.arpa."};
    {"network"=100.73.0.0/16 ; "address"=100.73.0.0 ; "domain"="73.100.in-addr.arpa."};
    {"network"=100.74.0.0/16 ; "address"=100.74.0.0 ; "domain"="74.100.in-addr.arpa."};
    {"network"=100.75.0.0/16 ; "address"=100.75.0.0 ; "domain"="75.100.in-addr.arpa."};
    {"network"=100.76.0.0/16 ; "address"=100.76.0.0 ; "domain"="76.100.in-addr.arpa."};
    {"network"=100.77.0.0/16 ; "address"=100.77.0.0 ; "domain"="77.100.in-addr.arpa."};
    {"network"=100.78.0.0/16 ; "address"=100.78.0.0 ; "domain"="78.100.in-addr.arpa."};
    {"network"=100.79.0.0/16 ; "address"=100.79.0.0 ; "domain"="79.100.in-addr.arpa."};
    {"network"=100.80.0.0/16 ; "address"=100.80.0.0 ; "domain"="80.100.in-addr.arpa."};
    {"network"=100.81.0.0/16 ; "address"=100.81.0.0 ; "domain"="81.100.in-addr.arpa."};
    {"network"=100.82.0.0/16 ; "address"=100.82.0.0 ; "domain"="82.100.in-addr.arpa."};
    {"network"=100.83.0.0/16 ; "address"=100.83.0.0 ; "domain"="83.100.in-addr.arpa."};
    {"network"=100.84.0.0/16 ; "address"=100.84.0.0 ; "domain"="84.100.in-addr.arpa."};
    {"network"=100.85.0.0/16 ; "address"=100.85.0.0 ; "domain"="85.100.in-addr.arpa."};
    {"network"=100.86.0.0/16 ; "address"=100.86.0.0 ; "domain"="86.100.in-addr.arpa."};
    {"network"=100.87.0.0/16 ; "address"=100.87.0.0 ; "domain"="87.100.in-addr.arpa."};
    {"network"=100.88.0.0/16 ; "address"=100.88.0.0 ; "domain"="88.100.in-addr.arpa."};
    {"network"=100.89.0.0/16 ; "address"=100.89.0.0 ; "domain"="89.100.in-addr.arpa."};
    {"network"=100.90.0.0/16 ; "address"=100.90.0.0 ; "domain"="90.100.in-addr.arpa."};
    {"network"=100.91.0.0/16 ; "address"=100.91.0.0 ; "domain"="91.100.in-addr.arpa."};
    {"network"=100.92.0.0/16 ; "address"=100.92.0.0 ; "domain"="92.100.in-addr.arpa."};
    {"network"=100.93.0.0/16 ; "address"=100.93.0.0 ; "domain"="93.100.in-addr.arpa."};
    {"network"=100.94.0.0/16 ; "address"=100.94.0.0 ; "domain"="94.100.in-addr.arpa."};
    {"network"=100.95.0.0/16 ; "address"=100.95.0.0 ; "domain"="95.100.in-addr.arpa."};
    {"network"=100.96.0.0/16 ; "address"=100.96.0.0 ; "domain"="96.100.in-addr.arpa."};
    {"network"=100.97.0.0/16 ; "address"=100.97.0.0 ; "domain"="97.100.in-addr.arpa."};
    {"network"=100.98.0.0/16 ; "address"=100.98.0.0 ; "domain"="98.100.in-addr.arpa."};
    {"network"=100.99.0.0/16 ; "address"=100.99.0.0 ; "domain"="99.100.in-addr.arpa."};
    {"network"=100.100.0.0/16 ; "address"=100.100.0.0 ; "domain"="100.100.in-addr.arpa."};
    {"network"=100.101.0.0/16 ; "address"=100.101.0.0 ; "domain"="101.100.in-addr.arpa."};
    {"network"=100.102.0.0/16 ; "address"=100.102.0.0 ; "domain"="102.100.in-addr.arpa."};
    {"network"=100.103.0.0/16 ; "address"=100.103.0.0 ; "domain"="103.100.in-addr.arpa."};
    {"network"=100.104.0.0/16 ; "address"=100.104.0.0 ; "domain"="104.100.in-addr.arpa."};
    {"network"=100.105.0.0/16 ; "address"=100.105.0.0 ; "domain"="105.100.in-addr.arpa."};
    {"network"=100.106.0.0/16 ; "address"=100.106.0.0 ; "domain"="106.100.in-addr.arpa."};
    {"network"=100.107.0.0/16 ; "address"=100.107.0.0 ; "domain"="107.100.in-addr.arpa."};
    {"network"=100.108.0.0/16 ; "address"=100.108.0.0 ; "domain"="108.100.in-addr.arpa."};
    {"network"=100.109.0.0/16 ; "address"=100.109.0.0 ; "domain"="109.100.in-addr.arpa."};
    {"network"=100.110.0.0/16 ; "address"=100.110.0.0 ; "domain"="110.100.in-addr.arpa."};
    {"network"=100.111.0.0/16 ; "address"=100.111.0.0 ; "domain"="111.100.in-addr.arpa."};
    {"network"=100.112.0.0/16 ; "address"=100.112.0.0 ; "domain"="112.100.in-addr.arpa."};
    {"network"=100.113.0.0/16 ; "address"=100.113.0.0 ; "domain"="113.100.in-addr.arpa."};
    {"network"=100.114.0.0/16 ; "address"=100.114.0.0 ; "domain"="114.100.in-addr.arpa."};
    {"network"=100.115.0.0/16 ; "address"=100.115.0.0 ; "domain"="115.100.in-addr.arpa."};
    {"network"=100.116.0.0/16 ; "address"=100.116.0.0 ; "domain"="116.100.in-addr.arpa."};
    {"network"=100.117.0.0/16 ; "address"=100.117.0.0 ; "domain"="117.100.in-addr.arpa."};
    {"network"=100.118.0.0/16 ; "address"=100.118.0.0 ; "domain"="118.100.in-addr.arpa."};
    {"network"=100.119.0.0/16 ; "address"=100.119.0.0 ; "domain"="119.100.in-addr.arpa."};
    {"network"=100.120.0.0/16 ; "address"=100.120.0.0 ; "domain"="120.100.in-addr.arpa."};
    {"network"=100.121.0.0/16 ; "address"=100.121.0.0 ; "domain"="121.100.in-addr.arpa."};
    {"network"=100.122.0.0/16 ; "address"=100.122.0.0 ; "domain"="122.100.in-addr.arpa."};
    {"network"=100.123.0.0/16 ; "address"=100.123.0.0 ; "domain"="123.100.in-addr.arpa."};
    {"network"=100.124.0.0/16 ; "address"=100.124.0.0 ; "domain"="124.100.in-addr.arpa."};
    {"network"=100.125.0.0/16 ; "address"=100.125.0.0 ; "domain"="125.100.in-addr.arpa."};
    {"network"=100.126.0.0/16 ; "address"=100.126.0.0 ; "domain"="126.100.in-addr.arpa."};
    {"network"=100.127.0.0/16 ; "address"=100.127.0.0 ; "domain"="127.100.in-addr.arpa."};
    {"network"=127.0.0.0/16 ; "address"=127.0.0.0 ; "domain"="127.in-addr.arpa."};
    {"network"=169.254.0.0/16 ; "address"=169.254.0.0 ; "domain"="254.169.in-addr.arpa."};
    {"network"=172.16.0.0/16 ; "address"=172.16.0.0 ; "domain"="16.172.in-addr.arpa."};
    {"network"=172.17.0.0/16 ; "address"=172.17.0.0 ; "domain"="17.172.in-addr.arpa."};
    {"network"=172.18.0.0/16 ; "address"=172.18.0.0 ; "domain"="18.172.in-addr.arpa."};
    {"network"=172.19.0.0/16 ; "address"=172.19.0.0 ; "domain"="19.172.in-addr.arpa."};
    {"network"=172.20.0.0/16 ; "address"=172.20.0.0 ; "domain"="20.172.in-addr.arpa."};
    {"network"=172.21.0.0/16 ; "address"=172.21.0.0 ; "domain"="21.172.in-addr.arpa."};
    {"network"=172.22.0.0/16 ; "address"=172.22.0.0 ; "domain"="22.172.in-addr.arpa."};
    {"network"=172.23.0.0/16 ; "address"=172.23.0.0 ; "domain"="23.172.in-addr.arpa."};
    {"network"=172.24.0.0/16 ; "address"=172.24.0.0 ; "domain"="24.172.in-addr.arpa."};
    {"network"=172.25.0.0/16 ; "address"=172.25.0.0 ; "domain"="25.172.in-addr.arpa."};
    {"network"=172.26.0.0/16 ; "address"=172.26.0.0 ; "domain"="26.172.in-addr.arpa."};
    {"network"=172.27.0.0/16 ; "address"=172.27.0.0 ; "domain"="27.172.in-addr.arpa."};
    {"network"=172.28.0.0/16 ; "address"=172.28.0.0 ; "domain"="28.172.in-addr.arpa."};
    {"network"=172.29.0.0/16 ; "address"=172.29.0.0 ; "domain"="29.172.in-addr.arpa."};
    {"network"=172.30.0.0/16 ; "address"=172.30.0.0 ; "domain"="30.172.in-addr.arpa."};
    {"network"=172.31.0.0/16 ; "address"=172.31.0.0 ; "domain"="31.172.in-addr.arpa."};
    {"network"=192.0.2.0/24 ; "address"=192.0.2.0 ; "domain"="2.0.192.in-addr.arpa."};
    {"network"=192.168.0.0/16 ; "address"=192.168.0.0 ; "domain"="168.192.in-addr.arpa."};
    {"network"=198.51.100.0/24 ; "address"=198.51.100.0 ; "domain"="100.51.198.in-addr.arpa."};
    {"network"=203.0.113.0/24 ; "address"=203.0.113.0 ; "domain"="113.0.203.in-addr.arpa."};
    {"network"=255.255.255.255/32 ; "address"=255.255.255.255 ; "domain"="255.255.255.255.in-addr.arpa."};
}

# Sorted by "address" for binary search.
:set ($HomenetDNS->"constRFC6303IP6DomainsLookupTable") {
    {"network"=::/128 ; "address"=:: ; "domain"="0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.ip6.arpa."};
    {"network"=::1/128 ; "address"=::1 ; "domain"="1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.ip6.arpa."};
    {"network"=fd00::/8 ; "address"=fd00:: ; "domain"="d.f.ip6.arpa."};
    {"network"=fe80::/12 ; "address"=fe80:: ; "domain"="8.e.f.ip6.arpa."};
    {"network"=fe90::/12 ; "address"=fe90:: ; "domain"="9.e.f.ip6.arpa."};
    {"network"=fea0::/12 ; "address"=fea0:: ; "domain"="a.e.f.ip6.arpa."};
    {"network"=feb0::/12 ; "address"=feb0:: ; "domain"="b.e.f.ip6.arpa."};
    {"network"=2001:0db8::/32 ; "address"=2001:0db8:: ; "domain"="8.b.d.0.1.0.0.2.ip6.arpa."};
}

# RFC2606, RFC8375, RFC6761, RFC9462 and draft-ietf-dnssd-srp
:set ($HomenetDNS->"constReservedDomains") {
    {"domain"="example."};
    {"domain"="home.arpa."};
    {"domain"="internal."};
    {"domain"="invalid."};
    {"domain"="local."};
    {"domain"="localhost."};
    {"domain"="resolver.arpa."};
    {"domain"="service.arpa."};
    {"domain"="test."};
}

:set ($HomenetDNS->"RestartContainer") do={
    :global LogPrint

    :local argContainerID $0

    /container/stop $argContainerID
    :local varRetry 0
    :while ([/container/get $argContainerID value-name=status] != "stopped") do={
        :if ($varRetry < 100) do={
            :delay 100ms
            :set varRetry ($varRetry + 1)
        } else={
            $LogPrint error $varJobName ("failed to stop the container")
            :error false
        }
    }
    /container/start $argContainerID
}

:set ($HomenetDNS->"FileExists") do={
    :local argPath $0

    :do {
        /file/get $argPath value-name=name
        :return true
    } on-error={
        :return false
    }
}

:set ($HomenetDNS->"RemoveFile") do={
    :local argPath $0

    :onerror varError in={
        /file/remove $argPath
    } do={
        :if (($varError ~ "no such item") = false) do={
            :error $varError
        }
    }
}

:set ($HomenetDNS->"WriteFile") do={
    :local argPath $0
    :local argContents $1

    :onerror varError in={
        /file/set $argPath contents=$argContents
    } do={
        :if ($varError ~ "no such item") do={
            /file/add name=$argPath type=file contents=$argContents
        } else={
            :error $varError
        }
    }
}

:set ($HomenetDNS->"MakeFQDN") do={
    :local argDomain $0
    :local argDefaultDomain $1

    :local varDomain $argDomain
    :if ([:len $varDomain] = 0) do={
        :set varDomain $argDefaultDomain
    } else={
        :if ([:pick $varDomain ([:len $varDomain] - 1)] != ".") do={
            :set varDomain "$varDomain."
        }
    }
    :return $varDomain
}

:set ($HomenetDNS->"MakeRelativeDomain") do={
    :local argOrigin $0
    :local argFQDN $1

    :if ($argFQDN = $argOrigin) do={
        :return "@"
    } else={
        :if ($argFQDN ~ "\\.$argOrigin\$") do={
            :return [:pick $argFQDN 0 ([:len $argFQDN] - [:len $argOrigin] - 1)]
        } else={
            :return $argFQDN
        }
    }
}

:set ($HomenetDNS->"MakeDefaultIPNetworksExtra") do={
    :local varNetworks ({})

    # TODO: Only consider networks that are used by DHCPv4 servers running
    # on interfaces that match $interfacesRegex
    :local varItems [/ip/dhcp-server/network/print\
        as-value\
        proplist=address\
        where\
            address]
    :foreach varI in=$varItems do={
        :set varNetworks ($varNetworks , $varI->"address")
    }

    :return $varNetworks
}

:set ($HomenetDNS->"MakeDefaultIP6NetworksExtra") do={
    :local argConfig $0

    :local cfgInterfacesRegex ($argConfig->"interfacesRegex")
    :local varNetworks ({})

    :local varItems [/ipv6/address/print\
        as-value\
        proplist=from-pool\
        where\
            !disabled\
            !invalid\
            [:len $"from-pool"]\
            interface~$cfgInterfacesRegex]
    :foreach varI in=$varItems do={
        :local varPool ($varI->"from-pool")
        :set varNetworks ($varNetworks , [/ipv6/pool/get $varPool value-name=prefix])
    }

    :set varItems [/ipv6/nd/prefix/print\
        as-value\
        proplist=prefix\
        where\
            !disabled\
            !invalid\
            on-link\
            prefix\
            interface~$cfgInterfacesRegex]
    :foreach varI in=$varItems do={
        :set varNetworks ($varNetworks , $varI->"prefix")
    }

    :set varItems [/ipv6/dhcp-server/print\
        as-value\
        proplist=address-pool,prefix-pool\
        where\
            !disabled\
            !invalid\
            interface~$cfgInterfacesRegex]
    :foreach varI in=$varItems do={
        :local varAddressPool ($varI->"address-pool")
        :if (([:len $varAddressPool] > 0) and $varAddressPool != "static-only") do={
            :set varNetworks ($varNetworks , [/ipv6/pool/get $varAddressPool value-name=prefix])
        }

        :local varPrefixPool ($varI->"prefix-pool")
        :if (([:len $varPrefixPool] > 0) and $varPrefixPool != "static-only") do={
            :set varNetworks ($varNetworks , [/ipv6/pool/get $varPrefixPool value-name=prefix])
        }
    }

    :return $varNetworks
}

:set ($HomenetDNS->"FindZoneOriginInLookupTable") do={
    :local argLookupTable $0
    :local argAddress $1

    :local varLo 0
    :local varHi [:len $argLookupTable]
    :local varI
    :local varIsFound false

    :while ($varIsFound = false and $varLo < $varHi) do={
        :set varI (($varLo + $varHi) / 2)

        :if ($argAddress in $argLookupTable->$varI->"network") do={
            :set varIsFound true
        } else={
            :if ($argAddress < $argLookupTable->$varI->"address") do={
                :set varHi $varI
            } else={
                :set varLo ($varI + 1)
            }
        }
    }

    :if ($varIsFound) do={
        :return ($argLookupTable->$varI->"domain")
    } else={
        :return []
    }
}

:set ($HomenetDNS->"FindZoneOrigin") do={
    :global HomenetDNS

    :global MakeIPDomain
    :global MakeIP6Domain

    :local argState $0
    :local argOwner $1

    :if ([:typeof $argOwner] = "ip") do={
        :local varOrigin [($HomenetDNS->"FindZoneOriginInLookupTable") ($HomenetDNS->"constRFC6303IPDomainsLookupTable") $argOwner]
        :if ([:len $varOrigin] = 0) do={
            :set varOrigin [($HomenetDNS->"FindZoneOriginInLookupTable") ($argState->"varIPNetworksExtraLookupTable") $argOwner]
        }

        :if ([:len $varOrigin] != 0) do={
            :return $varOrigin
        } else={
            :return [$MakeIPDomain $argOwner]
        }
    }

    :if ([:typeof $argOwner] = "ip6") do={
        :local varOrigin [($HomenetDNS->"FindZoneOriginInLookupTable") ($HomenetDNS->"constRFC6303IP6DomainsLookupTable") $argOwner]
        :if ([:len $varOrigin] = 0) do={
            :set varOrigin [($HomenetDNS->"FindZoneOriginInLookupTable") ($argState->"varIP6NetworksExtraLookupTable") $argOwner]
        }

        :if ([:len $varOrigin] != 0) do={
            :return $varOrigin
        } else={
            :return [$MakeIP6Domain $argOwner]
        }
    }

    :set argOwner [:tostr $argOwner]
    :foreach varI in=($HomenetDNS->"constReservedDomains" , $argState->"varDomainsExtraLookupTable") do={
        :local varOrigin ($varI->"domain")
        :if ($argOwner = $varOrigin or $argOwner ~ "\\.$varOrigin\$") do={
            :return $varOrigin
        }
    }

    :return $argOwner
}

:set ($HomenetDNS->"ResolveHost") do={
    :global StructureIPAddress
    :global StructureIP6Address

    :local argState $0
    :local argAddresses $1

    :local varConfig ($argState->"varConfig")
    :local cfgInterfacesRegex ($varConfig->"interfacesRegex")
    :local cfgIPARPStatusRegex ($varConfig->"ipARPStatusRegex")
    :local cfgIP6NeighborStatusRegex ($varConfig->"ip6NeighborStatusRegex")

    :local varA
    :local varAAAA
    :local varPTR ({})

    # Use provided addresses to collect all related MACs and local interfaces.
    :local varAllMACs ({})
    :local varAllInterfaces ({})

    :foreach varAddress in=$argAddresses do={
        :if ([:typeof $varAddress] = "ip") do={
            :set ($varPTR->"$[:tostr $varAddress]") $varAddress
            :if ([:len $varA] = 0) do={
                :set varA $varAddress
            }

            # Local interface with matching IPv4 address
            :local varItems [/ip/address/print\
                as-value\
                proplist=interface,actual-interface\
                where\
                    !disabled\
                    !invalid\
                    ($varAddress in $address)\
                    interface~$cfgInterfacesRegex]
            :foreach varI in=$varItems do={
                :local varInt ($varI->"interface")
                :set ($varAllInterfaces->$varInt) $varInt
                :set varInt ($varI->"actual-interface")
                :set ($varAllInterfaces->$varInt) $varInt
            }

            # On-link host with matching IPv4 address
            :set varItems [/ip/arp/print\
                as-value\
                proplist=mac-address\
                where\
                    !disabled\
                    !invalid\
                    mac-address\
                    address=$varAddress\
                    interface~$cfgInterfacesRegex]
            :foreach varI in=$varItems do={
                :local varMAC ($varI->"mac-address")
                :set ($varAllMACs->$varMAC) $varMAC
            }
        }

        :if ([:typeof $varAddress] = "ip6") do={
            :set ($varPTR->"$[:tostr $varAddress]") $varAddress
            :if ([:len $varAAAA] = 0) do={
                :set varAAAA $varAddress
            }

            # Local interface with matching IPv6 address
            :local varItems [/ipv6/address/print\
                as-value\
                proplist=interface,actual-interface\
                where\
                    !disabled\
                    !invalid\
                    ($varAddress in $address)\
                    interface~$cfgInterfacesRegex]
            :foreach varI in=$varItems do={
                :local varInt ($varI->"interface")
                :set ($varAllInterfaces->$varInt) $varInt
                :set varInt ($varI->"actual-interface")
                :set ($varAllInterfaces->$varInt) $varInt
            }

            # On-link host with matching IPv6 address
            :set varItems [/ipv6/neighbor/print\
                as-value\
                proplist=mac-address\
                where\
                    mac-address\
                    address=$varAddress\
                    interface~$cfgInterfacesRegex]
            :foreach varI in=$varItems do={
                :local varMAC ($varI->"mac-address")
                :set ($varAllMACs->$varMAC) $varMAC
            }
        }

        :if ([:typeof $varAddress] = "str") do={
            :set ($varAllMACs->$varAddress) $varAddress

            # Local interface with matching MAC address
            :local varItems [/interface/print\
                as-value\
                proplist=name\
                where\
                    !disabled\
                    mac-address=$varAddress\
                    name~$cfgInterfacesRegex]
            :foreach varI in=$varItem do={
                :local varInt ($varI->"name")
                :set ($varAllInterfaces->$varInt) $varInt
            }
        }
    }

    # Then use these MACs and interfaces to find all IPs.
    :foreach varMAC in=$varAllMACs do={
        # On-link IPv4 hosts with matching MAC address
        :local varItems [/ip/arp/print\
            as-value\
            proplist=address\
            where\
                !disabled\
                !invalid\
                address\
                mac-address=$varMAC\
                interface~$cfgInterfacesRegex\
                status~$cfgIPARPStatusRegex]
        :foreach varARP in=$varItems do={
            :local varIP ($varARP->"address")
            :set ($varPTR->"$[:tostr $varIP]") $varIP
        }

        # On-link IPv6 hosts with matching MAC address
        :set varItems [/ipv6/neighbor/print\
            as-value\
            proplist=address\
            where\
                address\
                mac-address=$varMAC\
                interface~$cfgInterfacesRegex\
                status~$cfgIP6NeighborStatusRegex]
        :foreach varND in=$varItems do={
            :local varIP6 ($varND->"address")
            :set ($varPTR->"$[:tostr $varIP6]") $varIP6
        }
    }

    :foreach varInt in=$varAllInterfaces do={
        # IPv4 addresses assigned to matched interfaces
        :local varItems [/ip/address/print\
            as-value\
            proplist=address\
            where\
                !disabled\
                !invalid\
                actual-interface=$varInt]
        :foreach varIPPrefix in=$varItems do={
            :local varIP ([$StructureIPAddress ($varIPPrefix->"address")]->"address")
            :set ($varPTR->"$[:tostr $varIP]") $varIP
        }

        # IPv6 addresses assigned to matched interfaces
        :set varItems [/ipv6/address/print\
            as-value\
            proplist=address\
            where\
                !disabled\
                !invalid\
                actual-interface=$varInt]
        :foreach varIP6Prefix in=$varItems do={
            :local varIP6 ([$StructureIP6Address ($varIP6Prefix->"address")]->"address")
            :set ($varPTR->"$[:tostr $varIP6]") $varIP6
        }
    }

    :return {"a"=$varA ; "aaaa"=$varAAAA ; "ptr"=$varPTR}
}

:set ($HomenetDNS->"MakeHosts") do={
    :global HomenetDNS

    :global LogPrint
    :global MakeIPDomain
    :global MakeIP6Domain

    :local argState $0

    :local varConfig ($argState->"varConfig")
    :local cfgHosts ($varConfig->"hosts")
    :local cfgServices ($varConfig->"services")

    :local varZones ({})

    # Add A, AAAA and PTR records for every host.
    :foreach varHost in=$cfgHosts do={
        :local varName ($varHost->"name")
        :local varAddresses ($varHost->"addresses")
        :local varDomain ($varHost->"domain")

        :local varResolvedAddresses [($HomenetDNS->"ResolveHost") $argState $varAddresses]

        # Add A, AAAA and PTR resource records to the corresponding zones.
        :local varOrigin [($HomenetDNS->"FindZoneOrigin") $argState $varDomain]
        :local varOwner [($HomenetDNS->"MakeRelativeDomain") $varOrigin ("$varName.$varDomain")]

        :local varA ($varResolvedAddresses->"a")
        :if ([:len $varA]) do={
            :set ($varZones->$varOrigin) ($varZones->$varOrigin , "$varOwner A $varA")
        }

        :local varAAAA ($varResolvedAddresses->"aaaa")
        :if ([:len $varAAAA]) do={
            :set ($varZones->$varOrigin) ($varZones->$varOrigin , "$varOwner AAAA $varAAAA")
        }

        :if ([:len $varA] = 0 and [:len $varAAAA] = 0) do={
            $LogPrint error ($argState->"varJobName") ("host \"$varName\" must have at least one IP address")
            :error false
        }

        :local varPTR ($varResolvedAddresses->"ptr")
        :foreach varAddress in=$varPTR do={
            :set varOrigin [($HomenetDNS->"FindZoneOrigin") $argState $varAddress]
            :if ([:typeof $varAddress] = "ip") do={
                :set varOwner [$MakeIPDomain $varAddress]
            } else={
                :set varOwner [$MakeIP6Domain $varAddress]
            }
            :set varOwner [($HomenetDNS->"MakeRelativeDomain") $varOrigin $varOwner]
            :set ($varZones->$varOrigin) ($varZones->$varOrigin , "$varOwner PTR $varName.$varDomain")
        }
    }

    :return $varZones
}

:set ($HomenetDNS->"MakeServices") do={
    :global HomenetDNS

    :global JoinArray
    :global LogPrint

    :local argState $0

    :local varConfig ($argState->"varConfig")
    :local cfgServices ($varConfig->"services")
    :local cfgDomain ($varConfig->"domain")

    :local varZones ({})

    # Add PTR, SRV and TXT resource records for each DNS-SD service.
    :local varAllServices ({})
    :set ($varAllServices->$cfgDomain) ({})

    :foreach varService in=$cfgServices do={
        :local varDomain ($varService->"domain")
        :local varPort ($varService->"port")
        :local varOrigin [($HomenetDNS->"FindZoneOrigin") $argState $varDomain]

        :local varServiceType ($varService->"service")
        :local varServiceOwner "$varServiceType.$varDomain"
        :set varServiceOwner [($HomenetDNS->"MakeRelativeDomain") $varOrigin $varServiceOwner]

        :local varInstance ($varService->"name")
        :local varInstanceOwner "$varInstance.$varServiceOwner"

        :local varHostOwner ($varService->"host")
        :if ([:pick $varHostOwner ([:len $varHostOwner] - 1)] != ".") do={
            :set varHostOwner "$varHostOwner.$varDomain"
        }
        :set varHostOwner [($HomenetDNS->"MakeRelativeDomain") $varOrigin $varHostOwner]

        :set ($varZones->$varOrigin) ($varZones->$varOrigin,\
            "$varServiceOwner PTR $varInstanceOwner",\
            "$varInstanceOwner SRV 0 0 $varPort $varHostOwner")

        :local varTXT ($varService->"txt")
        :if ([:typeof ($varTXT->0)] != "array") do={
            :set varTXT ({$varTXT})
        }
        :local varTXTRData ({})
        :foreach varI in=$varTXT do={
            :foreach varK,varV in=$varI do={
                :if ([:typeof $varK] = "str") do={
                    :if ([:len $varK]) do={
                        :set varTXTRData ($varTXTRData , "\"$varK=$varV\"")
                    } else={
                        $LogPrint error ($argState->"varJobName") ("key in the TXT resource record of \"$varInstanceOwner\" must not be empty")
                        :error false
                    }
                } else={
                    :if ([:len $varV]) do={
                        :set varTXTRData ($varTXTRData , "\"$varV\"")
                    }
                }
            }
            :set $varTXTRData [$JoinArray $varTXTRData " "]
            :if ([:len $varTXTRData]) do={
                :set ($varZones->$varOrigin) ($varZones->$varOrigin , "$varInstanceOwner TXT ($varTXTRData)")
            }
        }

        :set ($varAllServices->$varDomain->$varServiceOwner) $varServiceOwner
    }

    # Add "_services._dns-sd._udp" to each zone that has at least one service.
    :local varAllServiceDomains ({})
    :local varAllServiceTypes ({})
    :foreach varDomain,varTypes in=$varAllServices do={
        :foreach varI in=$varTypes do={
            :local varOrigin [($HomenetDNS->"FindZoneOrigin") $argState $varDomain]
            :local varOwner "_services._dns-sd._udp.$varDomain"
            :set varOwner [($HomenetDNS->"MakeRelativeDomain") $varOrigin $varOwner]
            :set varI [($HomenetDNS->"MakeRelativeDomain") $varOrigin $varI]
            :set ($varZones->$varOrigin) ($varZones->$varOrigin , "$varOwner PTR $varI")
        }

        :set varAllServiceDomains ($varAllServiceDomains , $varDomain)
    }

    # Add DNS-SD browsing resource records: b._dns-sd._udp, lb._dns-sd._udp and db._dns-sd._udp
    # Since CoreDNS is configured to redirect queries for these resource records to $cfgDomain,
    # it's sufficient to only add them once to the zone of $cfgDomain.
    :local varOrigin [($HomenetDNS->"FindZoneOrigin") $argState $cfgDomain]
    :local varOwner "_dns-sd._udp.$cfgDomain"
    :set $varOwner [($HomenetDNS->"MakeRelativeDomain") $varOrigin $varOwner]
    :foreach varI in=$varAllServiceDomains do={
        :set varI [($HomenetDNS->"MakeRelativeDomain") $varOrigin $varI]
        :set ($varZones->$varOrigin) ($varZones->$varOrigin,\
            "b.$varOwner PTR $varI",\
            "lb.$varOwner PTR $varI")
    }
    :set ($varZones->$varOrigin) ($varZones->$varOrigin , "db.$varOwner PTR $[($HomenetDNS->"MakeRelativeDomain") $varOrigin $cfgDomain]")

    :return $varZones
}

:set ($HomenetDNS->"MakeZones") do={
    :global HomenetDNS

    :global MakeIPDomain
    :global MakeIP6Domain

    :local argState $0

    :local varConfig ($argState->"varConfig")
    :local cfgNSIPAddress ($varConfig->"nsIPAddress")
    :local cfgNSIP6Address ($varConfig->"nsIP6Address")
    :local cfgZonesExtra ($varConfig->"zonesExtra")

    :local varZones ({})
    :local varItems ($HomenetDNS->"constRFC6303IPDomainsLookupTable",\
        $HomenetDNS->"constRFC6303IP6DomainsLookupTable",\
        $HomenetDNS->"constReservedDomains",\
        $argState->"varIPNetworksExtraLookupTable",\
        $argState->"varIP6NetworksExtraLookupTable",\
        $argState->"varDomainsExtraLookupTable")
    :foreach varI in=$varItems do={
        :local varDomain ($varI->"domain")
        :set ($varZones->$varDomain) ({} , $cfgZonesExtra->$varDomain)
    }

    :foreach varK,varV in=[($HomenetDNS->"MakeHosts") $argState] do={
        :set ($varZones->$varK) ($varZones->$varK , $varV)
    }

    :foreach varK,varV in=[($HomenetDNS->"MakeServices") $argState] do={
        :set ($varZones->$varK) ($varZones->$varK , $varV)
    }

    # Add PTR recrods for reverse IP lookup of nameservers of zones that have resource records.
    :local varNSIPOrigin
    :local varNSIPOwner
    :if ([:len $cfgNSIPAddress]) do={
        :local varNSIPDomain [$MakeIPDomain $cfgNSIPAddress]
        :set varNSIPOrigin [($HomenetDNS->"FindZoneOrigin") $argState $cfgNSIPAddress]
        :set varNSIPOwner [($HomenetDNS->"MakeRelativeDomain") $varNSIPOrigin $varNSIPDomain]
    }
    :local varNSIPPTRRRSet ({})

    :local varNSIP6Origin
    :local varNSIP6Owner
    :if ([:len $cfgNSIP6Address]) do={
        :local varNSIP6Domain [$MakeIP6Domain $cfgNSIP6Address]
        :set varNSIP6Origin [($HomenetDNS->"FindZoneOrigin") $argState $cfgNSIP6Address]
        :set varNSIP6Owner [($HomenetDNS->"MakeRelativeDomain") $varNSIP6Origin $varNSIP6Domain]
    }
    :local varNSIP6PTRRRSet ({})

    :foreach varK,varV in=$varZones do={
        :if ([:len $varV]) do={
            :if ([:len $cfgNSIPAddress]) do={
                :set varV ("ns A $cfgNSIPAddress" , $varV)
                :set varNSIPPTRRRSet ($varNSIPPTRRRSet , "$varNSIPOwner PTR ns.$varK")
            }
            :if ([:len $cfgNSIP6Address]) do={
                :set varV ("ns AAAA $cfgNSIP6Address" , $varV)
                :set varNSIP6PTRRRSet ($varNSIP6PTRRRSet , "$varNSIP6Owner PTR ns.$varK")
            }
            :set ($varZones->$varK) $varV
        }
    }

    :if ([:len $cfgNSIPAddress]) do={
        :set ($varZones->$varNSIPOrigin) ($varZones->$varNSIPOrigin , $varNSIPPTRRRSet)
    }

    :if ([:len cfgNSIP6Address]) do={
        :set ($varZones->$varNSIP6Origin) ($varZones->$varNSIP6Origin , $varNSIP6PTRRRSet)
    }

    :return $varZones
}

:set ($HomenetDNS->"SetupCoreDNS") do={
    :global HomenetDNS

    :global LogPrint

    :local argState $0

    :local varJobName ($argState->"varJobName")
    :local varZones ($argState->"varZones")
    :local varConfig ($argState->"varConfig")
    :local cfgDomain ($varConfig->"domain")
    :local cfgNSContainer ($varConfig->"nsContainer")
    :local cfgNSRoot ($varConfig->"nsRoot")
    :local cfgNSIPAddress ($varConfig->"nsIPAddress")
    :local cfgNSIP6Address ($varConfig->"nsIP6Address")
    :local cfgTTL ($varConfig->"ttl")
    :local cfgCorefileExtra ($varConfig->"corefileExtra")

    :local varHasChanges false
    :local varStatePath "$cfgNSRoot/state.json"
    :local varNewState ({})
    :local varOldState
    :do {
        :set varOldState [:deserialize value=[/file/get $varStatePath contents] from=json options=json.no-string-conversion]
    } on-error={
        :set varOldState ({})
    }

    # Generate zone files.
    :foreach varOrigin,varRecords in=$varZones do={
        :local varDBPath "$cfgNSRoot/zones/db.$varOrigin"
        :local varDataPath "$cfgNSRoot/zones/data.$varOrigin"

        :local varDataContents ""
        :foreach varI in=$varRecords do={
            :set varDataContents ($varDataContents . "$varI\n")
        }

        :local varOldHash ($varOldState->$varOrigin->"hash")
        :local varOldSerial [:tonum ($varOldState->$varOrigin->"serial")]
        :local varOldTTL [:tonum ($varOldState->$varOrigin->"ttl")]
        :local varNewHash [:convert $varDataContents transform=md5]

        :if ($varOldHash != $varNewHash or $varOldTTL != $cfgTTL or [($HomenetDNS->"FileExists") $varDataPath] = false or [($HomenetDNS->"FileExists") $varDBPath] = false) do={
            :local varNewSerial ($varOldSerial + 1)
            :local varZoneContents "\
\$ORIGIN $varOrigin\n\
\$TTL $cfgTTL\n\
@ IN SOA ns nobody.invalid. ($varNewSerial 3600 1200 604800 $cfgTTL)\n\
@ NS ns\n\
\$INCLUDE data.$varOrigin\n"
            $LogPrint info $varJobName ("updating $varOrigin")
            ($HomenetDNS->"WriteFile") $varDataPath $varDataContents
            ($HomenetDNS->"WriteFile") $varDBPath $varZoneContents
            :set ($varNewState->$varOrigin) ({"serial"=$varNewSerial ; "hash"=$varNewHash ; "ttl"=$cfgTTL})
            :set varHasChanges true
        } else={
            $LogPrint debug $varJobName ("reusing $varOrigin")
            :set ($varNewState->$varOrigin) ($varOldState->$varOrigin)
        }
    }

    # Generate DNS-SD rule for CoreDNS.
    # The rewrite rule redirects all requests for DNS-SD auxiliary subdomains to $cfgDomain. This allows handling in one zone file.
    :local varDNSSDPath "$cfgNSRoot/Corefile.dns-sd"
    :local varDNSSDContents "rewrite stop name regex ^(b|db|lb)\\._dns-sd\\._udp\\.(.*)\$ {1}._dns-sd._udp.$cfgDomain answer auto\n"
    :local varDNSSDOldHash ($varOldState->"Corefile.dns-sd"->"hash")
    :local varDNSSDNewHash [:convert $varDNSSDContents transform=md5]
    :if ($varDNSSDOldHash != $varDNSSDNewHash or [($HomenetDNS->"FileExists") $varDNSSDPath] = false) do={
        $LogPrint info $varJobName ("updating Corefile.dns-sd")
        ($HomenetDNS->"WriteFile") $varDNSSDPath $varDNSSDContents
        :set ($varNewState->"Corefile.dns-sd") ({"hash"=$varDNSSDNewHash})
        :set varHasChanges true
    } else={
        $LogPrint debug $varJobName ("reusing Corefile.dns-sd")
        :set ($varNewState->"Corefile.dns-sd") ({"hash"=$varDNSSDOldHash})
    }

    :local varExtraPath "$cfgNSRoot/Corefile.extra"
    :local varExtraContents $cfgCorefileExtra
    :local varExtraOldHash ($varOldState->"Corefile.extra"->"hash")
    :local varExtraNewHash [:convert $varExtraContents transform=md5]
    :if ($varExtraOldHash != $varExtraNewHash or [($HomenetDNS->"FileExists") $varExtraPath] = false) do={
        $LogPrint info $varJobName ("updating Corefile.extra")
        ($HomenetDNS->"WriteFile") $varExtraPath $varExtraContents
        :set ($varNewState->"Corefile.extra") ({"hash"=$varExtraNewHash})
        :set varHasChanges true
    } else={
        $LogPrint debug $varJobName ("reusing Corefile.extra")
        :set ($varNewState->"Corefile.extra") ({"hash"=$varExtraOldHash})
    }

    # Clean up files of zones that do not exist anymore.
    :local varItems [/file/print\
        as-value\
        path="$cfgNSRoot/zones"\
        proplist=name\
        where\
            name~"^$cfgNSRoot/zones/(db|data)\\."]
    :foreach varI in=$varItems do={
        :local varPath ($varI->"name")
        :local varOrigin [:pick $varPath ([:find $varPath "." ([:len $cfgNSRoot])] + 1) [:len $varPath]]
        :if ([:len ($varNewState->$varOrigin)] = 0) do={
            $LogPrint debug $varJobName ("removing $varOrigin")
            ($HomenetDNS->"RemoveFile") $varPath
            :set varHasChanges true
        }
    }

    :if ($varHasChanges) do={
        $LogPrint info $varJobName ("CoreDNS configuration has changed, restarting the container")
        ($HomenetDNS->"WriteFile") $varStatePath [:serialize value=$varNewState to=json options=json.no-string-conversion]
        ($HomenetDNS->"RestartContainer") ($argState->"varContainerID")
    }
}

:set ($HomenetDNS->"SetupDNSForwarder") do={
    :global JoinArray
    :global DeduplicateArray
    :global SetIfExistsElseAdd

    :local argState $0

    :local varConfig ($argState->"varConfig")
    :local cfgManagedID ($varConfig->"managedID")
    :local cfgNSIPAddress ($varConfig->"nsIPAddress")
    :local cfgNSIP6Address ($varConfig->"nsIP6Address")
    :local cfgTTL ($varConfig->"ttl")
    :local varZones ($argState->"varZones")

    $SetIfExistsElseAdd /ip/dns/forwarders\
        ({"comment~\"$cfgManagedID\\\$\""})\
        ({
            "name"="homenet-dns";
            "dns-servers"=[$JoinArray [$DeduplicateArray ({$cfgNSIPAddress ; $cfgNSIP6Address})]];
            "comment"="\"Managed: homenet-dns / $cfgManagedID\""
        })

    :foreach varZone,varContents in=$varZones do={
        :local varEntryName [:pick $varZone 0 ([:len $varZone] - 1)]
        $SetIfExistsElseAdd /ip/dns/static\
            ({"comment~\"$cfgManagedID\\\$\"" ; "name"="$varEntryName" ; "type"="FWD"})\
            ({
                "name"="$varZone";
                "type"="FWD";
                "forward-to"="homenet-dns";
                "match-subdomain"="yes";
                "ttl"=($cfgTTL . "s");
                "comment"="\"Managed: homenet-dns / $cfgManagedID\""
            })
    }

    # Clean up entries of zones that do not exist anymore.
    :local varItems [/ip/dns/static/print\
        as-value\
        proplist=name\
        where\
            type=FWD\
            comment~"$cfgManagedID\$"]
    :foreach varI in=$varItems do={
        :local varOrigin ($varI->"name" . ".")
        :if ([:typeof ($varZones->$varOrigin)] = "nothing") do={
            /ip/dns/static/remove ($varI->".id")
        }
    }
}

:set ($HomenetDNS->"TearDownDNSForwarder") do={
    :local argState $0

    :local varConfig ($argState->"varConfig")
    :local cfgManagedID ($varConfig->"managedID")

    /ip/dns/static/remove [find comment~"$cfgManagedID\$"]
    /ip/dns/forwarders/remove [find comment~"$cfgManagedID\$"]
}

:set ($HomenetDNS->"TearDown") do={
    :global HomenetDNS

    :local argState $0

    :local varConfig ($argState->"varConfig")
    :local cfgNSRoot ($varConfig->"nsRoot")

    /container stop ($argState->"varContainerID")

    ($HomenetDNS->"TearDownDNSForwarder") $argState

    :local varItems [/file/print\
        as-value\
        list\
        path=$cfgNSRoot\
        where\
            type!=directory\
            name~"^$cfgNSRoot/zones/(db|data)\\."]
    :foreach varFile in=$varItems do={
        ($HomenetDNS->"RemoveFile") ($PvarFile->"name")
    }

    ($HomenetDNS->"RemoveFile") ("$cfgNSRoot/Corefile.dns-sd")
    ($HomenetDNS->"RemoveFile") ("$cfgNSRoot/state.json")
}

:set ($HomenetDNS->"Initialize") do={
    :global HomenetDNS
    :global HomenetDNSConfig

    :global DeduplicateIPAddresses
    :global DeduplicateIP6Addresses
    :global DeduplicateStrArray
    :global LogPrint
    :global MakeIPDomain
    :global MakeIP6Domain
    :global StructureIPAddress
    :global StructureIP6Address

    :local varConfig ({})
    :local varJobName [:jobname]
    :local varState {"varJobName"=$varJobName}

    :local cfgManagedID ($HomenetDNSConfig->"managedID")
    :if ([:len $cfgManagedID] = 0) do={
        $LogPrint error $varJobName ("managedID must not be empty")
        :error false
    }
    :set ($varConfig->"managedID") $cfgManagedID

    :local cfgNSContainer ($HomenetDNSConfig->"nsContainer")
    :if ([:len $cfgNSContainer] = 0) do={
        $LogPrint error $varJobName ("nsContainer must not be empty")
        :error false
    }
    :set ($varConfig->"nsContainer") $cfgNSContainer

    :local varContainer ([/container/print as-value proplist=interface,mounts where name=$cfgNSContainer]->0)
    :if ([:len $varContainer] = 0) do={
        $LogPrint error $varJobName ("Container \"$cfgNSContainer\" does not exist")
        :error false
    }
    :set ($varState->"varContainerID") ($varContainer->".id")

    :local cfgNSRoot ($HomenetDNSConfig->"nsRoot")
    :if ([:len $cfgNSRoot] = 0) do={
        :local varMount ($varContainer->"mounts"->0)
        :set cfgNSRoot ([/container/mounts/print as-value proplist=src where name=$varMount]->0->"src")
        :if ([:pick $cfgNSRoot 0] = "/") do={
            # /file doesn't like paths starting with "/"
            :set cfgNSRoot [:pick $cfgNSRoot 1 [:len $cfgNSRoot]]
        }
    }
    :if ([:len $cfgNSRoot] = 0) do={
        $LogPrint error $varJobName ("nsRoot must not be empty")
        :error false
    }
    :if ([/file/get $cfgNSRoot value-name="type"] != "directory") do={
        $LogPrint error $varJobName ("nsRoot must be an existing directory")
        :error false
    }
    :set ($varConfig->"nsRoot") $cfgNSRoot

    :local cfgNSIPAddress ($HomenetDNSConfig->"nsIPAddress")
    :local cfgNSIP6Address ($HomenetDNSConfig->"nsIP6Address")
    :if ([:len $cfgNSIPAddress] = 0 or [:len $cfgNSIP6Address] = 0) do={
        :local varInterface ($varContainer->"interface")
        :local varItems [/interface/veth/get $varInterface value-name=address]
        :foreach varI in=$varItems do={
            :if ([:len $cfgNSIPAddress] = 0 and [:typeof $varI] = "ip-prefix") do={
                :set cfgNSIPAddress ([$StructureIPAddress $varI]->"address")
            }
            :if ([:len $cfgNSIP6Address] = 0 and [:typeof $varI] = "ip6-prefix") do={
                :set cfgNSIP6Address ([$StructureIP6Address $varI]->"address")
            }
        }
    }
    :if ([:len $cfgNSIPAddress] = 0 and [:len $cfgNSIP6Address] = 0) do={
        $LogPrint error $varJobName ("at least one of nsIPAddress and nsIP6Address must not be empty")
        :error false
    }
    :set ($varConfig->"nsIPAddress") $cfgNSIPAddress
    :set ($varConfig->"nsIP6Address") $cfgNSIP6Address

    :local cfgDomain ($HomenetDNSConfig->"domain")
    :local cfgDomainDefault "home.arpa."
    :global Domain
    :if ([:len $cfgDomain] = 0 and [:len $Domain] > 0) do={
        :set cfgDomain $Domain
    }
    :set cfgDomain [($HomenetDNS->"MakeFQDN") $cfgDomain $cfgDomainDefault]
    :set ($varConfig->"domain") $cfgDomain

    :local cfgTTL ($HomenetDNSConfig->"ttl")
    :local cfgTTLDefault 3600
    :if ([:len $cfgTTL] = 0 or $cfgTTL <= 0) do={
        :set cfgTTL $cfgTTLDefault
    }
    :set ($varConfig->"ttl") $cfgTTL

    :local cfgIPARPStatusRegex ($HomenetDNSConfig->"ipARPStatusRegex")
    :local cfgIPARPStatusRegexDefault "(permanent|reachable|stale)"
    :if ([:len $cfgIPARPStatusRegex] = 0) do={
        :set cfgIPARPStatusRegex $cfgIPARPStatusRegexDefault
    }
    :set ($varConfig->"ipARPStatusRegex") $cfgIPARPStatusRegex

    :local cfgIP6NeighborStatusRegex ($HomenetDNSConfig->"ip6NeighborStatusRegex")
    :local cfgIP6NeighborStatusRegexDefault "(noarp|reachable|stale)"
    :if ([:len $cfgIP6NeighborStatusRegex] = 0) do={
        :set cfgIP6NeighborStatusRegex $cfgIP6NeighborStatusRegexDefault
    }
    :set ($varConfig->"ip6NeighborStatusRegex") $cfgIP6NeighborStatusRegex

    :local cfgInterfacesRegex ($HomenetDNSConfig->"interfacesRegex")
    :local cfgInterfacesRegexDefault ".*"
    :if ([:len $cfgInterfacesRegex] = 0) do={
        :set cfgInterfacesRegex $cfgInterfacesRegexDefault
    }
    :set ($varConfig->"interfacesRegex") $cfgInterfacesRegex

    :local cfgHosts ({})
    :foreach varI in=($HomenetDNSConfig->"hosts") do={
        :set ($varI->"domain") [($HomenetDNS->"MakeFQDN") ($varI->"domain") $cfgDomain]
        :set cfgHosts ($cfgHosts , {$varI})
    }
    :set ($varConfig->"hosts") $cfgHosts

    :local cfgServices ({})
    :foreach varI in=($HomenetDNSConfig->"services") do={
        :set ($varI->"domain") [($HomenetDNS->"MakeFQDN") ($varI->"domain") $cfgDomain]
        :set cfgServices ($cfgServices , {$varI})
    }
    :set ($varConfig->"services") $cfgServices

    :set ($varConfig->"zonesExtra") ($HomenetDNSConfig->"zonesExtra")
    :set ($varConfig->"domainsExtra") ($HomenetDNSConfig->"domainsExtra")

    :set ($varConfig->"ipNetworksExtra") ($HomenetDNSConfig->"ipNetworksExtra")
    :if ([:typeof ($varConfig->"ipNetworksExtra")] = "nothing") do={
        :set ($varConfig->"ipNetworksExtra") [($HomenetDNS->"MakeDefaultIPNetworksExtra") $varConfig]
    }

    :set ($varConfig->"ip6NetworksExtra") ($HomenetDNSConfig->"ip6NetworksExtra")
    :if ([:typeof ($varConfig->"ip6NetworksExtra")] = "nothing") do={
        :set ($varConfig->"ip6NetworksExtra") [($HomenetDNS->"MakeDefaultIP6NetworksExtra") $varConfig]
    }

    :local cfgUseDNSForwarderDefault [/ip/dns/get allow-remote-requests]
    :local cfgUseDNSForwarder ($HomenetDNSConfig->"useDNSForwarder")
    :if ([:typeof $cfgUseDNSForwarder] = "nothing") do={
        :set cfgUseDNSForwarder $cfgUseDNSForwarderDefault
    } else={
        :set cfgUseDNSForwarder [:tobool $cfgUseDNSForwarder]
    }
    :set ($varConfig->"useDNSForwarder" $cfgUseDNSForwarder)

    :set ($varConfig->"corefileExtra") [:tostr ($HomenetDNSConfig->"corefileExtra")]

    :set ($varState->"varConfig") $varConfig

    :local varItems [$DeduplicateIPAddresses ($varConfig->"ipNetworksExtra") structure=true]
    :local varLookupTable ({})
    :foreach varI in=$varItems do={
        :set varLookupTable ($varLookupTable , {{
            "network"=($varI->"addressPrefix");
            "address"=($varI->"prefix");
            "domain"=[$MakeIPDomain $varI];
        }})
    }
    :set ($varState->"varIPNetworksExtraLookupTable") $varLookupTable

    :set varItems [$DeduplicateIP6Addresses ($varConfig->"ip6NetworksExtra") structure=true]
    :set varLookupTable ({})
    :foreach varI in=$varItems do={
        :set varLookupTable ($varLookupTable , {{
            "network"=($varI->"addressPrefix");
            "address"=($varI->"prefix");
            "domain"=[$MakeIP6Domain $varI];
        }})
    }
    :set ($varState->"varIP6NetworksExtraLookupTable") $varLookupTable

    :local varItems [$DeduplicateStrArray $argDomains]
    :set varLookupTable ({})
    :foreach varI in=$varItems do={
        :set varLookupTable ($varLookupTable , {{"domain"=$varI}})
    }
    :set ($varState->"varDomainsExtraLookupTable") $varLookupTable

    :set ($varState->"varZones") [($HomenetDNS->"MakeZones") $varState]

    :return $varState
}

:set ($HomenetDNS->"Main") do={
    :global HomenetDNS

    :global LogPrint

    :local varState [($HomenetDNS->"Initialize")]
    # $LogPrint debug ($varState->"varJobName") [:serialize value=$varState to=json options=json.pretty,json.no-string-conversion]

    :onerror varError in={
        ($HomenetDNS->"SetupCoreDNS") $varState

        :if ($varState->"varConfig"->"useDNSForwarder") do={
            ($HomenetDNS->"SetupDNSForwarder") $varState
        } else={
            ($HomenetDNS->"TearDownDNSForwarder") $varState
        }
    } do={
        ($HomenetDNS->"TearDown") $varState
        $LogPrint error ($varState->"varJobName") ("failed to set up Homenet DNS: $varError")
        :error false
    }
}
