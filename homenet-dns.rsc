#!rsc by RouterOS

# Provision zone files for a simple homenet authoritative nameserver.
#
# Homenet zones include zones from IANA's Locally-Served DNS Zones list (RFC 6303) as well as delegated IPv6 prefixes
# as determined by /ipv6/dhcp-client and, optionally, $argIP6DelegatedNetworksExtra.
# Each zone is represented by two files: "db.*" with SOA and NS, and "data.*" with A, AAAA, PTR and user's extra
# resource records from $argZonesExtra. This separation allows the script to minimize disk writes by maintaing
# hashes of all data files in the "state.json" file.
#
# $argHosts allows to add hosts to $argDomain. The first IPv4 / IPv6 address in the array is used for A / AAAA resource
# record. The remaining IP and MAC addresses are used to determine the list of PTR resource records.
#
#
# Arguments:
#   - argManagedID (str): Regex-escaped unique ID of the managed objects
#   - argNSRootPath (str): Path to a directory for zone files
#   - argNSIPAddress (ip, str): IPv4 address of the nameserver
#   - argNSIP6Address (ip, str): IPv6 address of the nameserver
#   - [argDomain] (str): Optional domain name that overrides global-config's $Domain; defaults to "home.arpa."
#   - [argHosts] (array): Optional array that maps hosts to an array of IPv4, IPv6 and MAC addresses to populate A, AAAA and PTR records
#       - key: Hostname within the domain
#       - value: An array of IPv4, IPv6 or MAC addresses
#   - [argIP6DelegatedNetworksExtra] (array): Optional array of IPv6 networks delegated to the router by means other than DHCPv6
#   - [argEmail] (str): Optional email that overrides global-config's $EmailGeneralTo; defaults to "nobody@invalid"
#   - [argTTL] (num): Optional TTL in seconds for DNS resource records; defaults to 3600
#   - [argIPARPStatusRegex] (str): Optional regex to filter IPv4 ARP when resolving hosts; defaults to "(permanent|reachable|stale)"
#   - [argIP6NeighborStatusRegex] (str): Optional regex to filter IPv6 neighbors when resolving hosts; defaults to "(noarp|reachable|stale)"
#   - [argInterfacesRegex] (str): Optional regex to filter interfaces when resolving IP addresses of hosts; defaults to "", i.e. any
#   - [argZonesExtra] (array): Optional array of extra resource records
#       - key: Zone domain name
#       - value: An array of additional resource records to append to the zone file
#
#
# Affects:
#   - /file
#   - /ip/dns/forwarders
#   - /ip/dns/static
#
#
# Requirements:
#   - mod/ipv4-structured
#   - mod/ipv6-structured
#   - mod/kentzo-functions

:global GlobalFunctionsReady;
:while ($GlobalFunctionsReady != true) do={ :delay 500ms; }


# Sorted by "address" for binary search.
:global constRFC6303IPDomainsLookupTable {
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
:global constRFC6303IP6DomainsLookupTable {
    {"network"=::/128 ; "address"=:: ; "domain"="0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.ip6.arpa."};
    {"network"=::1/128 ; "address"=::1 ; "domain"="1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.ip6.arpa."};
    {"network"=fd00::/8 ; "address"=fd00:: ; "domain"="d.f.ip6.arpa."};
    {"network"=fe80::/12 ; "address"=fe80:: ; "domain"="8.e.f.ip6.arpa."};
    {"network"=fe90::/12 ; "address"=fe90:: ; "domain"="9.e.f.ip6.arpa."};
    {"network"=fea0::/12 ; "address"=fea0:: ; "domain"="a.e.f.ip6.arpa."};
    {"network"=feb0::/12 ; "address"=feb0:: ; "domain"="b.e.f.ip6.arpa."};
    {"network"=2001:0db8::/32 ; "address"=2001:0db8:: ; "domain"="8.b.d.0.1.0.0.2.ip6.arpa."};
}

:global constIANADomains {
    {"domain"="home.arpa."};
    {"domain"="internal."};
    {"domain"="invalid."};
    {"domain"="resolver.arpa."};
    {"domain"="service.arpa."};
}

# Sorted by "address" for binary search.
:local MakeIP6DelegatedPrefixDomains do={
    :global DeduplicateIP6Addresses
    :global ExpandIP6Address
    :global MakeIP6Domain
    :global StructureIP6Address

    :local varNetworks $1
    :foreach pool in=[/ipv6/pool/print as-value proplist=prefix] do={
        :set varNetworks ($varNetworks , $pool->"prefix")
    }
    :local varNetworkStructs [$DeduplicateIP6Addresses $varNetworks structure=true]

    :local varLookupTable ({})
    :foreach networkStruct in=$varNetworkStructs do={
        :set varLookupTable ($varLookupTable , {{"network"=$networkStruct->"addressPrefix" ; "address"=$networkStruct->"prefix" ; "domain"=[$MakeIP6Domain $networkStruct]}})
    }

    :return $varLookupTable
}
:global varIP6DelegatedPrefixDomainsLookupTable [$MakeIP6DelegatedPrefixDomains $argIP6DelegatedNetworksExtra]

:global FindZoneDomainInLookupTable do={
    :local argLookupTable $1
    :local argAddress $2
    :local argDefault $3

    :local lo 0
    :local hi [:len $argLookupTable]
    :local i
    :local isFound false

    :while ($isFound = false and $lo < $hi) do={
        :set i (($lo + $hi) / 2)

        :if ($argAddress in $argLookupTable->$i->"network") do={
            :set isFound true
        } else={
            :if ($argAddress < $argLookupTable->$i->"address") do={
                :set hi $i
            } else={
                :set lo ($i + 1)
            }
        }
    }

    :if ($isFound) do={
        :return ($argLookupTable->$i->"domain")
    } else={
        :return $argDefault
    }
}

:global FindZoneDomain do={
    :global FindZoneDomainInLookupTable
    :global constIANADomains
    :global constRFC6303IP6DomainsLookupTable
    :global constRFC6303IPDomainsLookupTable
    :global varIP6DelegatedPrefixDomainsLookupTable

    :local argOwner $1
    :local argDefault $2

    :if ([:typeof $argOwner] = "ip") do={
        :return [$FindZoneDomainInLookupTable $constRFC6303IPDomainsLookupTable $argOwner $argDefault]
    }

    :if ([:typeof $argOwner] = "ip6") do={
        :local varDomain [$FindZoneDomainInLookupTable $constRFC6303IP6DomainsLookupTable $argOwner]
        :if ([:typeof $varDomain] != "nil") do={ :return $varDomain }
        :return [$FindZoneDomainInLookupTable $varIP6DelegatedPrefixDomainsLookupTable $argOwner $argDefault]
    }

    :if ([:typeof $argOwner] = "str") do={
        :foreach item in=$constIANADomains do={
            :local varDomain ($item->"domain")
            :if ($argOwner=$varDomain or $argOwner~".$varDomain\$") do={
                :return $varDomain
            }
        }
    }

    :return $argDefault
}

:global ResolveHost do={
    :global argInterfacesRegex
    :global argIP6NeighborStatusRegex
    :global argIPARPStatusRegex

    :local argAddresses $1

    :local varAllMACs ({})
    :local varA
    :local varAAAA
    :local varPTR ({})

    # First use provided addresses to collect all MACs of the host.
    :foreach a in=$argAddresses do={
        :if ([:typeof $a] = "ip") do={
            :set ($varPTR->"$[:tostr $a]") $a
            :if ([:len $varA] = 0) do={ :set varA $a }
            :foreach arp in=[/ip/arp/print as-value proplist=mac-address where address=$a interface~$argInterfacesRegex mac-address !disabled !invalid] do={
                :local m ($arp->"mac-address")
                :set ($varAllMACs->$m) $m
            }
        }

        :if ([:typeof $a] = "ip6") do={
            :set ($varPTR->"$[:tostr $a]") $a
            :if ([:len $varAAAA]) do={ :set varAAAA $a }
            :foreach nd in=[/ipv6/neighbor/print as-value proplist=mac-address where address=$a interface~$argInterfacesRegex mac-address] do={
                :local m ($nd->"mac-address")
                :set ($varAllMACs->$m) $m
            }
        }

        :if ([:typeof $a] = "str") do={ :set ($varAllMACs->$a) $a }
    }

    # Then use these MACs to find all IPs of the host.
    :foreach m in=$varAllMACs do={
        :foreach arp in=[/ip/arp/print as-value proplist=address where mac-address=$m interface~$argInterfacesRegex status~$argIPARPStatusRegex address !invalid !disabled] do={
            :local ip ($arp->"address")
            :if ([:typeof $ip] = "ip") do={ :set ($varPTR->"$[:tostr $ip]") $ip }
        }

        :foreach nd in=[/ipv6/neighbor/print as-value proplist=address where mac-address=$m interface~$argInterfacesRegex status~$argIP6NeighborStatusRegex address] do={
            :local ip6 ($nd->"address")
            :if ([:typeof $ip6] = "ip6") do={ :set ($varPTR->"$[:tostr $ip6]") $ip6 }
        }
    }

    :return {"a"=$varA ; "aaaa"=$varAAAA ; "ptr"=$varPTR}
}

:global MakeRelativeDomain do={
    :local argOrigin $1
    :local argFQDN $2

    :if ($argFQDN=$argOrigin) do={
        :return "@"
    } else={
        :if ($argFQDN~".$argOrigin\$") do={
            :return [:pick $argFQDN 0 ([:len $argFQDN] - [:len $argOrigin] - 1)]
        } else={
            :return $argFQDN
        }
    }
}

:global MakeZones do={
    :global FindZoneDomain
    :global MakeIP6Domain
    :global MakeIPDomain
    :global MakeRelativeDomain
    :global ResolveHost
    :global argDomain
    :global constIANADomains
    :global constRFC6303IP6DomainsLookupTable
    :global constRFC6303IPDomainsLookupTable
    :global varIP6DelegatedPrefixDomainsLookupTable

    :local argHosts $1
    :local argZonesExtra $2

    :local varZones ({})
    :foreach item in=$constRFC6303IPDomainsLookupTable do={ :local domain ($item->"domain") ; :set ($varZones->$domain) ({} , $argZonesExtra->$domain) }
    :foreach item in=$constRFC6303IP6DomainsLookupTable do={ :local domain ($item->"domain") ; :set ($varZones->$domain) ({} , $argZonesExtra->$domain) }
    :foreach item in=$constIANADomains do={ :local domain ($item->"domain") ; :set ($varZones->$domain) ({} , $argZonesExtra->$domain) }
    :foreach item in=$varIP6DelegatedPrefixDomainsLookupTable do={ :local domain ($item->"domain") ; :set ($varZones->$domain) ({} , $argZonesExtra->$domain) }

    foreach name,addresses in=$argHosts do={
        :local varResolvedAddresses [$ResolveHost $addresses]

        # Add A, AAAA and PTR resource records to the corresponding zones.
        :local varA ($varResolvedAddresses->"a")
        :if ([:len $varA]) do={
            :local varOrigin [$FindZoneDomain $argDomain $argDomain]
            :local varOwner [$MakeRelativeDomain $varOrigin ("$name.$argDomain")]
            :set ($varZones->$varOrigin) ($varZones->$varOrigin , "$varOwner A $varA")
        }

        :local varAAAA ($varResolvedAddresses->"aaaa")
        :if ([:len $varAAAA]) do={
            :local varOrigin [$FindZoneDomain $argDomain $argDomain]
            :local varOwner [$MakeRelativeDomain $varOrigin ("$name.$argDomain")]
            :set ($varZones->$varOrigin) ($varZones->$varOrigin , "$varOwner AAAA $varAAAA")
        }

        :local varPTR ($varResolvedAddresses->"ptr")
        :foreach address in=$varPTR do={
            :local varOrigin [$FindZoneDomain $address $argDomain]
            :local varOwner
            :if ([:typeof $address] = "ip") do={
                :set varOwner [$MakeIPDomain $address]
            } else={
                :set varOwner [$MakeIP6Domain $address]
            }
            :set varOwner [$MakeRelativeDomain $varOrigin $varOwner]
            :set ($varZones->$varOrigin) ($varZones->$varOrigin , "$varOwner PTR $name.$argDomain")
        }
    }

    :return $varZones
}

:global RemoveFile do={
    :global LogPrint
    :global varScriptName

    :local argPath $1

    $LogPrint debug $varScriptName ("Removing $argPath")
    /file/remove [find name=$argPath]
}

:global WriteFile do={
    :global LogPrint
    :global varScriptName

    :local argPath $1
    :local argContents $2

    $LogPrint debug $varScriptName ("Writing $argPath")
    :do {
        /file/set $argPath contents=$argContents
    } on-error={
        /file/add name=$argPath type=file contents=$argContents
    }
}

:global SetupZoneFiles do={
    :global LogPrint
    :global RemoveFile
    :global WriteFile
    :global argEmail
    :global argNSIP6Address
    :global argNSIPAddress
    :global argNSRootPath
    :global argTTL
    :global varScriptName

    :local argZones $1

    :local varStatePath "$argNSRootPath/state.json"
    :local varNewState ({})
    :local varOldState
    :do {
        :set varOldState [:deserialize value=[/file/get $varStatePath contents] from=json options=json.no-string-conversion]
    } on-error={
        :set varOldState ({})
    }

    :local varAllDBPaths ({})
    :local varAllDataPaths ({})
    :foreach zone,records in=$argZones do={
        :local varDBPath "$argNSRootPath/db.$zone"
        :local varDataPath "$argNSRootPath/data.$zone"

        :set ($varAllDBPaths->$varDBPath) 1
        :set ($varAllDataPaths->$varDataPath) 1

        :local varIncludeContents ""
        :if ([:len $records]) do={
            :if ([:len $argNSIPAddress]) do={ :set varIncludeContents ($varIncludeContents . "@ A $argNSIPAddress\n") }
            :if ([:len $argNSIP6Address]) do={ :set varIncludeContents ($varIncludeContents . "@ AAAA $argNSIP6Address\n") }
            :foreach r in=$records do={ :set varIncludeContents ($varIncludeContents . "$r\n") }
        }

        :local varNewHash [:convert $varIncludeContents transform=md5]
        :local varOldSerial
        :local varOldHash
        :if ([:typeof ($varOldState->$zone)] != "nothing") do={
            :set varOldSerial [:tonum ($varOldState->$zone->"serial")]
            :set varOldHash ($varOldState->$zone->"hash")
        } else={
            :set varOldSerial 0
            :set varOldHash ""
        }

        # Minimize disk writes by avoiding rewriting unchanged zones.
        :if ($varOldHash != $varNewHash) do={
            :local varNewSerial ($varOldSerial + 1)
            :local varZoneContents "\
\$ORIGIN $zone\n\
\$TTL $argTTL\n\
@ IN SOA @ $argEmail $varNewSerial 3600 1200 604800 $argTTL\n\
@ NS @\n\
\$INCLUDE data.$zone\n\
"
            $LogPrint info $varScriptName ("Updating $zone")
            [$WriteFile $varDBPath $varZoneContents]
            [$WriteFile $varDataPath $varIncludeContents]
            :set ($varNewState->$zone) ({"serial"=$varNewSerial ; "hash"=$varNewHash})
        } else={
            $LogPrint debug $varScriptName ("Reusing $zone")
            :set ($varNewState->$zone) ({"serial"=$varOldSerial ; "hash"=$varOldHash})
        }
    }

    # Clean up files of zones that do not exist anymore.
    :foreach file in=[/file/print as-value proplist=name where name~"^$argNSRootPath/db.*"] do={
        :local varPath ($file->"name")
        :if ($varAllDBPaths->$varPath != 1) do={
            [$RemoveFile $varPath]
        }
    }

    :foreach file in=[/file/print as-value proplist=name where name~"^$argNSRootPath/data.*"] do={
        :local varPath ($file->"name")
        :if ($varAllDataPaths->$varPath != 1) do={
            [$RemoveFile $varPath]
        }
    }

    [$WriteFile $varStatePath [:serialize value=$varNewState to=json options=json.no-string-conversion]]
}

:local SetupDNSForwarder do={
    :global SetIfExistsElseAdd
    :global argManagedID
    :global argNSIPAddress
    :global argNSIP6Address
    :global argTTL

    :local argZones $1

    $SetIfExistsElseAdd /ip/dns/forwarders\
        ({"comment~\"$argManagedID\\\$\""})\
        ({\
            "name"="homenet-dns";\
            "dns-servers"="$argNSIPAddress,$argNSIP6Address";\
            "comment"="\"Managed: homenet-dns / $argManagedID\""\
        })

    :foreach zone,contents in=$argZones do={
        :local varEntryName [:pick $zone 0 ([:len $zone] - 1)]
        $SetIfExistsElseAdd /ip/dns/static\
            ({"comment~\"$argManagedID\\\$\"" ; "name"="$varEntryName" ; "type"="FWD"})\
            ({\
                "name"="$zone";\
                "type"="FWD";\
                "forward-to"="homenet-dns";\
                "match-subdomain"="yes";\
                "disabled"="yes";\
                "ttl"=("$argTTL" . "s");\
                "comment"="\"Managed: homenet-dns / $argManagedID\""\
            })
    }

    # Clean up entries of zones that do not exist anymore.
    :foreach entry in=[/ip/dns/static/print as-value show-ids proplist=name where type=FWD comment~"$argManagedID\$"] do={
        :local varZoneName (($entry->"name") . ".")
        :if ([:typeof ($argZones->$varZoneName)] = "nothing") do={
            /ip/dns/static/remove ($entry->".id")
        }
    }
}

:local TearDown do={
    :global argManagedID
    :global argNSRootPath

    /ip/dns/static/remove [find comment~"$argManagedID\$"]
    /ip/dns/forwarders/remove [find comment~"$argManagedID\$"]
    /file/remove [find name~"^$argNSRootPath/(db|data)\\..*"]
    /file/remove [find name="$argNSRootPath/state.json"]
}


:global argManagedID
:global argNSRootPath
:global argNSIPAddress
:global argNSIP6Address
:global argDomain
:global argHosts
:global argEmail
:global argTTL
:global argIPARPStatusRegex
:global argIP6NeighborStatusRegex
:global argInterfacesRegex
:global argZonesExtra

:global AssertNotEmpty
:global CharacterReplace

# global-config.rsc
:global Domain
:if ([:len $argDomain] = 0 and [:len $Domain]) do={ :set argDomain $Domain }
:if ([:len $argDomain] = 0) do={ :set argDomain "home.arpa." }
:if ([:pick $argDomain ([:len $argDomain] - 1)] != ".") do={ :set argDomain ($argDomain . ".")}

# global-config.rsc
:global EmailGeneralTo
:local argEmailDefault "nobody@invalid"
:if ([:len $argEmail] = 0 and [:len $EmailGeneralTo]) do={ :set argEmail $EmailGeneralTo }
:if ([:len $argEmail] = 0) do={ :set argEmail $argEmailDefault }
:set argEmail [$CharacterReplace $argEmail "@" ("\\.")]

:local argTTLDefault 3600
:if ([:len $argTTL] = 0 or $argTTL <= 0) do={ :set argTTL $argTTLDefault }

:local argIPARPStatusRegexDefault "(permanent|reachable|stale)"
:if ([:len $argIPARPStatusRegex] = 0) do={ :set argIPARPStatusRegex $argIPARPStatusRegexDefault }

:local argIP6NeighborStatusRegexDefault "(noarp|reachable|stale)"
:if ([:len $argIP6NeighborStatusRegex] = 0) do={ :set argIP6NeighborStatusRegex $argIP6NeighborStatusRegexDefault }

:local argInterfacesRegexDefault ""
:if ([:len $argInterfacesRegex] = 0) do={ :set argInterfacesRegex $argInterfacesRegexDefault }

$AssertNotEmpty "argNSRootPath"
$AssertNotEmpty "argNSIPAddress"
$AssertNotEmpty "argNSIP6Address"
$AssertNotEmpty "argManagedID"

:do {
    :local varZones [$MakeZones $argHosts $argZonesExtra]
    $SetupZoneFiles $varZones
    $SetupDNSForwarder $varZones
} on-error={
    $TearDown
    $LogPrint error $0 ("Failed to set up Homenet DNS")
    :error "fatal error in homenet-dns.rsc"
}
