#!rsc by RouterOS

# Wait for an /ipv6/address record with prefix $2 to appear on interface $1,
# optionally matched by the comment regex $3.
#
# $1 (str): Interface name to monitor
# $2 (ip6-prefix, str): IPv6 address-prefix the address must belong to
# [$3] (str): Regex that must match the comment of the /ipv6/address record
#
# > $WaitIP6Address loopback 2001:db8::/48
#
:global WaitIP6Address do={
    :local varAddress
    /ipv6/address {
        :retry command={
            :set varAddress [get value-name=address [find interface=$1 (address in $2) comment~"$3"]]
        } delay=1 max=5
    }
    :return $varAddress
}
