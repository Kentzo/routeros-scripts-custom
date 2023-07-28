# Wait for an IPv6 address with prefix $2 to appear on $1 marked by the comment regex $3.
:global WaitIP6Address do={
    :local varAddress
    /ipv6/address {
        :retry command={
            :set varAddress [get value-name=address [find interface=$1 (address in $2) comment~"$3\$"]]
        } delay=1 max=5
    }
    :return $varAddress
}
