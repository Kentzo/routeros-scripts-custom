#!rsc by RouterOS
# argLoopbackInt: name of the loopback interface
# argWanPool: name of the WAN pool 
# argUlaPool: name of the ULA pool
# argManagedID: regex-escaped unique ID of the managed objects

:global argLoopbackInt
:global argWanPool
:global argUlaPool
:global argManagedID

:global GlobalFunctionsReady;
:while ($GlobalFunctionsReady != true) do={ :delay 500ms; }

:global WaitIP6Address
:global LogPrintExit2

/ipv6/pool
:local varWanPrefix [get value-name=prefix $argWanPool]
:local varUlaPrefix [get value-name=prefix $argUlaPool]

:do {
    /ipv6/address
    :local varOldGuaPrefix [get value-name=address [find comment~"$argManagedID\$"]]
    :local varNewGuaPrefix [$WaitIP6Address $argLoopbackInt $varWanPrefix $argManagedID]

    :if ($varOldGuaPrefix != $varNewGuaPrefix) do={
        :log info "Set $varNewGuaPrefix <-> $varUlaPrefix"
        /ipv6/firewall/mangle
        set dst-prefix=$varNewGuaPrefix [find action=snpt comment~"$argManagedID\$"]
        set dst-address=$varNewGuaPrefix src-prefix=$varNewGuaPrefix [find action=dnpt comment~"$argManagedID\$"]
    }
} on-error={
    /ipv6/address
    remove [find comment~"$argManagedID\$"]
    add interface=$argLoopbackInt advertise=no from-pool=$argWanPool comment="Managed: NPTv6 / $argManagedID"
    :local varGuaPrefix
    :do {
        :set varGuaPrefix [$WaitIP6Address $argLoopbackInt $varWanPrefix $argManagedID]
    } on-error={
        remove [find comment~"$argManagedID\$"]
        $LogPrintExit2 error "Unable to allocate prefix from $varWanPrefix on $argLoopbackInt" true
    }

    :log info "Add $varGuaPrefix <-> $varUlaPrefix"
    /ipv6/firewall/mangle
    remove [find comment~"$argManagedID\$"]
    add chain=postrouting action=snpt src-address=$varUlaPrefix src-prefix=$varUlaPrefix dst-prefix=$varGuaPrefix comment="Managed: NPTv6 / $argManagedID"
    add chain=prerouting action=dnpt dst-address=$varGuaPrefix src-prefix=$varGuaPrefix dst-prefix=$varUlaPrefix comment="Managed: NPTv6 / $argManagedID"
}
