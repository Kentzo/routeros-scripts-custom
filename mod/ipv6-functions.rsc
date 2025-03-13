#!rsc by RouterOS

# Run command with arguments specified as an array.
#
# $1 (str): Full command name to run
# $2 (array): An array of command arguments
#
# Array of arguments may contain key-values which will be added as $key=$value
# or just values that will be added as is. Order of arguments follows array enumeration.
#
# > $RunCommandFromArray /ipv6/firewall/raw/print ({"detail", "where", "src-address-list"="blacklist"})
# /ipv6/firewall/raw/print detail where src-address-list=blacklist
#
:global RunCommandFromArray do={
    :global LogPrint

    :local varCommand [:tostr $1]
    :foreach k,v in=$2 do={
        :if ([:typeof $k] = "num") do={
            :set varCommand ($varCommand . " $[:tostr $v]")
        } else={
            :set varCommand ($varCommand . " $k=$[:tostr $v]")
        }
    }
    :local varResult
    :do {
        $LogPrint debug $0 ("> $varCommand")
        :set varResult [[:parse $varCommand]]
        $LogPrint debug $0 ("  $[:tostr $varResult]")
    } on-error={
        $LogPrint error $0 ("`$varCommand` failed")
        :error "fatal error in ipv6-functions.rsc/RunCommandFromArray"
    }
    :return $varResult
}

# Update objects in place if they already exist; otherwise add them.
#
# $1 (str): Full path where find, add and set commands will be run
# $2 (array): Search criteria
# $3 (array): Add/set properties
#
# > $SetIfExistsElseAdd /ipv6/firewall/raw ({"comment~\"blocklist\""}) ({chain="prerouting";action="drop";comment="\"blocklist\""})
#
:global SetIfExistsElseAdd do={
    :global RunCommandFromArray

    :local varExisting ([$RunCommandFromArray ("$1/find") $2]->0)
    :if ($varExisting) do={
        $RunCommandFromArray ("$1/set") ($3 , {numbers=$varExisting})
    } else={
        $RunCommandFromArray ("$1/add") $3
    }
}

# Same as SetIfExistsElseAdd but objects are only updated if they fail equality check.
#
# This is useful to avoid side effects of set, such as address re-allocation
# when setting /ipv6/address. It's costlier to run, avoid unless necessary.
#
# $1 (str): Full path where print, add and set commands will be run
# $2 (array): Search criteria
# $3 (array): Equality criteria, compared against `print as-value`
# $4 (array): Add/set properties
#
:global SetIfExistsElseAddUnlessEqual do={
    :global LogPrint
    :global RunCommandFromArray

    :local varExisting ([$RunCommandFromArray ("$1/print") ({"as-value" ; "where"} , $2)]->0)
    :if ($varExisting) do={
        :foreach k,v in=$3 do={
            :if ([:typeof $k] = "num") do={
                $LogPrint error $0 ("equality criteria cannot have non-key elements")
                :error "fatal error in ipv6-functions.rsc/SetIfExistsElseAddUnlessEqual"
            }
            :local left ($varExisting->$k)
            :local right $v
            :if ($left != $right) do={
                $LogPrint debug $0 ("\"$k\": $left != $right")
                $RunCommandFromArray ("$1/set") ($4 , {numbers=($varExisting->".id")})

                :return []
            }
        }
    } else={
        $RunCommandFromArray ("$1/add") $4
    }
}

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
    /ipv6/address {
        :retry command={
            :local varAddress [get value-name=address ([find interface=$1 (address in $2) comment~"$3"]->0)]
            $LogPrint $0 debug ("$varAddress from $2 is available on $1")
            :return $varAddress
        } on-error={
            :local varWrongAddresses
            :foreach varAddress in=[print as-value proplist=address where interface=$1 comment~"$3"] do={
                :set varWrongAddresses ($varWrongAddresses . " $($varAddress->address)")
            }
            $LogPrint $0 error ("expected an address from $2 on $1, got ($varWrongAddresses) instead")
            :error "fatal error in ipv6-functions.rsc/WaitIP6Address"
        } delay=1 max=5
    }
}

# Assert that a given variable named $1 has non-empty value $2.
#
# $1 (str): Name of the variable for logging
# $2: Value for checking
#
# > $AssertNotEmpty argLoopbackInt $argLoopbackInt
#
:global AssertNotEmpty do={
    :global LogPrint

    :if ([:len $2] = 0) do={
        $LogPrint $0 error ("$1 cannot be empty")
        :error "fatal error in ipv6-functions.rsc/AssertNotEmpty"
    }
}

# Remove duplicates from the array.
#
# $1 (array): An array of items with defined relational operator '='.
#
# > :put [$DeduplicateArray ({1;2;3;1})]
# 1;2;3
#
:global DeduplicateArray do={
    :local varDuplicatesIdx ({})

    :for i from=([:len $1] - 1) to=0 step=1 do={
        :local j ($i - 1)
        :while ($j >= 0 and $varDuplicatesIdx->"$i" != true) do={
            :if ($1->$i = $1->$j) do={
                :set ($varDuplicatesIdx->"$i") true
            }

            :set j ($j - 1)
        }
    }

    :local varArray ({})
    :for i from=0 to=([:len $1] - 1) step=1 do={
        :if ($varDuplicatesIdx->"$i" != true) do={
            :set varArray ($varArray , $1->$i)
        }
    }

    :return $varArray
}
