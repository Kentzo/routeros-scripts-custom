Available scripts
=================

* [mod/kentzo-functions](mod/kentzo-functions.rsc): Utility functions used by other modules and scripts
* [mod/ipv4-structured](mod/ipv4-structured.rsc): Structured view of the IPv4 address
* [mod/ipv6-structured](mod/ipv6-structured.rsc): Structured view of the IPv6 address
* [mod/homenet-dns](mod/homenet-dns.rsc): Configure zones for a homenet authoritative nameserver powered by [CoreDNS](https://coredns.io)
* [ipv6-npt](ipv6-npt.rsc): Install or update NPTv6 rules for a given prefix

For detailed documentation consult corresponding script files.

Installation
============

Scripts are designed to extend @eworm-de's excellent [routeros-scripts](https://github.com/eworm-de/routeros-scripts) project, it's a prerequisite.

E.g. mod/kentzo-functions can be installed via:

    $ScriptInstallUpdate mod/kentzo-functions "base-url=https://raw.githubusercontent.com/Kentzo/routeros-scripts-custom/main/"

Scripts and modules may depend on other modules in *mod/\**. Read the header in script file before installation.
