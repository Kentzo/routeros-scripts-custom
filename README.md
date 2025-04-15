Available scripts
=================

* [mod/kentzo-functions](mod/ipv6-functions): Utility functions used by other modules and scripts
* [mod/ipv4-structured](mod/ipv6-structured): Structured view of the IPv4 address
* [mod/ipv6-structured](mod/ipv6-structured): Structured view of the IPv6 address
* [ipv6-npt](ipv6-npt): Install or update NPTv6 rules for a given prefix
* [homenet-dns](homenet-dns): Configure zones for a homenet authoritative nameserver powered by [CoreDNS](https://coredns.io)

For detailed documentation consult corresponding script files.

Installation
============

Scripts are designed to extend @eworm-de's excellent [routeros-scripts](https://github.com/eworm-de/routeros-scripts) project, it's a prerequisite.

E.g. mod/kentzo-functions can be installed via:

    $ScriptInstallUpdate mod/kentzo-functions "base-url=https://raw.githubusercontent.com/Kentzo/routeros-scripts-custom/main/"

Scripts and modules may depend on other modules in *mod/\**. Read the header in script file before installation.
