Masquerade plugin for DNSCrypt
=========================

This is a [dnscrypt](http://dnscrypt.org) plugin to masquerade
DNS queries according with a hosts-like configuration file

Dependencies
------------

- cmake
- ldns

Installation
------------

```bash
$ cmake . && make
```

The resulting plugin can be copied anyhwere on the system.

Example usage
-------------

Create a hosts.mask file to configure what DNS should be masqueraded. The default location for this file is /usr/local/etc/hosts.mask

The plugin can then be loaded like any regular dnscrypt plugin, such as:

```bash
$ sudo dnscrypt-proxy --plugin=lib_masquerade,--hosts=/etc/hosts.mask
```
