# CVE-2021-24086

This is a proof of concept for [CVE-2021-24086](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-24086) ("Windows TCP/IP Denial of Service Vulnerability
"), a NULL dereference in `tcpip.sys` patched by Microsoft in February 2021. According to this [tweet](https://twitter.com/metr0/status/1359214923541192704), the vulnerability has been found by [@piazzt](https://twitter.com/piazzt). It is triggerable remotely by sending malicious UDP packet over IPv6.

![trigger](pics/trigger.gif)

You can read Microsoft's blog here: [Multiple Security Updates Affecting TCP/IP:  CVE-2021-24074, CVE-2021-24094, and CVE-2021-24086](https://msrc-blog.microsoft.com/2021/02/09/multiple-security-updates-affecting-tcp-ip/). It discusses briefly the impact and workaround/mitigations.

A more in-depth discussion about the root-cause is available on [doar-e.github.io](https://doar-e.github.io/): [Reverse-engineering tcpip.sys: mechanics of a packet of the death (CVE-2021-24086)](https://doar-e.github.io/blog/2021/04/15/reverse-engineering-tcpipsys-mechanics-of-a-packet-of-the-death-cve-2021-24086/).

![doare](pics/doare.png)

## Running the PoC

Run the `cve-2021-24086.py` script; it requires [Scapy](https://github.com/secdev/scapy):

```
over@bubuntu:~$ sudo python3 cve-2021-24086.py
66 fragments, total size 0xfff8
..................................................................
Sent 66 packets.
.
Sent 1 packets.
```

# Authors

* Axel '[@0vercl0k](https://twitter.com/0vercl0k)' Souchet
