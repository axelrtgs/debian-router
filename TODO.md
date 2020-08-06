# TODO

- Convert these to systemd unit since rc.local is deprecated on Debian 10

```shell
# netfilter
sysctl -wq net.netfilter.nf_conntrack_tcp_timeout_established=3600
echo 65536 > /sys/module/nf_conntrack/parameters/hashsize

# Assign CPU affinity
# /opt/router/scripts/irq-affinity
```

- Research on wide-dhcpv6 and proper setup for subnetting across the 3 vlans
- Setup Guest VLAN and appropriate firewall rules
- Why named cache and unbound keys manually?
- DNS ACL set proper with only LAN subnets
- DDNS script vs inadyn?
- dynamical enable all systemd services in repo during install
