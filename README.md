
# Network Nasmespace Utils

Create network namespace in one command line !

## Usage

```
Usage: netns [OPTIONS] --name <NAME>

Options:
  -n, --name <NAME>      Name of the network namespace
  -i, --ifname <IFNAME>  Interface name to enslave in the network namespace
  -d, --destroy          Destroy the network namespace
  -h, --help             Print help
  -V, --version          Print version
```

## Examples
1. Create a network namespace 'test' with 'eno1' interface in it:
```
guillaume@nix:~$ netns -n test -i enp5s0
Creating network namespace test
Joining network namespace test
guillaume@test:~$ ip link
1: lo: <LOOPBACK> mtu 65536 qdisc noop state DOWN mode DEFAULT group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
2: enp5s0: <BROADCAST,MULTICAST> mtu 1500 qdisc noop state DOWN mode DEFAULT group default qlen 1000
    link/ether fc:aa:14:cb:e9:aa brd ff:ff:ff:ff:ff:ff
```

2. Join the network namespace in another terminal:
```
guillaume@nix:~$ ip link
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN mode DEFAULT group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
5: dummy0: <BROADCAST,NOARP> mtu 1500 qdisc noop state DOWN mode DEFAULT group default qlen 1000
    link/ether de:e8:6d:eb:72:30 brd ff:ff:ff:ff:ff:ff
guillaume@nix:~$ netns -n test
Joining network namespace test
guillaume@test:~$ ip link
1: lo: <LOOPBACK> mtu 65536 qdisc noop state DOWN mode DEFAULT group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
2: enp5s0: <BROADCAST,MULTICAST> mtu 1500 qdisc noop state DOWN mode DEFAULT group default qlen 1000
    link/ether fc:aa:14:cb:e9:aa brd ff:ff:ff:ff:ff:ff
```

3. Simply destroy the network namespace when exiting all terminals
```
guillaume@test:~$ exit
exit
netns reference count: 1
guillaume@nix:~$ 

guillaume@test:~$ exit
exit
netns reference count: 0
Destroying network namespace test
NETNS Inode: 4026534538
guillaume@nix:~$ 
```
