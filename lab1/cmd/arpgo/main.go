package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"net/netip"
	"time"

	"github.com/sazonovItas/arpgo/internel/ifutils"
	"github.com/sazonovItas/arpgo/internel/iputils"
)

var (
	// duration flag is used to set timeout for ARP request
	timeoutFlag = flag.Duration("t", time.Second, "timeout for ARP request")

	// ip flag is used for IPv4 destination for ARP request
	ipFlag = flag.String("ip", "all", "ip to send request")

	// interface flag is used for network interface for ARP request
	ifFlag = flag.String("i", "all", "network interface for send ARP request")
)

func main() {
	// parse flags
	flag.Parse()

	var ifaces []net.Interface
	if *ifFlag == "all" {
		ifaces, _ = net.Interfaces()
	} else {
		v, err := net.InterfaceByName(*ifFlag)
		if err != nil {
			log.Printf("error to get interface by name %s: %s", *ifFlag, err.Error())
			return
		}

		ifaces = append(ifaces, *v)
	}

	if *ipFlag != "all" {
		_, err := netip.ParseAddr(*ipFlag)
		if err != nil {
			flag.PrintDefaults()
			return
		}
	}

	OutputInterfaceMacs(ifaces, *ipFlag)
}

func OutputInterfaceMacs(ifaces []net.Interface, ip string) {
	for _, iface := range ifaces {
		if ipv4, mask := iputils.GetIpv4FromInterface(&iface); ipv4 == nil || mask == nil ||
			ipv4[0] == 127 ||
			mask[0] != 255 ||
			mask[1] != 255 {
			OutputIpToMacsByInterface(&iface, []iputils.IpToMac{}...)
			continue
		}

		if ip == "all" {
			ips, err := iputils.GetAllIPv4ForInterface(&iface)
			if err != nil {
				OutputIpToMacsByInterface(&iface, []iputils.IpToMac{}...)
				continue
			}

			ipMacs, err := ifutils.GetIpMacAddresses(&iface, ips, *timeoutFlag)
			if err != nil {
				OutputIpToMacsByInterface(&iface, []iputils.IpToMac{}...)
				continue
			}

			OutputIpToMacsByInterface(&iface, ipMacs...)
		} else {
			ipv4, _ := netip.ParseAddr(ip)

			ipMacs, err := ifutils.GetIpMacAddresses(&iface, []netip.Addr{ipv4}, *timeoutFlag)
			if err != nil {
				OutputIpToMacsByInterface(&iface, []iputils.IpToMac{}...)
				continue
			}

			OutputIpToMacsByInterface(&iface, ipMacs...)
		}
	}
}

func OutputIpToMacsByInterface(ifi *net.Interface, ipMacs ...iputils.IpToMac) {
	fmt.Printf("%s:\n", ifi.Name)
	if len(ipMacs) == 0 {
		fmt.Printf("\tno entry\n")
		return
	}

	for _, ipMac := range ipMacs {
		fmt.Printf("\t%s ---> %s\n", ipMac.Ip, ipMac.Mac)
	}
}
