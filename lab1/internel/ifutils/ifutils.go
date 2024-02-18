package ifutils

import (
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/mdlayher/arp"

	"github.com/sazonovItas/arpgo/internel/iputils"
)

func GetIpMacAddresses(
	ifi *net.Interface,
	ips []netip.Addr,
	to time.Duration,
) ([]iputils.IpToMac, error) {
	const maxConcurrency = 1000

	var wg sync.WaitGroup
	ipMacs := make([]iputils.IpToMac, 0)

	macAddrsch := make(chan iputils.IpToMac)
	defer close(macAddrsch)

	go func() {
		for {
			if value, ok := <-macAddrsch; ok {
				ipMacs = append(ipMacs, value)
			} else {
				break
			}
		}
	}()

	semch := make(chan struct{}, maxConcurrency)
	defer close(semch)

	for _, ipAddr := range ips {
		semch <- struct{}{}
		wg.Add(1)
		go iputils.AsyncGetIpv4MacAddress(ifi, ipAddr, macAddrsch, to, &wg, semch)
	}

	wg.Wait()

	return ipMacs, nil
}

func GetIpv4MacAddress(
	ifi *net.Interface,
	ipAddr netip.Addr,
	to time.Duration,
) (iputils.IpToMac, error) {
	client, err := arp.Dial(ifi)
	if err != nil {
		return iputils.IpToMac{}, err
	}
	defer client.Close()

	ipMac := iputils.IpToMac{Ip: ipAddr}
	macAddr, err := iputils.GetIpv4MacAddress(client, ipAddr, to)
	if err != nil {
		return iputils.IpToMac{}, err
	}

	ipMac.Mac = macAddr
	return ipMac, nil
}
