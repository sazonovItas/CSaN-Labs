package iputils

import (
	"encoding/binary"
	"net"
	"net/netip"
	"sync"
	"time"

	_ "github.com/j-keck/arping"
	"github.com/mdlayher/arp"
)

type IpToMac struct {
	Ip  netip.Addr
	Mac net.HardwareAddr
}

// return mac address from ip
func GetIpv4MacAddress(
	client *arp.Client,
	ipv4 netip.Addr,
	timeout time.Duration,
) (net.HardwareAddr, error) {
	if err := client.SetDeadline(time.Now().Add(timeout)); err != nil {
		return nil, err
	}

	mac, err := client.Resolve(ipv4)
	if err != nil {
		return nil, err
	}

	return mac, nil
}

func AsyncGetIpv4MacAddress(
	ifi *net.Interface,
	ipv4 netip.Addr,
	ch chan IpToMac,
	to time.Duration,
	wg *sync.WaitGroup,
	semch chan struct{},
) {
	defer func() {
		wg.Done()
		<-semch
	}()

	client, err := arp.Dial(ifi)
	if err != nil {
		return
	}
	defer client.Close()

	if err := client.SetReadDeadline(time.Now().Add(to)); err != nil {
		return
	}

	quitch := make(chan struct{})
	defer close(quitch)

	go func() {
		for {
			select {
			case <-quitch:
				return
			default:
				err := client.Request(ipv4)
				if err != nil {
					return
				}
				time.Sleep(time.Millisecond * 200)
			}
		}
	}()

	mac, err := client.Resolve(ipv4)
	quitch <- struct{}{}
	if err != nil {
		return
	}

	// mac, _, err := arping.PingOverIface(ipv4.AsSlice(), *ifi)
	// if err != nil {
	// 	return
	// }

	ch <- IpToMac{Ip: ipv4, Mac: mac}
}

// return all ip address related to that interface
func GetAllIPv4ForInterface(ifi *net.Interface) ([]netip.Addr, error) {
	addrs, err := ifi.Addrs()
	if err != nil {
		return nil, err
	}

	var ipAddrs []netip.Addr
	for _, addr := range addrs {
		var (
			ip   net.IP
			mask net.IPMask
		)

		switch v := addr.(type) {
		case *net.IPNet:
			ip = v.IP
			mask = v.Mask
		case *net.IPAddr:
			ip = v.IP
			mask = v.IP.DefaultMask()
		}

		if ip = ip.To4(); ip != nil {
			ipAddrs = append(ipAddrs, MaskIPv4(ip, mask)...)
		}

	}

	return ipAddrs, nil
}

func GetIpv4FromInterface(ifi *net.Interface) (net.IP, net.IPMask) {
	addrs, err := ifi.Addrs()
	if err != nil {
		return nil, nil
	}

	for _, addr := range addrs {
		var (
			ip   net.IP
			mask net.IPMask
		)

		switch v := addr.(type) {
		case *net.IPNet:
			ip = v.IP
			mask = v.Mask
		case *net.IPAddr:
			ip = v.IP
			mask = v.IP.DefaultMask()
		}

		if ip.To4() != nil {
			return ip, mask
		}
	}

	return nil, nil
}

// return all IPv4 address from given ip and mask
func MaskIPv4(ipv4 net.IP, submask net.IPMask) []netip.Addr {
	ip, mask := ipv4ToUint(ipv4), maskToUint(submask)
	firstIp := ip & mask
	lastIP := ip | ^mask

	ipAddrs := make([]netip.Addr, 0, lastIP-firstIp+1)
	for i := firstIp; i <= lastIP; i++ {
		addr, _ := netip.AddrFromSlice(uintToIpv4(i))
		ipAddrs = append(ipAddrs, addr)
	}

	return ipAddrs
}

func ipv4ToUint(ip net.IP) uint32 {
	if len(ip) == 16 {
		return binary.BigEndian.Uint32(ip[12:16])
	}

	return binary.BigEndian.Uint32(ip)
}

func uintToIpv4(ip uint32) net.IP {
	ipv4 := make(net.IP, 4)
	binary.BigEndian.PutUint32(ipv4, ip)
	return ipv4
}

func maskToUint(mask net.IPMask) uint32 {
	return binary.BigEndian.Uint32(mask)
}
