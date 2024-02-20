package main

import (
	_ "bytes"
	"context"
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/fatih/color"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"

	oui "github.com/sazonovItas/arp-scanner/internal"
)

var (
	timeoutFlag = flag.Duration("t", time.Second, "set timeout of listening for ARP responds")
	ifaceFlag   = flag.String("i", "eth0", "set interface for scan devices")
	ipFlag      = flag.String("ip4", "none", "set ip for check mac hardware address")
	debugFlag   = flag.Bool("debug", false, "if set true print log of the program")

	cache = map[string]string{}
)

func main() {
	flag.Parse()

	if *debugFlag {
		defer color.Yellow("scanning are done")
	}

	var ipsToCheck []net.IP
	if ip := net.ParseIP(*ipFlag); ip != nil && ip.To4() != nil {
		ipsToCheck = append(ipsToCheck, ip.To4())
	} else {
		ipsToCheck = nil
	}

	iface, err := net.InterfaceByName(*ifaceFlag)
	if err != nil {
		fmt.Printf("error to get interface by name %s: %s\n", *ifaceFlag, err)
		return
	}

	fmt.Printf("%s:\n", iface.Name)
	if err := scan(iface, ipsToCheck); err != nil {
		fmt.Printf("error to scan interfase %s: %s\n", iface.Name, err)
		return
	}
}

func scan(iface *net.Interface, ipsToCheck []net.IP) error {
	var addr *net.IPNet
	if addrs, err := iface.Addrs(); err != nil {
		return err
	} else {
		for _, a := range addrs {
			var ipnet net.IPNet

			switch v := a.(type) {
			case *net.IPNet:
				ipnet.IP = v.IP
				ipnet.Mask = v.Mask
			case *net.IPAddr:
				ipnet.IP = v.IP
				ipnet.Mask = v.IP.DefaultMask()
			}

			if ipnet.IP = ipnet.IP.To4(); ipnet.IP != nil {
				addr = &net.IPNet{
					IP:   ipnet.IP,
					Mask: ipnet.Mask,
				}

				break
			}
		}
	}

	// check the interface addr
	if addr == nil {
		return errors.New("there is no good ip for network found")
	} else if addr.IP[0] == 127 {
		return errors.New("skipping localhost")
	} else if addr.Mask[0] != 0xff || addr.Mask[1] != 0xff {
		return errors.New("mask too large")
	}

	fmt.Printf("IP - %s  HWAddress - %s\n", addr.IP, iface.HardwareAddr.String())

	handle, err := pcap.OpenLive(iface.Name, 65536, true, pcap.BlockForever)
	if err != nil {
		return err
	}
	defer handle.Close()

	if ipsToCheck == nil {
		ipsToCheck = ipv4s(addr)
	}

	// start up a goroutine to read in packet data
	stop := make(chan struct{})
	go readARP(handle, iface, stop)
	defer close(stop)

	if *debugFlag {
		color.Yellow(
			"start scan interface %s and address %s with mask %s",
			iface.Name,
			addr.IP,
			addr.Mask,
		)
	}

	ctx, cancel := context.WithTimeout(context.Background(), *timeoutFlag)
	defer cancel()

	for {
		select {
		case <-ctx.Done():
			if *debugFlag {
				color.Yellow("context done")
			}

			if len(cache) == 0 {
				fmt.Printf("\tno entry for interface\n")
			}
			return nil
		default:
			// write out packets out to the handle
			if err := writeARP(handle, iface, addr, ipsToCheck); err != nil {
				return err
			}
			time.Sleep(time.Millisecond * 200)

			if len(cache) == len(ipsToCheck) {
				return nil
			}
		}
	}
}

func readARP(handle *pcap.Handle, iface *net.Interface, stop chan struct{}) {
	if *debugFlag {
		defer color.Yellow("read are done")
	}

	src := gopacket.NewPacketSource(handle, layers.LayerTypeEthernet)
	in := src.Packets()
	for {
		var packet gopacket.Packet
		select {
		case <-stop:
			return
		case packet = <-in:
			arpLayer := packet.Layer(layers.LayerTypeARP)
			if arpLayer == nil {
				continue
			}

			// ||	bytes.Equal([]byte(iface.HardwareAddr), arp.SourceHwAddress)
			arp := arpLayer.(*layers.ARP)
			if arp.Operation != layers.ARPReply {
				continue
			}

			if _, ok := cache[net.IP(arp.SourceProtAddress).String()]; !ok {
				fmt.Printf(
					"\t%15s ---> %s  ",
					net.IP(arp.SourceProtAddress),
					net.HardwareAddr(arp.SourceHwAddress),
				)

				if arp.SourceHwAddress[0]&0x2 == 1 {
					fmt.Printf("local administraited ")
				} else {
					strs := strings.Split(
						strings.ToUpper(net.HardwareAddr(arp.SourceHwAddress).String()),
						":",
					)
					if name, ok := oui.OUIs[strs[0]+":"+strs[1]+":"+strs[2]]; ok {
						fmt.Printf("%s   %s  ", name.Manufacturer, name.FullName)
					}
				}

				addr, err := net.LookupAddr(net.IP(arp.SourceProtAddress).String())
				if err == nil {
					fmt.Printf("%s", addr)
				}
				fmt.Printf("\n")

				cache[net.IP(arp.SourceProtAddress).String()] = net.HardwareAddr(arp.SourceHwAddress).
					String()
			}
		}
	}
}

func writeARP(handle *pcap.Handle, iface *net.Interface, addr *net.IPNet, ips []net.IP) error {
	if *debugFlag {
		defer color.Yellow("write are done")
	}

	// Set up all the layers' fields
	eth := layers.Ethernet{
		SrcMAC:       iface.HardwareAddr,
		DstMAC:       net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
		EthernetType: layers.EthernetTypeARP,
	}
	arp := layers.ARP{
		AddrType:          layers.LinkTypeEthernet,
		Protocol:          layers.EthernetTypeIPv4,
		HwAddressSize:     6,
		ProtAddressSize:   4,
		Operation:         layers.ARPRequest,
		SourceHwAddress:   []byte(iface.HardwareAddr),
		SourceProtAddress: []byte(addr.IP),
		DstHwAddress:      []byte{0, 0, 0, 0, 0, 0},
	}

	// buffers and options for serialization
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}

	// send one packet for every address
	for _, ip := range ips {
		arp.DstProtAddress = []byte(ip)
		err := gopacket.SerializeLayers(buf, opts, &eth, &arp)
		if err != nil {
			color.Red("error to serialize %s", err)
		}
		if err := handle.WritePacketData(buf.Bytes()); err != nil {
			return err
		}
	}

	return nil
}

func ipv4s(ipv4 *net.IPNet) (out []net.IP) {
	ip := binary.BigEndian.Uint32([]byte(ipv4.IP))
	mask := binary.BigEndian.Uint32([]byte(ipv4.Mask))
	ip &= mask

	for mask < 0xffffffff {
		var buf [4]byte
		binary.BigEndian.PutUint32(buf[:], ip)
		out = append(out, net.IP(buf[:]))
		mask++
		ip++
	}

	return
}
