package sniffer

import (
	"log"
	"net"
	"os"
	"strconv"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/oschwald/geoip2-golang"
)

type mainProcess func(GoniffPacket)

type GoniffAddress struct {
	ip      string
	port    int
	country string
	ptr     string
	ASN     string
	ORG     string
	typea   string
}

type GoniffPacket struct {
	src          GoniffAddress
	dst          GoniffAddress
	transmission string
}

var maing mainProcess

var db *geoip2.Reader
var db2 *geoip2.Reader

func loadASNFile() string {
	DB_ASNFile := "./databases/GeoLite2-ASN.mmdb"
	if len(os.Getenv("DB_GEOLITE_ASN")) > 0 {
		DB_ASNFile = os.Getenv("DB_GEOLITE_ASN")
	}
	return DB_ASNFile
}

func loadCountryFile() string {
	DB_ContryFile := "./databases/GeoLite2-Country.mmdb"
	if len(os.Getenv("DB_GEOLITE_COUNTRY")) > 0 {
		DB_ContryFile = os.Getenv("DB_GEOLITE_COUNTRY")
	}
	return DB_ContryFile
}

func Sniff(network_interface string, mainp mainProcess) {
	if os.Getenv("CACHEREDIS") != "" {
		CacheInit(true)
	} else {
		CacheInit(false)
	}

	maing = mainp

	db, _ = geoip2.Open(loadCountryFile())
	defer db.Close()

	db2, _ = geoip2.Open(loadASNFile())
	defer db2.Close()

	handle, err := pcap.OpenLive(network_interface, 65536, true, pcap.BlockForever)
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()

	filter := "tcp or udp"
	err = handle.SetBPFFilter(filter)
	if err != nil {
		log.Fatal(err)
	}

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		ipLayer := packet.Layer(layers.LayerTypeIPv4)
		if ipLayer != nil {
			switch packet.TransportLayer().LayerType() {
			case layers.LayerTypeTCP:
				tcpLayer := packet.Layer(layers.LayerTypeTCP)
				if tcpLayer != nil {
					tcp, _ := tcpLayer.(*layers.TCP)
					ip, _ := ipLayer.(*layers.IPv4)
					go processPacketTCP(ip, tcp)
				}
			case layers.LayerTypeUDP:
				udpLayer := packet.Layer(layers.LayerTypeUDP)
				if udpLayer != nil {
					udp, _ := udpLayer.(*layers.UDP)
					ip, _ := ipLayer.(*layers.IPv4)
					go processPacketUDP(ip, udp)
				}
			}
		}
	}
}

func lookupDB(ip net.IP) map[string]string {
	output := map[string]string{
		"country": "",
	}

	record, err := db.Country(ip)
	if err == nil {
		output["country"] = record.Country.IsoCode
	}

	record2, err2 := db2.ASN(ip)
	if err2 == nil {
		output["ASN"] = strconv.FormatUint(uint64(record2.AutonomousSystemNumber), 10)
		output["ORG"] = record2.AutonomousSystemOrganization
	}

	return output
}

func processPacketTCP(ip *layers.IPv4, tcp *layers.TCP) {
	src := processIP(ip.SrcIP, int(tcp.SrcPort))
	dst := processIP(ip.DstIP, int(tcp.DstPort))
	pkt := GoniffPacket{src: *src, dst: *dst, transmission: "TCP"}
	maing(pkt)
}

func processPacketUDP(ip *layers.IPv4, udp *layers.UDP) {
	src := processIP(ip.SrcIP, int(udp.SrcPort))
	dst := processIP(ip.DstIP, int(udp.DstPort))
	pkt := GoniffPacket{src: *src, dst: *dst, transmission: "UDP"}
	maing(pkt)
}

func processIP(ip net.IP, port int) *GoniffAddress {
	addr := GoniffAddress{
		ip:      ip.String(),
		port:    port,
		country: "",
		ptr:     "",
		ASN:     "",
		ORG:     "",
		typea:   "private",
	}

	if !isPrivateIP(ip) {
		populate := false

		addr.typea = "public"

		cachedp, err := GetPacket(ip.String())
		if err == nil {
			addr.country = cachedp["country"]
			addr.ptr = cachedp["ptr"]
			addr.ASN = cachedp["ASN"]
			addr.ORG = cachedp["ORG"]
		}

		if addr.country == "" {
			populate = true
			cachedp := lookupDB(ip)
			addr.country = cachedp["country"]
			addr.ASN = cachedp["ASN"]
			addr.ORG = cachedp["ORG"]
		}

		if addr.ptr == "" {
			populate = true
			addr.ptr = resolveDNSName(ip)
		}

		if populate {
			SetPacket(addr)
		}
	}

	return &addr
}
