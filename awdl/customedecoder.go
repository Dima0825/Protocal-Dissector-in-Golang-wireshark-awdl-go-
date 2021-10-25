package main

import (
	"encoding/binary"
	"fmt"
	"log"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

type CustomLayer struct {
	layers.BaseLayer
	SomeBytes     byte
	AnotherBytes  byte
	AnotherBytes2 byte
	AnotherBytes3 byte
	AnotherBytes4 uint32
	AnotherBytes5 uint32
	restOfData    []byte
}

var CustomLayerType = gopacket.RegisterLayerType(
	2001,
	gopacket.LayerTypeMetadata{
		"CustomLayerType",
		gopacket.DecodeFunc(decodeCustomLayer),
	},
)

var (
	pcapFile    string = "awdl-sample.s0i0.pcap" //"test.pcap"
	device      string = "wlp111s0"
	snapshotLen int32  = 1024
	prom        bool   = false
	err         error
	handle      *pcap.Handle
)

func (l *CustomLayer) LayerType() gopacket.LayerType {
	return CustomLayerType
}

func (l *CustomLayer) LayerContents() []byte {
	return []byte{l.SomeBytes, l.AnotherBytes}
}

func (l *CustomLayer) LayerPayload() []byte {
	return l.restOfData
}

func (l *CustomLayer) CanDecode() gopacket.LayerClass {
	return CustomLayerType
}

func decodeCustomLayer(data []byte, p gopacket.PacketBuilder) error {

	awdl := &CustomLayer{}

	awdl.SomeBytes = data[0]
	awdl.AnotherBytes = data[1]
	awdl.AnotherBytes2 = data[2]
	awdl.AnotherBytes3 = data[3]
	awdl.AnotherBytes4 = binary.BigEndian.Uint32(data[4:8])
	awdl.AnotherBytes5 = binary.BigEndian.Uint32(data[8:12])
	awdl.restOfData = data[12:]
	p.AddLayer(awdl)

	return p.NextDecoder(gopacket.LayerTypePayload)
}

// var g int = 0

func main() {
	handle, err = pcap.OpenOffline(pcapFile)

	if err != nil {
		log.Fatal(err)
	}

	defer handle.Close()

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		printPacketInfo(packet)
	}
}

func printPacketInfo(packet gopacket.Packet) {
	ethernetLayer := packet.Layer(layers.LayerTypeEthernet)

	if ethernetLayer != nil {
		fmt.Println("Ethernet layer detected")
		ethernetPacket, _ := ethernetLayer.(*layers.Ethernet)

		fmt.Println("source mac: ", ethernetPacket.SrcMAC)

		fmt.Println()
	}

	// Let's see if the packet is IP (even though the ether type told us)
	ipLayer := packet.Layer(layers.LayerTypeIPv4)
	if ipLayer != nil {
		fmt.Println("IPv4 layer detected.")
		ip, _ := ipLayer.(*layers.IPv4)

		// IP layer variables:
		// Version (Either 4 or 6)
		// IHL (IP Header Length in 32-bit words)
		// TOS, Length, Id, Flags, FragOffset, TTL, Protocol (TCP?),
		// Checksum, SrcIP, DstIP
		fmt.Printf("From %s to %s\n", ip.SrcIP, ip.DstIP)
		fmt.Println("Protocol: ", ip.Protocol)
		fmt.Println()
	}

	awdl := packet.Layer(CustomLayerType)

	if awdl != nil {
		fmt.Println("awdl layer detected.")

	}

	fmt.Println("All packet layers")
	for index, layer := range packet.Layers() {
		fmt.Println(index, "-", layer.LayerType())
		// g++
		// fmt.Println(g, "-")
	}
}
