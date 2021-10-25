// package main

// import (
// 	"fmt"
// 	"log"

// 	"github.com/google/gopacket"
// 	"github.com/google/gopacket/pcap"
// )

// var (
// 	pcapFile string = "test.pcap"
// 	handle   *pcap.Handle
// 	err      error
// )

// func main() {
// 	handle, err = pcap.OpenOffline(pcapFile)

// 	if err != nil {
// 		log.Fatal(err)
// 	}

// 	defer handle.Close()

// 	var filter string = "tcp"
// 	err = handle.SetBPFFilter(filter)
// 	if err != nil {
// 		log.Fatal(err)
// 	}

// 	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

// 	for packet := range packetSource.Packets() {
// 		fmt.Println(packet)
// 	}
// }
