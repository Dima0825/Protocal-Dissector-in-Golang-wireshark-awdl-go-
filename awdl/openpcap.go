// package main

// import (
// 	"fmt"
// 	"log"

// 	"github.com/google/gopacket"
// 	"github.com/google/gopacket/pcap"
// )

// var (
// 	pcapFile string = "awdl-sample.s0i0.pcap"
// 	handle   *pcap.Handle
// 	err      error
// )

// func main() {
// 	handle, err = pcap.OpenOffline(pcapFile)

// 	if err != nil {
// 		log.Fatal(err)
// 	}

// 	defer handle.Close()

// 	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

// 	for packet := range packetSource.Packets() {
// 		fmt.Println(packet)
// 	}
// }
