package main

import (
	"bytes"
	"fmt"
	"log"

	awdl "github.com/arsalan914/awdl2"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

var (
	pcapFile    string = "awdl-sample.s0i0.pcap" //"test.pcap"
	device      string = "wlp111s0"
	snapshotLen int32  = 1024
	prom        bool   = false
	err         error
	handle      *pcap.Handle
)

func main() {
	handle, err = pcap.OpenOffline(pcapFile)

	if err != nil {
		log.Fatal(err)
	}

	defer handle.Close()

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		// printPacketInfo(packet)
		a, err := awdl.InitAwdlParser(packet)

		if err != nil {
			// fmt.Println(err)
		} else {
			fmt.Println(a.CategoryCode)
			fmt.Println(a.Oui)
			fmt.Println("Tags :", len(a.Tags))
			fmt.Println()

			for _, tag := range a.Tags {
				//todo: loop through each packet
				t := awdl.ProcessTag(tag)

				//case interface to struct
				sync, ok := t.(*awdl.SynchronizationParameters)
				if ok == true {
					fmt.Println(sync)
				}

				ep, ok := t.(*awdl.ElectionParameters)
				if ok == true {
					fmt.Println(ep)
				}

				cs, ok := t.(*awdl.ChannelSequence)
				if ok == true {
					fmt.Println(cs)
				}

				epv2, ok := t.(*awdl.ElectionParametersV2)
				if ok == true {
					fmt.Println(epv2)
				}
			}
		}
	}
}

func printPacketInfo(packet gopacket.Packet) {

	dot11Layer := packet.Layer(layers.LayerTypeDot11)
	if dot11Layer != nil {

		// fmt.Println("802.11 layer detected.")

		dot11, _ := dot11Layer.(*layers.Dot11)

		// fmt.Println("type : ", dot11.Type)
		// fmt.Printf("%d\n", dot11.Type)

		// the dot11 payload is the 802.11 fixed params + AWDL data.
		var awdlData []byte = dot11.Payload

		// type and subtype are stored in 'Type' variable as follows.
		//		type is 2 bits(bit 0 to 1).
		// 		subtype is 4 bits(bit 2 to 5)

		// however as per 802.11 protocol the 802.11 Frame Control Field 8 bit definition is as follows
		//		version is 2 bits (bit 0 to 1) which is not part of the dot11.Type field.
		//		type is 2 bits (bit 2 to 3)
		//		subtype is 4 bits (bit 4 to 7)

		f_type := (((dot11.Type << 2) & 0x0F) >> 2)
		f_subtype := (((dot11.Type << 2) & 0xF0) >> 4)

		var categoryCode uint8
		var oui [3]byte // organizational unit identifier

		if f_type == 0 && f_subtype == 0xD {

			// fmt.Println("length awldata", len(awdlData))

			// to be AWL following conditions must be satisfied:
			//		the bssid should be of apple device.
			// 		category code must be 127
			// 		OUI must be 00:17:F2
			if bytes.Equal(dot11.Address3, []byte{0x00, 0x25, 0x00, 0xff, 0x94, 0x73}) {

				if len(awdlData) > 0 {
					categoryCode = awdlData[0]
				}

				// 127 is vendor specific
				if categoryCode == 127 {
					copy(oui[:], awdlData[1:4])

					// 		OUI must be 00:17:F2
					if oui[0] == 0x00 && oui[1] == 0x17 && oui[2] == 0xF2 {
						// 802.11 fields
						fmt.Println("frame type = management")
						fmt.Println("frame subtype = action")
						fmt.Println("bssid :", dot11.Address3)
						fmt.Println("category code :", categoryCode)
						fmt.Println("OUI :", oui)

						// AWS specific Data
						awdl.DecodeAwdData(awdlData[4:])
						// fmt.Println("type :", awdlData[4])
						// fmt.Println("version :", awdlData[5]>>4, ".", awdlData[5]&0x0F)
						// fmt.Println("subtype :", awdlData[6])
						// fmt.Println()
					}
				}
			}
		}

		// if dot11.Type == 0xD0>>2 {
		// 	fmt.Println("type = management subtype = action")
		// 	fmt.Println("category code :", awdlData[0])
		// 	fmt.Println("OUI :", hex.EncodeToString(awdlData[1:4]))
		// }

		// fmt.Println("address3 : ", dot11.Address3)
	}

	// fmt.Println("All packet layers")
	// for _, layer := range packet.Layers() {
	// 	fmt.Println("-", layer.LayerType())
	// }
}
