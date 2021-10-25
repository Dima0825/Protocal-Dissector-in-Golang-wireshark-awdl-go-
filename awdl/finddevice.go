// package main

// import (
// 	"fmt"
// 	"log"

// 	"github.com/google/gopacket/pcap"
// )

// func main() {

// 	devices, err := pcap.FindAllDevs()

// 	if err != nil {
// 		log.Fatal(err)
// 	}

// 	fmt.Println("Devices Found")

// 	for _, device := range devices {
// 		fmt.Println("\nName: ", device.Name)
// 		fmt.Println("Description: ", device.Description)

// 		for _, address := range device.Addresses {
// 			fmt.Println("- Ip Address:", address.IP)
// 			fmt.Println("- Subnet mask:", address.Netmask)
// 		}
// 	}
// }
