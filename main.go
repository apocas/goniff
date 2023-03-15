package main

import (
	"fmt"
	"os"

	"apocas/goniff/helper"
	"apocas/goniff/sniffer"

	"github.com/joho/godotenv"
)

func process(packet sniffer.GoniffPacket) {
	fmt.Println(packet)
}

func init() {
	godotenv.Load(".env")
}

func main() {
	var network_interface = ""

	if len(os.Args) < 2 {
		fmt.Println("Trying to find suitable interface...")
		network_interface = helper.FindInterface()

		if network_interface == "" {
			fmt.Println("Usage interface as ARG, EX: goniff eth0")
			os.Exit(0)
		}
	} else {
		network_interface = os.Args[1]
	}

	sniffer.Sniff(network_interface, process)
}
