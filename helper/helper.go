package helper

import (
	"fmt"
	"net"
)

func FindInterface() string {
	conn, err := net.Dial("tcp", "google.com:80")
	if err != nil {
		fmt.Println("Error:", err)
		return ""
	}
	defer conn.Close()

	localAddr := conn.LocalAddr().(*net.TCPAddr)
	interfaceName, err := getInterfaceName(localAddr.IP)
	if err != nil {
		fmt.Println("Error:", err)
		return ""
	}

	return interfaceName
}

func getInterfaceName(ip net.IP) (string, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return "", err
	}

	for _, iface := range ifaces {
		addrs, err := iface.Addrs()
		if err != nil {
			return "", err
		}

		for _, addr := range addrs {
			if ipnet, ok := addr.(*net.IPNet); ok {
				if ipnet.Contains(ip) {
					return iface.Name, nil
				}
			}
		}
	}

	return "", fmt.Errorf("could not determine internet interface")
}
