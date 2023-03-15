package sniffer

import (
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"

	"github.com/PuerkitoBio/goquery"
)

func Abuseipdb(ip string) int {
	url := fmt.Sprintf("https://www.abuseipdb.com/check/%s", ip)

	client := &http.Client{}
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		fmt.Println("Error creating HTTP request:", err)
		return -1
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/88.0.4324.182 Safari/537.36")

	res, err := client.Do(req)
	if err != nil {
		fmt.Println("Error sending HTTP request:", err)
		return -1
	}
	defer res.Body.Close()

	doc, err := goquery.NewDocumentFromReader(res.Body)
	if err != nil {
		fmt.Println("Error parsing HTML response:", err)
		return -1
	}

	reportCountStr := doc.Find("#report-wrapper > div:nth-child(1) > div:nth-child(1) > div > p:nth-child(2) > b:nth-child(1)").First().Text()
	reportCount, err := strconv.Atoi(strings.TrimSpace(reportCountStr))
	if err != nil {
		fmt.Println("Error converting report count to integer:", err)
		return -1
	}

	return reportCount
}

func isPrivateIP(ip net.IP) bool {
	privateBlocks := []string{
		"10.0.0.0/8",
		"172.16.0.0/12",
		"192.168.0.0/16",
		"169.254.0.0/16",
		"127.0.0.0/8",
	}
	for _, block := range privateBlocks {
		_, privateBlock, _ := net.ParseCIDR(block)
		if privateBlock.Contains(ip) {
			return true
		}
	}
	return false
}

func resolveDNSName(ip net.IP) string {
	names, err := net.LookupAddr(ip.String())
	if err != nil {
		//fmt.Printf("Error: %s\n", err);
		return ""
	}
	return names[0]
}
