package main

import (
	"container/list"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"strings"
)

type found struct {
	isFound   bool
	cidr      string
	allRecord string
}

func main() {

	var ipAddr string
	var email string
	flag.StringVar(&ipAddr, "ip-address", "", "The IP to check")

	flag.StringVar(&email, "id", "", "The email address to check")

	flag.Parse()

	if ipAddr == "" {
		log.Fatal("IP Address not defined")
	}

	if email == "" {
		log.Fatal("Email not defined")
	}

	domain, err := processEmail(email)
	if err != nil {
		log.Fatal(err)
	}

	txtRecords, err := net.LookupTXT(domain)
	if err != nil {
		log.Fatal(err)
	}

	spfRecordList, err := findSPFRecord(txtRecords)
	if err != nil {
		log.Fatal(err)
	}

	spfRecord := spfRecordList.Front()
	splitSPFRecord := strings.Split(spfRecord.Value.(string), " ")
	allRecord := splitSPFRecord[len(splitSPFRecord)-1]
	allRecordSplit := strings.Split(allRecord, "a")
	allRecord = allRecordSplit[0]

	ips, err := getIPsForRecord(domain, spfRecord.Value.(string))
	if err != nil {
		log.Fatal(err)
	}

	foundRecord := found{isFound: false, cidr: "", allRecord: allRecord}
	for _, element := range ips {
		elementWithCidr := element
		if !strings.Contains(elementWithCidr, "/") {
			if !strings.Contains(elementWithCidr, ":") {
				elementWithCidr = fmt.Sprintf("%s/32", elementWithCidr)
			} else {
				elementWithCidr = fmt.Sprintf("%s/128", elementWithCidr)
			}
		}
		_, cidrnet, err := net.ParseCIDR(elementWithCidr)
		if err != nil {
			log.Fatal(err)
		}
		ipAddress := net.ParseIP(ipAddr)
		if cidrnet.Contains(ipAddress) {
			foundRecord.isFound = true
			foundRecord.cidr = cidrnet.String()
		}
	}
	if foundRecord.isFound {
		fmt.Printf("IP Sent from is in %s.  This email will be allowed to send.\n", foundRecord.cidr)
	} else {
		switch allRecord {
		case "-":
			fmt.Printf("IP Sent from is NOT found. This email would NOT be allowed as your \"ALL\" authorization is set to \"-all\"\n")
		case "~":
			fmt.Printf("IP Sent from is NOT found. This email would be allowed, but would be a \"SoftFail\" as your authorization is set to \"~all\"\n")
		}
	}

}

func processEmail(email string) (string, error) {
	split_email := strings.Split(email, "@")
	if len(split_email) != 2 {
		return "", errors.New("Email address either has not enough or too many @ symbols")
	}
	domain := split_email[1]
	return domain, nil
}

func findSPFRecord(txtRecords []string) (*list.List, error) {
	spfRecords := list.New()
	for _, record := range txtRecords {
		if strings.HasPrefix(record, "v=spf1") {
			spfRecords.PushBack(record)
		}
	}
	if spfRecords.Len() == 0 || spfRecords.Len() > 1 {
		return list.New(), errors.New("Too many SPF records found")
	}
	return spfRecords, nil
}

func getIPsForRecord(domain string, record string) ([]string, error) {
	var spfSections []string
	var cidrIPs []string
	splitTextRecords := strings.Split(record, " ")
	for _, element := range splitTextRecords {
		spfSections = append(spfSections, element)
	}
	for _, element := range spfSections {
		if strings.HasPrefix("v=spf1", element) {
			continue
		} else if strings.HasPrefix(element, "ip4") {
			cidr := strings.Replace(element, "ip4:", "", -1)
			cidrIPs = append(cidrIPs, cidr)
			continue
		} else if strings.HasPrefix(element, "include") {
			record := strings.Replace(element, "include:", "", -1)
			txtRecords, err := net.LookupTXT(record)
			if err != nil {
				return []string{}, err
			}
			spfRecordList, err := findSPFRecord(txtRecords)
			if err != nil {
				return []string{}, err
			}
			spfRecord := spfRecordList.Front()
			recursiveList, err := getIPsForRecord(record, spfRecord.Value.(string))
			for _, element := range recursiveList {
				cidrIPs = append(cidrIPs, element)
			}
			continue
		} else if strings.ToLower(element) == "a" || strings.ToLower(element) == "mx" {
			otherRecord, err := parseOtherRecord(domain, element)
			if err != nil {
				return []string{}, err
			}
			for _,element := range otherRecord {
				cidrIPs = append(cidrIPs, element)
			}
			continue
		} else {
			continue
		}
	}
	return cidrIPs, nil
}

func parseOtherRecord(domain string, record string) ([]string, error) {
	var ipList []string
	if record == "a" {
		ip, err := net.LookupIP(domain)
		if err != nil {
			return []string{}, err
		}
		for _, element := range ip {
			ipList = append(ipList, element.String())
		}
		return ipList, nil
	} else if record == "mx" {
		ip, err := net.LookupMX(domain)
		if err != nil {
			return []string{}, err
		}
		for _, element := range ip {
			MXARecords, err := parseOtherRecord(element.Host, "a")
			if err != nil {
				return []string{}, err
			}
			for _,listElement := range MXARecords {
				ipList = append(ipList,listElement)
			}

		}
		return ipList, nil
	}
	return []string{}, errors.New("Unknown Record for SPF")
}
