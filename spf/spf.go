package spf

import (
	"log"
	"net"
	"strings"
	"fmt"
	"errors"
)

type SPF struct {
	validIPRanges []string
	domain string
	emailAddress string
	sourceIPAddress string
	isFound bool
	foundCIDR string
	allRecord string
}

func New(emailAddress string, sourceIPAddress string) *SPF {
	spfObject := SPF{
		emailAddress: emailAddress,
		sourceIPAddress: sourceIPAddress,
	}
	spfObject.Process()
	return &spfObject
}

func (spf *SPF) Process() {
	if spf.emailAddress == "" {
		log.Fatal("Email Address is not defined")
	}
	if spf.sourceIPAddress == "" {
		log.Fatal("Source IP Address is not defined")
	}
	var err error
	spf.domain, err = processEmail(spf.emailAddress)
	if err != nil {
		log.Fatal(err)
	}

	txtRecords, err := net.LookupTXT(spf.domain)
	if err != nil {
		log.Fatal(err)
	}

	spfRecordList, err := findSPFRecord(txtRecords)
	if err != nil {
		log.Fatal(err)
	}

	spfRecord := spfRecordList[0]
	splitSPFRecord := strings.Split(spfRecord, " ")
	allRecord := splitSPFRecord[len(splitSPFRecord)-1]
	allRecordSplit := strings.Split(allRecord, "a")
	allRecord = allRecordSplit[0]
	spf.allRecord = allRecord

	ips, err := getIPsForRecord(spf.domain, spfRecord)
	if err != nil {
		log.Fatal(err)
	}
	spf.validIPRanges = ips

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
		ipAddress := net.ParseIP(spf.sourceIPAddress)
		if cidrnet.Contains(ipAddress) {
			spf.isFound = true
			spf.foundCIDR = cidrnet.String()
		}
	}
}

func (spf *SPF) IsValid() bool {
	return spf.isFound
}

func (spf *SPF) IPAddress() string {
	return spf.sourceIPAddress
}

func (spf *SPF) Domain() string {
	return spf.domain
}

func (spf *SPF) AllRecord() string {
	allRecord := spf.allRecord
	if allRecord == "~" {
		return "SoftFail"
	} else if allRecord == "-" {
		return "Fail"
	} else {
		return "None"
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

func findSPFRecord(txtRecords []string) ([]string, error) {
	var spfRecords []string
	for _, record := range txtRecords {
		if strings.HasPrefix(record, "v=spf1") {
			spfRecords = append(spfRecords, record)
		}
	}
	if len(spfRecords) == 0 || len(spfRecords) > 1 {
		return []string{}, errors.New("Too many SPF records found")
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
			spfRecord := spfRecordList[0]
			recursiveList, err := getIPsForRecord(record, spfRecord)
			for _, element := range recursiveList {
				cidrIPs = append(cidrIPs, element)
			}
			continue
		} else if strings.ToLower(element) == "a" || strings.ToLower(element) == "mx" {
			otherRecord, err := parseOtherRecord(domain, element)
			if err != nil {
				return []string{}, err
			}
			for _, element := range otherRecord {
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
			for _, listElement := range MXARecords {
				ipList = append(ipList, listElement)
			}

		}
		return ipList, nil
	}
	return []string{}, errors.New("Unknown Record for SPF")
}


