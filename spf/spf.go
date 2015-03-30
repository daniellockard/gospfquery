package spf

import (
	"errors"
	"fmt"
	"log"
	"net"
	"strings"
)
// SPF wraps all of our information into a nice little struct
type SPF struct {
	ValidIPRanges []string //Contains a list of valid CIDR ranges, as defined in the SPF record
	Domain        string   //The domain we're checking SPF for
	EmailAddress  string   //The email address we're pretending to send as
	IPAddress     string   //The IP address we're pretending to send from
	IsValid       bool     //Will be true if IPAddress is found in ValidIPRanges
	FoundCIDR     string   //The actual CIDR range our IP is found in
	allRecord     string
}

// New returns an SPF struct, given an email address and a source IP.
func New(emailAddress string, sourceIPAddress string) *SPF {
	spfObject := SPF{
		EmailAddress: emailAddress,
		IPAddress:    sourceIPAddress,
	}
	spfObject.Process()
	return &spfObject
}

// Process is where all the magic happens. It is called when we create a new SPF object.
// It can also be called again if you change the email address or source IP address.
func (spf *SPF) Process() {
	if spf.EmailAddress == "" {
		log.Fatal("Email Address is not defined")
	}
	if spf.IPAddress == "" {
		log.Fatal("Source IP Address is not defined")
	}
	var err error
	spf.Domain, err = processEmail(spf.EmailAddress)
	if err != nil {
		log.Fatal(err)
	}

	txtRecords, err := net.LookupTXT(spf.Domain)
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

	ips, err := getIPsForRecord(spf.Domain, spfRecord)
	if err != nil {
		log.Fatal(err)
	}
	spf.ValidIPRanges = ips

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
		ipAddress := net.ParseIP(spf.IPAddress)
		if cidrnet.Contains(ipAddress) {
			spf.IsValid = true
			spf.FoundCIDR = cidrnet.String()
		}
	}
}

// AllRecord returns a string containing "SoftFail", "Fail", or "None".
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

//Splits an email address into "username" and "domain" parts. It gives back the domain name.
func processEmail(email string) (string, error) {
	splitEmail := strings.Split(email, "@")
	if len(splitEmail) != 2 {
		return "", errors.New("Email address either has not enough or too many @ symbols")
	}
	domain := splitEmail[1]
	return domain, nil
}

//Locates the SPF record in the txt records, and returns the record as long as there aren't too many.
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
