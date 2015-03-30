package main

import (
	"flag"
	"fmt"
	"github.com/daniellockard/gospfquery/spf"
	"log"
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

	spfObject := spf.New(email, ipAddr)

	if spfObject.IsValid {
		fmt.Printf("Your SPF record is allowed to send from %s for domain %s\n", spfObject.IPAddress, spfObject.Domain)
	} else {
		if spfObject.AllRecord() == "SoftFail" || spfObject.AllRecord() == "None" {
			fmt.Printf("The IP (%s) was not found as a valid sender for your SPF record, but your \"ALL\" record is %s, so sending would be permitted\n", spfObject.IPAddress, spfObject.AllRecord())
		} else {
			fmt.Printf("The IP (%s) was not found as a valid sender for your SPF record, and your \"ALL\" record is %s, so sending would NOT be permitted\n", spfObject.IPAddress, spfObject.AllRecord())
		}
	}
}
