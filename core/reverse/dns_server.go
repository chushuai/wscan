/**
* @Author: shaochuyu
* @Date: 5/7/2022 11:30
 */
package reverse

import (
	"errors"
	"fmt"
	"github.com/miekg/dns"
	"golang.org/x/net/dns/dnsmessage"
	"log"
	"net"
	"strings"
	"sync"
	"time"
	"wscan/core/utils"
	logger "wscan/core/utils/log"
)

type DNSServer struct {
	*dns.Server
	config                *Config
	db                    *DB
	internalGroupEventMap *sync.Map
}

// NewDNSServer creates a new DNSServer instance.
func NewDNSServer(config *Config, db *DB) (*DNSServer, error) {
	dnsServer := &DNSServer{
		config: config,
		db:     db,
	}

	if config.DNSServerConfig.Enabled {
		server := &dns.Server{Addr: net.JoinHostPort(config.DNSServerConfig.ListenIP, "533"), Net: "udp"}
		dnsServer.Server = server
	}

	return dnsServer, nil
}

func GenRandDomain(config *Config) (string, error) {
	if config.DNSServerConfig.Enabled == false {
		return "", errors.New("")
	}
	if config.DNSServerConfig.Domain != "" {
		return fmt.Sprintf("%s.%s", utils.RandLetters(8), config.DNSServerConfig.Domain), nil
	}
	return "", errors.New("DNSLOG configuration error")
}

// Start starts the DNS server.
func (ds *DNSServer) Start() {
	if ds.config.DNSServerConfig.ListenIP == "" {
		ds.config.DNSServerConfig.ListenIP = "0.0.0.0"
	}

	dnsIP := net.ParseIP(ds.config.DNSServerConfig.ListenIP)
	if dnsIP == nil {
		logger.Fatal("DNS Server ip format error")
	}
	logger.Infof("reverse dns listen 0.0.0.0:53")
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: dnsIP, Port: 53})
	if err != nil {
		log.Fatal(err.Error())
	}
	defer conn.Close()

	for {
		buf := make([]byte, 512)
		_, addr, _ := conn.ReadFromUDP(buf)
		var msg dnsmessage.Message
		if err := msg.Unpack(buf); err != nil {
			fmt.Println(err)
			continue
		}
		go ds.serverDNS(addr, conn, msg)
	}
}

// Stop stops the DNS server.
func (ds *DNSServer) Stop() {
	if ds.Server != nil {
		ds.Server.Shutdown()
	}
}

// handleDNSRequest handles DNS requests.
func (ds *DNSServer) handleDNSRequest(w dns.ResponseWriter, r *dns.Msg) {
	// Implement DNS request handling logic here
	// You can use ds.db or ds.config as needed
}

func (ds *DNSServer) serverDNS(addr *net.UDPAddr, conn *net.UDPConn, msg dnsmessage.Message) {
	if len(msg.Questions) < 1 {
		return
	}
	question := msg.Questions[0]
	var (
		queryNameStr = question.Name.String()
		queryType    = question.Type
		queryName, _ = dnsmessage.NewName(queryNameStr)
		resource     dnsmessage.Resource
		// queryDoamin  = strings.Split(strings.Replace(queryNameStr, fmt.Sprintf(".%s.", ds.config.DNSServerConfig.Domain), "", 1), ".")
	)

	//域名过滤
	if strings.Contains(queryNameStr, ds.config.DNSServerConfig.Domain) {
		D.Set(ds.config.GetUserDir(ds.config.Token), DnsInfo{
			Type:      "DNS",
			Subdomain: queryNameStr[:len(queryNameStr)-1],
			Ipaddress: addr.IP.String(),
			Time:      time.Now().Unix(),
		})
	}

	fmt.Println(D)
	switch queryType {
	case dnsmessage.TypeA:
		resource = NewAResource(queryName, [4]byte{127, 0, 0, 1})
	default:
		resource = NewAResource(queryName, [4]byte{127, 0, 0, 1})
	}
	// send response
	msg.Response = true
	msg.Answers = append(msg.Answers, resource)
	ds.Response(addr, conn, msg)
}

// Response return
func (ds *DNSServer) Response(addr *net.UDPAddr, conn *net.UDPConn, msg dnsmessage.Message) {
	packed, err := msg.Pack()
	if err != nil {
		logger.Error(err)
		return
	}
	if _, err := conn.WriteToUDP(packed, addr); err != nil {
		fmt.Println(err)
	}
}

func NewAResource(query dnsmessage.Name, a [4]byte) dnsmessage.Resource {
	return dnsmessage.Resource{
		Header: dnsmessage.ResourceHeader{
			Name:  query,
			Class: dnsmessage.ClassINET,
			TTL:   0,
		},
		Body: &dnsmessage.AResource{
			A: a,
		},
	}
}
