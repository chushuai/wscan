/**
* @Author: shaochuyu
* @Date: 5/7/2022 11:30
 */
package reverse

import (
	"errors"
	"github.com/miekg/dns"
	"golang.org/x/net/context"
	"net"
	"strings"
	"sync"
	"time"
	logger "wscan/core/utils/log"
)

type DNSServer struct {
	*dns.Server
	config                *Config
	db                    *DB
	internalGroupEventMap *sync.Map
}

func NewDNSServer(config *Config, internalGroupEventMap *sync.Map, db *DB) (*DNSServer, error) {
	dnsServer := &DNSServer{
		config:                config,
		db:                    db,
		internalGroupEventMap: internalGroupEventMap,
	}
	if config.DNSServerConfig.Enabled {
		dnsServer.Server = &dns.Server{Addr: net.JoinHostPort(config.DNSServerConfig.ListenIP, "53"),
			Net: "udp", Handler: dnsServer}
	} else {
		return nil, errors.New("DNSServer disabled")
	}
	return dnsServer, nil
}

func (ds *DNSServer) Start() {
	logger.Info("starting reverse dns server")
	if err := ds.ListenAndServe(); err != nil {
		logger.Fatal(err)
	}
}

// EventSource string `json:"event_source"`
//
//	EventType   string `json:"event_type"`
//	Request     string `json:"request"`
//	RemoteAddr  string `json:"remote_addr"`
//
// hashedToken, groupID, unitID, oobData
func (d *DNSServer) ServeDNSQuery(groupID string, unitID string, eventSource string, remoteAddr string, request string, r *dns.Msg) {
	// utils.TimeStampNano()
	// public
	// internalintprod

	ev := &Event{
		GroupID:     groupID,
		UnitID:      unitID,
		EventType:   "dns",
		EventSource: eventSource,
		RemoteAddr:  remoteAddr,
		Request:     request,
		TimeStamp:   time.Now().UnixMilli(),
	}
	d.db.storeEvent(ev)
	d.internalGroupEventMap.Store(groupID, ev)

}

func (d *DNSServer) ServeDNS(w dns.ResponseWriter, r *dns.Msg) {

	if len(r.Question) == 0 {
		return
	}

	if r.Opcode != dns.OpcodeQuery {
		return
	}
	question := r.Question[0]
	logger.Infof("[oob][dns] query '%s' from '%s'", question.Name, w.RemoteAddr().String())
	dnsName := strings.Trim(question.Name, ".")
	hashedToken, groupID, unitID, _, err := parseDomainInfo(dnsName, d.config.DNSServerConfig.Domain)
	if err == nil {
		if generateHashedToken(d.config.Token, groupID, unitID) == hashedToken {
			d.ServeDNSQuery(groupID, unitID, "internal",
				w.RemoteAddr().String(), question.Name, r)
		}
	}

	rrs := make([]dns.RR, 0)
	rrHeader := dns.RR_Header{
		Name:   question.Name,
		Rrtype: question.Qtype,
		Class:  dns.ClassINET,
		Ttl:    10,
	}
	dnsResponseConfig := d.db.getDNSResponse(groupID)
	switch question.Qtype {
	case dns.TypeA:
		if dnsResponseConfig != nil && len(dnsResponseConfig.DNSResponse.A) > 0 {
			for _, a := range dnsResponseConfig.DNSResponse.A {
				rrs = append(rrs, &dns.A{Hdr: dns.RR_Header{
					Name:   question.Name,
					Rrtype: question.Qtype,
					Class:  dns.ClassINET,
					Ttl:    a.TTL,
				}, A: net.ParseIP(a.Value)})
			}
		} else {
			rrs = append(rrs, &dns.A{Hdr: rrHeader, A: net.ParseIP("127.0.0.1")})
		}
	case dns.TypeAAAA:
		if dnsResponseConfig != nil && len(dnsResponseConfig.DNSResponse.AAAA) > 0 {
			for _, aaaa := range dnsResponseConfig.DNSResponse.A {
				rrs = append(rrs, &dns.A{Hdr: dns.RR_Header{
					Name:   question.Name,
					Rrtype: question.Qtype,
					Class:  dns.ClassINET,
					Ttl:    aaaa.TTL,
				}, A: net.ParseIP(aaaa.Value)})
			}
		} else {
			rrs = append(rrs, &dns.A{Hdr: rrHeader, A: net.ParseIP(":1")})
		}
	case dns.TypeTXT:
		if dnsResponseConfig != nil && len(dnsResponseConfig.DNSResponse.TXT) > 0 {
			for _, txt := range dnsResponseConfig.DNSResponse.TXT {
				rrs = append(rrs, &dns.TXT{Hdr: dns.RR_Header{
					Name:   question.Name,
					Rrtype: question.Qtype,
					Class:  dns.ClassINET,
					Ttl:    txt.TTL,
				}, Txt: []string{txt.Value}})
			}
		} else {
			rrs = append(rrs, &dns.TXT{Hdr: rrHeader, Txt: []string{}})
		}
	default:
		dns.HandleFailed(w, r)
		return
	}
	m := new(dns.Msg)
	m.SetReply(r)
	m.Compress = false
	m.Authoritative = true
	m.Answer = append(m.Answer, rrs...)
	if err := w.WriteMsg(m); err != nil {
		logger.Warnf("[dns] write message fail error: %s \n", err)
	}
}

func (ds *DNSServer) ActivateAndServe() error {
	return ds.Server.ActivateAndServe()
}

func (ds *DNSServer) ListenAndServe() error {
	return ds.Server.ListenAndServe()
}

func (ds *DNSServer) Shutdown() error {
	return ds.Server.Shutdown()
}

func (ds *DNSServer) ShutdownContext(ctx context.Context) error {
	return ds.Server.ShutdownContext(ctx)
}

func (ds *DNSServer) Stop() {
	if ds.Server != nil {
		ds.Server.Shutdown()
	}
}
