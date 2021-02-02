package dnsServer

import (
	"fmt"
	"github.com/miekg/dns"
	log "github.com/sirupsen/logrus"
	"net"
	"sync"
)

var ipv4 string

var DNSChallenges map[string]string
var mutex *sync.RWMutex

type handler struct{}
type DNSServer struct {
	*dns.Server
	KeyAuthChan chan KeyAuthDomain
}

type KeyAuthDomain struct {
	KeyAuthDigest string
	Domain        string
	Delete        bool
}

func InitDNSServer(ip string) *DNSServer {
	ipv4 = ip
	srv := &DNSServer{}
	srv.Server = &dns.Server{Addr: ip+":10053", Net: "udp"}
	srv.Handler = &handler{}
	srv.KeyAuthChan = make(chan KeyAuthDomain)

	mutex = &sync.RWMutex{}
	DNSChallenges = make(map[string]string)

	go func() {
		for keyAuthDomain := range srv.KeyAuthChan {
			mutex.Lock()
			if keyAuthDomain.Delete {
				delete(DNSChallenges, keyAuthDomain.Domain)
				log.Info("Challenge for ", keyAuthDomain.Domain, " removed")
			} else {
				DNSChallenges[keyAuthDomain.Domain] = keyAuthDomain.KeyAuthDigest
				log.Info("Challenge for ", keyAuthDomain.Domain, " added")
			}
			mutex.Unlock()
		}
	}()

	return srv
}

func (handler *handler) ServeDNS(writer dns.ResponseWriter, msg *dns.Msg) {
	reply := dns.Msg{}
	reply.SetReply(msg)

	reply.Authoritative = true
	requestedDomain := dns.Fqdn(reply.Question[0].Name)



	switch reply.Question[0].Qtype {
	case dns.TypeA:
		log.Info("DNS Type A request for ", requestedDomain)
		reply.Answer = append(reply.Answer, &dns.A{
			Hdr: dns.RR_Header{
				Name:   requestedDomain,
				Rrtype: dns.TypeA,
				Class:  dns.ClassINET,
				Ttl:    365,
			},
			A: net.ParseIP(ipv4),
		})
	case dns.TypeTXT:
		log.Info("DNS Type TXT request for ", requestedDomain)

		mutex.RLock()
		if keyAuth, ok := DNSChallenges[requestedDomain]; ok{
			reply.Answer = append(reply.Answer, &dns.TXT{
				Hdr: dns.RR_Header{
					Name:   requestedDomain,
					Rrtype: dns.TypeTXT,
					Class:  dns.ClassINET,
					Ttl:    365,
				},
				Txt: []string{keyAuth},
			})
		}
		mutex.RUnlock()
	}
	if err := writer.WriteMsg(&reply); err != nil {
		fmt.Println(err)
	}

}
