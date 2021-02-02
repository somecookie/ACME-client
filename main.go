package main

import (
	"context"
	"github.com/jessevdk/go-flags"
	log "github.com/sirupsen/logrus"
	client "gitlab.inf.ethz.ch/PRV-PERRIG/netsec-course/project-acme/netsec-2020-acme/rferreira-acme-project/ACME-client"
	"gitlab.inf.ethz.ch/PRV-PERRIG/netsec-course/project-acme/netsec-2020-acme/rferreira-acme-project/dnsServer"
	"net/http"
	"os"
	"sync"
)

var opts struct {
	ChallengeMode string   `required:"true" choice:"dns01" choice:"http01" long:"cmd" description:"Indicates which ACME challenge type the client should perform. Valid options are dns01 and http01 for the dnsServer-01 and http-01 challenges, respectively."`
	DirURL        string   `required:"true" long:"dir" description:"Directory URL of the ACME server"`
	IPv4Addr      string   `required:"true" long:"record" description:"IPv4 address which must be returned by your DNS server for all A-record queries"`
	Domain        []string `required:"true" long:"domain" description:"Domain for  which to request the certificate. If multiple --domain flags are present, a single certificate for multiple domains should be requested. Wildcard domains have no special flag and are simply denoted by, e.g., *.example.net."`
	Revoke        bool     `long:"revoke" description:"If present, your application should immediately revoke the certificate after obtaining it. In both cases, your application should start its HTTPS server and set it up to use the newly obtained certificate."`
	CACert        string   `long:"cert" description:"Path to the certificate of the CA"`
}

var wg = &sync.WaitGroup{}

func init() {
	_, err := flags.Parse(&opts)

	if err != nil {
		log.Fatal(err)
	}
}

func main() {

	log.WithFields(log.Fields{
		"Challenge mode": opts.ChallengeMode,
		"Dir URL": opts.DirURL,
		"IPv4 address": opts.IPv4Addr,
		"Domains": opts.Domain,
		"Revoke":opts.Revoke,
	}).Info("Starting ACME protocol")

	if opts.CACert == ""{
		opts.CACert = "pebble.minica.pem"
	}
	cli := client.NewClient(opts.CACert)
	cli.IPv4 = opts.IPv4Addr

	wg.Add(1)

	var dnsserver *dnsServer.DNSServer
	var httpsServer *http.Server
	stop := false

	go func() {
		defer wg.Done()

		killSwitch := make(chan bool)
		killServer := client.GetKillSwitch(cli, killSwitch)

		go func() {
			if err := killServer.ListenAndServe(); err != nil {
				log.Error("Failed to set udp listener %s\n", err.Error())
			}
		}()
		for kill := range killSwitch {
			if kill {
				if dnsserver != nil {
					dnsserver.Shutdown()
				}

				if httpsServer != nil {
					httpsServer.Shutdown(context.TODO())
				}

				if killServer != nil {
					killServer.Shutdown(context.TODO())
				}

				os.Exit(1)
			}
		}

	}()

	dnsserver = dnsServer.InitDNSServer(opts.IPv4Addr)

	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := dnsserver.ListenAndServe(); err != nil {
			log.Error("Failed to set udp listener %s\n", err.Error())
		}

	}()

	if err := cli.GetDirectory(opts.DirURL); err != nil || stop {
		panic(err)
	}

	if err := cli.GetNewNonce(); err != nil || stop {
		panic(err)
	}

	if err := cli.GetAccount(); err != nil || stop {
		panic(err)
	}

	if err := cli.GetNewOrder(opts.Domain); err != nil || stop {
		panic(err)
	}

	if err := cli.HandleAuthorizations(opts.ChallengeMode, dnsserver); err != nil || stop {
		panic(err)
	}

	if err := cli.Finalize(); err != nil || stop {
		panic(err)
	}

	if err := cli.DownloadCert(); err != nil || stop {
		panic(err)
	}

	httpsServer, err := client.GetHTTPS(cli)

	if err != nil {
		panic(err)
	}

	wg.Add(1)
	go func() {
		defer wg.Done()

		if err := httpsServer.ListenAndServeTLS("", ""); err != nil {
			log.Error("Failed to set udp listener %s\n", err.Error())
		}
	}()

	if opts.Revoke {
		if err := cli.Revoke(); err != nil || stop {
			panic(err)
		}
	}
	wg.Wait()

}
