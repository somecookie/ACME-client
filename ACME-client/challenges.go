package client

import (
	"context"
	"crypto"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/miekg/dns"
	log "github.com/sirupsen/logrus"
	dnsServer "gitlab.inf.ethz.ch/PRV-PERRIG/netsec-course/project-acme/netsec-2020-acme/rferreira-acme-project/dnsServer"
	"io/ioutil"
	"net/http"
	"strings"
	"time"
)

var token, keyAuth string

func (cli *Client) DNSChallenge(challenge Challenge, domain string, dnsserver *dnsServer.DNSServer, url string) error {
	var err error

	token, keyAuth, err = cli.GetKeyAuth(challenge)

	if err != nil{
		log.Error(err)
		return err
	}

	hasher := crypto.SHA256.New()
	_, err = hasher.Write([]byte(keyAuth))

	if err != nil {
		log.Error(err)
		return err
	}

	keyAuthDigest := strings.TrimRight(base64.URLEncoding.EncodeToString(hasher.Sum(nil)), "=")

	dom := domain

	if strings.HasPrefix(domain, "*."){
		dom = domain[2:]
	}

	dom = fmt.Sprintf("_acme-challenge.%s", dom)

	dnsserver.KeyAuthChan <- dnsServer.KeyAuthDomain{
		KeyAuthDigest: keyAuthDigest,
		Domain:        dns.Fqdn(dom),
		Delete:        false,
	}

	cli.WaitUntilValid(url, challenge)

	dnsserver.KeyAuthChan <- dnsServer.KeyAuthDomain{
		KeyAuthDigest: keyAuthDigest,
		Domain:        dns.Fqdn(dom),
		Delete:        true,
	}



	return nil
}

func (cli *Client) HTTPChallenge(challenge Challenge, authURL string) error {

	var err error

	token, keyAuth, err = cli.GetKeyAuth(challenge)

	if err != nil{
		log.Error(err)
		return err
	}

	srv := cli.StartHTTPChallengeServer()

	if err := cli.WaitUntilValid(authURL, challenge); err != nil{
		log.Error(err)
		return err
	}

	if err := srv.Shutdown(context.TODO()); err != nil {
		log.Error(err)
	}

	return nil

}

func (cli *Client) WaitUntilValid(authURL string, challenge Challenge) error {

	jws := &JWS{
		Protected: ProtectedHeader{
			Alg:   "ES256",
			Kid:   cli.AccountURL,
			Nonce: cli.Nonce,
			Url:   challenge.Url,
		},
		Payload: Empty{},
	}

	_, err := cli.sendJWS(jws, challenge.Url, "Acknowledge challenge")
	if err != nil {
		log.Error(err)
		return err
	}

	for {
		time.Sleep(3 * time.Second)

		jws := &JWS{
			Protected: ProtectedHeader{
				Alg:   "ES256",
				Kid:   cli.AccountURL,
				Nonce: cli.Nonce,
				Url:   authURL,
			},
			Payload: "",
		}

		resp, err := cli.sendJWS(jws, authURL, "Challenge Verification")
		if err != nil {
			log.Error(err)

		} else if 400 <= resp.StatusCode && resp.StatusCode < 600 {
			logInfoBody(resp)
			continue
		}

		body, err := ioutil.ReadAll(resp.Body)

		if err != nil {
			log.Error(err)
			continue
		}

		var auth Authorization
		err = json.Unmarshal(body, &auth)

		if err != nil {
			log.Error(err)
			continue
		}

		if auth.Status == "valid" {
			log.Info("Challenge ", challenge.Token, " completed")
			return nil
		}else{
			log.Info("Status of the challenge: ", auth.Status)
		}
	}
}

func (cli *Client) StartHTTPChallengeServer() *http.Server {
	serverAddr := cli.IPv4+":5002"
	path := "/.well-known/acme-challenge/"+token
	log.Info("Starting HTTP challenge server: ", "http://"+serverAddr+path)

	srv := &http.Server{Addr: serverAddr}
	http.HandleFunc(path, HttpChallengeHandler)

	go func(){
		if err := srv.ListenAndServe(); err != http.ErrServerClosed{
			log.Fatal(err)
		}
	}()

	return srv

}

func HttpChallengeHandler(writer http.ResponseWriter, request *http.Request) {
	if request.Method == "GET"{
		log.Info("GET from ", request.RemoteAddr)
		writer.WriteHeader(http.StatusOK)
		writer.Write([]byte(keyAuth))
	}else{
		writer.WriteHeader(http.StatusNotFound)
	}
}

func (cli *Client) GetKeyAuth(challenge Challenge) (string,string, error) {

	keyAuth, err := cli.JWK.GetKeyAuth(challenge.Token)

	if err != nil{
		log.Error(err)
		return "", "", err
	}

	return challenge.Token, keyAuth, nil
}
