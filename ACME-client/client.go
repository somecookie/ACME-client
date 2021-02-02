package client

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	log "github.com/sirupsen/logrus"
	"gitlab.inf.ethz.ch/PRV-PERRIG/netsec-course/project-acme/netsec-2020-acme/rferreira-acme-project/dnsServer"
	"io/ioutil"
	"net/http"
	"strings"
	"time"
)

type Client struct {
	http.Client
	Directory    *Directory
	Nonce        string
	Account      *Account
	AccountURL   string
	JWK          *JWKES256
	SecretKey    *ecdsa.PrivateKey
	Order        *Order
	OrderUrl     string
	IPv4         string
	CertKey      *ecdsa.PrivateKey
	Certificates *Certs
	Certs []byte
}

func NewClient(ca_cert string) *Client {
	caCert, err := ioutil.ReadFile(ca_cert)
	if err != nil {
		log.Fatal(err)
	}
	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caCert)
	client := &Client{}
	client.Transport = &http.Transport{
		TLSClientConfig: &tls.Config{
			RootCAs: caCertPool,
		},
	}
	return client
}

func (cli *Client) GetDirectory(url string) error {
	resp, err := cli.Get(url)

	if err != nil {
		log.Error(err)
		return err
	} else if 400 <= resp.StatusCode && resp.StatusCode < 600 {
		logInfoBody(resp)
		return &HTTPError{
			StatusCode: resp.StatusCode,
		}
	}

	log.WithFields(log.Fields{
		"Protocol":    "GET",
		"To":          url,
		"Status code": resp.StatusCode,
	}).Info("Directory request")

	body, err := ioutil.ReadAll(resp.Body)

	if err != nil {
		log.Error(err)
		return err
	}

	var directory Directory
	err = json.Unmarshal(body, &directory)

	if err != nil {
		log.Error(err)
		return err
	}

	cli.Directory = &directory

	return nil
}

func (cli *Client) GetNewNonce() error {
	resp, err := cli.Head(cli.Directory.NewNonce)

	if err != nil {
		log.Error(err)
		return err
	} else if 400 <= resp.StatusCode && resp.StatusCode < 600 {
		logInfoBody(resp)
		return &HTTPError{
			StatusCode: resp.StatusCode,
		}
	}

	log.WithFields(log.Fields{
		"Protocol":    "Head",
		"To":          cli.Directory.NewNonce,
		"Status code": resp.StatusCode,
	}).Info("Nonce request")

	cli.Nonce = resp.Header["Replay-Nonce"][0]

	return nil
}

func (cli *Client) GetAccount() error {
	sk, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	if err != nil {
		log.Error(err)
		return err
	}

	cli.SecretKey = sk

	jwk := &JWKES256{
		Kty: "EC",
		Crv: "P-256",
		X:   strings.TrimRight(base64.URLEncoding.EncodeToString(sk.X.Bytes()), "="),
		Y:   strings.TrimRight(base64.URLEncoding.EncodeToString(sk.Y.Bytes()), "="),
	}

	cli.JWK = jwk

	jws := &JWS{
		Protected: ProtectedHeader{
			Alg:   "ES256",
			JWK:   jwk,
			Nonce: cli.Nonce,
			Url:   cli.Directory.NewAccount,
		},
		Payload: AccountPayload{
			TermsOfServiceAgreed: true,
			Contact:              []string{"mailto:admin@example.org"},
		},
	}

	resp, err := cli.sendJWS(jws, cli.Directory.NewAccount, "New account")
	if err != nil {
		return err
	}

	loc, err := resp.Location()

	if err != nil {
		log.Error(err)
		return err
	}

	cli.AccountURL = loc.String()

	body, err := ioutil.ReadAll(resp.Body)

	if err != nil {
		log.Error(err)
		return err
	}

	var acc Account
	err = json.Unmarshal(body, &acc)

	if err != nil {
		log.Error(err)
		return err
	}

	cli.Account = &acc

	return nil
}

func (cli *Client) HandleAuthorizations(challengeMode string, dnsserver *dnsServer.DNSServer) error {

	for _, authUrl := range cli.Order.Authorizations {
		jws := &JWS{
			Protected: ProtectedHeader{
				Alg:   "ES256",
				JWK:   nil,
				Kid:   cli.AccountURL,
				Nonce: cli.Nonce,
				Url:   authUrl,
			},
			Payload: nil,
		}

		resp, err := cli.sendJWS(jws, authUrl, "Authorization")
		if err != nil {
			log.Error(err)
			return err
		}

		body, err := ioutil.ReadAll(resp.Body)

		if err != nil {
			log.Error(err)
			return err
		}

		var auth Authorization
		err = json.Unmarshal(body, &auth)

		if err != nil {
			log.Error(err)
			return err
		}

		for _, challenge := range auth.Challenges {
			switch challenge.Type {
			case "dns-01":
				if challengeMode == "dns01" || auth.Wildcard {
					cli.DNSChallenge(challenge, auth.Identifier.Value, dnsserver, authUrl)
				}
			case "http-01":
				if challengeMode == "http01" {
					cli.HTTPChallenge(challenge, authUrl)
				}
			default:
				continue
			}
		}
	}
	return nil
}

func (cli *Client) Finalize() error {
	csr, err := cli.GetCSR()
	if err != nil {
		log.Error(err)
		return err
	}

	jws := &JWS{
		Protected: ProtectedHeader{
			Alg:   "ES256",
			Kid:   cli.AccountURL,
			Nonce: cli.Nonce,
			Url:   cli.Order.Finalize,
		},
		Payload: CSRPayload{Csr: csr},
	}

	resp, err := cli.sendJWS(jws, cli.Order.Finalize, "CSR")
	if err != nil {
		log.Error(err)
		return err
	}

	if err = cli.UpdateOrder(resp); err != nil {
		return err
	}

	for cli.Order.Status != "valid" {

		time.Sleep(1 * time.Second)

		jws := &JWS{
			Protected: ProtectedHeader{
				Alg:   "ES256",
				Kid:   cli.AccountURL,
				Nonce: cli.Nonce,
				Url:   cli.OrderUrl,
			},
			Payload: nil,
		}
		resp, err := cli.sendJWS(jws, cli.OrderUrl, "Order")
		if err != nil {
			log.Error(err)
			return err
		}

		if err = cli.UpdateOrder(resp); err != nil {
			return err
		}
	}

	return nil

}

func (cli *Client) GetNewOrder(domains []string) error {
	ids := make([]Identifier, len(domains))

	for i, domain := range domains {
		ids[i] = Identifier{
			Type:  "dns",
			Value: domain,
		}
	}
	before, after := getDate()
	order := Order{
		Identifiers: ids,
		NotBefore:   before,
		NotAfter:    after,
	}

	jws := &JWS{
		Protected: ProtectedHeader{
			Alg:   "ES256",
			Kid:   cli.AccountURL,
			Nonce: cli.Nonce,
			Url:   cli.Directory.NewOrder,
		},
		Payload: order,
	}

	resp, err := cli.sendJWS(jws, cli.Directory.NewOrder, "New order")
	if err != nil {
		log.Error(err)
		return err
	}

	if err = cli.UpdateOrder(resp); err != nil {
		return err
	}
	return nil
}

func (cli *Client) UpdateOrder(resp *http.Response) error {
	loc, err := resp.Location()

	if err != nil && err != http.ErrNoLocation {
		log.Error(err)
		return err
	} else if err == nil {
		cli.OrderUrl = loc.String()
	}

	body, err := ioutil.ReadAll(resp.Body)

	if err != nil {
		log.Error(err)
		return err
	}

	var ord Order
	err = json.Unmarshal(body, &ord)

	if err != nil {
		log.Error(err)
		return err
	}

	cli.Order = &ord
	return nil
}

func logInfoBody(resp *http.Response) {
	body, err := ioutil.ReadAll(resp.Body)

	if err != nil {
		log.Error(err)
	} else {
		log.Warn(string(body))
	}
}

func (cli *Client) sendJWS(jws *JWS, url string, requestType string) (*http.Response, error) {
	serializedJWS, err := jws.FlattenJSONSerialization(cli.SecretKey, requestType == "Order" || requestType == "Authorization" || requestType == "Challenge Verification" || requestType == "Download")

	if err != nil {
		return nil, err
	}

	resp, err := cli.Post(url, "application/jose+json", bytes.NewReader(serializedJWS))

	if err != nil {
		log.Error(err)
		return nil, err
	}else if resp.StatusCode == 400{
		body, err := ioutil.ReadAll(resp.Body)

		if err != nil {
			log.Error(err)
		}

		log.Warn(string(body))

		var errMsg Error
		if err = json.Unmarshal(body, &errMsg); err != nil{
			log.Error(err)
		}

		if errMsg.Type == "urn:ietf:params:acme:error:malformed" && errMsg.Detail == "JWS verification error: square/go-jose: error in cryptographic primitive"{
			return cli.sendJWS(jws, url, requestType)
		}

	} else if 400 < resp.StatusCode && resp.StatusCode < 600 {
		logInfoBody(resp)
		return nil, &HTTPError{
			StatusCode: resp.StatusCode,
		}
	}

	log.WithFields(log.Fields{
		"Protocol":    "Post",
		"To":          url,
		"Status code": resp.StatusCode,
	}).Info(requestType + " request")

	if nonce, ok := resp.Header["Replay-Nonce"]; ok {
		cli.Nonce = nonce[0]
	} else {
		log.Warn("No new Nonce")
	}

	return resp, nil
}

func (cli *Client) DownloadCert() error {
	jws := &JWS{
		Protected: ProtectedHeader{
			Alg:   "ES256",
			Kid:   cli.AccountURL,
			Nonce: cli.Nonce,
			Url:   cli.Order.Certificate,
		},
		Payload: nil,
	}

	resp, err := cli.sendJWS(jws, cli.Order.Certificate, "Download")
	if err != nil {
		log.Error(err)
		return err
	}

	body, err := ioutil.ReadAll(resp.Body)

	if err != nil {
		log.Error(err)
	}

	certs := strings.Split(string(body), "-----BEGIN CERTIFICATE-----\n")[1:]

	certificates := &Certs{
		EndEntity: "-----BEGIN CERTIFICATE-----\n" + certs[0],
		Issuer:    "-----BEGIN CERTIFICATE-----\n" + certs[1],
	}

	if len(certs) > 2 {
		certificates.Others = make([]string, 0, len(certs)-2)
		for _, cert := range certs {
			certificates.Others = append(certificates.Others, "-----BEGIN CERTIFICATE-----\n"+cert)
		}
	}

	cli.Certificates = certificates
	cli.Certs = body
	return nil
}

func (cli *Client) Revoke() error {
	cert := strings.Split(cli.Certificates.EndEntity, "\n")
	certStr := strings.Join(cert[1:len(cert)-2], "")

	certBytes, err := base64.StdEncoding.DecodeString(certStr)

	if err != nil {
		log.Error(err)
		return err
	}

	certStr = strings.TrimRight(base64.URLEncoding.EncodeToString(certBytes), "=")

	jws := &JWS{
		Protected: ProtectedHeader{
			Alg:   "ES256",
			Kid:   cli.AccountURL,
			Nonce: cli.Nonce,
			Url:   cli.Directory.RevokeCert,
		},
		Payload: Revocation{Certificate: certStr},
	}
	_, err = cli.sendJWS(jws, cli.Directory.RevokeCert, "Revocation")
	if  err != nil{
		log.Error(err)
		return err
	}

	return nil
}

func getDate() (string, string) {
	current := time.Now()
	currentStr := current.Format(time.RFC3339)
	offset := time.Hour * 24 * 15
	next := current.Add(offset)
	nextStr := next.Format(time.RFC3339)
	return currentStr, nextStr
}
