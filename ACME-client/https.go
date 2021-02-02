package client

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	log "github.com/sirupsen/logrus"
	"net/http"
)

func GetHTTPS(cli *Client) (*http.Server, error) {
	serverAddr := cli.IPv4 + ":5001"

	log.Info("Creating HTTPS server running on ", serverAddr)

	x509Encoded, err := x509.MarshalECPrivateKey(cli.CertKey)

	if err != nil {
		log.Error(err)
		return nil, err
	}
	pemEncoded := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: x509Encoded})

	cert, err := tls.X509KeyPair(cli.Certs, pemEncoded)

	if err != nil {
		log.Error(err)
		return nil, err
	}

	srv := &http.Server{
		Addr: serverAddr,
		TLSConfig: &tls.Config{
			Certificates: []tls.Certificate{cert},
		},
	}

	http.HandleFunc("/", RootHandler)

	return srv, nil
}

func RootHandler(writer http.ResponseWriter, request *http.Request) {
	switch request.Method {
	case "GET":
		log.Info(fmt.Sprintf("%s %s %s %d %d %s %s", request.Method, request.URL, request.Proto, request.ProtoMajor, request.ProtoMinor, request.UserAgent(), request.RemoteAddr))
		writer.WriteHeader(http.StatusOK)
	default:
		writer.WriteHeader(http.StatusNotFound)
	}
}