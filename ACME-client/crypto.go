package client

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	log "github.com/sirupsen/logrus"
	"strings"
)

type JWKES256 struct {
	Crv string `json:"crv"`
	Kty string `json:"kty"`
	X   string `json:"x"`
	Y   string `json:"y"`
}

type JWS struct {
	Protected ProtectedHeader
	Payload   interface{}
	Signature string
}

type AccountPayload struct {
	TermsOfServiceAgreed bool
	Contact              []string
}

type ProtectedHeader struct {
	Alg   string    `json:"alg"`
	JWK   *JWKES256 `json:"jwk"`
	Kid   string    `json:"kid"`
	Nonce string    `json:"nonce"`
	Url   string    `json:"url"`
}

type SerializedJWS struct {
	Protected string `json:"protected"`
	Payload   string `json:"payload"`
	Signature string `json:"signature"`
}

func (jwk *JWKES256) GetKeyAuth(token string) (string, error) {
	bytes, err := json.Marshal(jwk)

	if err != nil {
		log.Trace(err)
		return "", err
	}

	hasher := crypto.SHA256.New()
	_, err = hasher.Write(bytes)

	if err != nil {
		log.Error(err)
		return "", err
	}

	thumbprint := strings.TrimRight(base64.URLEncoding.EncodeToString(hasher.Sum(nil)), "=")

	return token + "." + thumbprint, nil

}

func (jws *JWS) FlattenJSONSerialization(sk *ecdsa.PrivateKey, noPayload bool) ([]byte, error) {

	serializedJWS := SerializedJWS{}

	protectedJSON, err := json.Marshal(jws.Protected)

	if err != nil {
		log.Error(err)
		return nil, err
	}

	serializedJWS.Protected = strings.TrimRight(base64.URLEncoding.EncodeToString(protectedJSON), "=")

	if noPayload {
		serializedJWS.Payload = ""
	} else {
		payloadJSON, err := json.Marshal(jws.Payload)

		if err != nil {
			log.Error(err)
			return nil, err
		}

		serializedJWS.Payload = strings.TrimRight(base64.URLEncoding.EncodeToString(payloadJSON), "=")
	}

	toSign := serializedJWS.Protected + "." + serializedJWS.Payload

	hasher := crypto.SHA256.New()
	_, err = hasher.Write([]byte(toSign))

	if err != nil {
		log.Error(err)
		return nil, err
	}

	r, s, err := ecdsa.Sign(rand.Reader, sk, hasher.Sum(nil))

	if err != nil {
		log.Error(err)
		return nil, err
	}

	serializedJWS.Signature = strings.TrimRight(base64.URLEncoding.EncodeToString(append(r.Bytes(), s.Bytes()...)), "=")

	data, err := json.Marshal(serializedJWS)

	if err != nil {
		log.Error(err)
		return nil, err
	}

	return data, nil
}

func (cli *Client) GetCSR() (string, error) {

	domains := make([]string,0)

	for _, id := range cli.Order.Identifiers{
		domains = append(domains, id.Value)
	}


	csrKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	if err != nil{
		log.Error(err)
		return "", err
	}

	cli.CertKey = csrKey

	template := &x509.CertificateRequest{
		Subject: pkix.Name{
			Country:            []string{"CH"},
			Province:           []string{"Zurich"},
			Locality:           []string{"Zurich"},
			Organization:       []string{"ETH"},
			OrganizationalUnit: []string{"NetSec2020"},

		},
		SignatureAlgorithm:       x509.ECDSAWithSHA256,
		DNSNames:                 domains,
	}

	derBytes, err := x509.CreateCertificateRequest(rand.Reader, template, csrKey)
	if err != nil {
		log.Error(err)
		return "", err
	}

	csr := strings.TrimRight(base64.URLEncoding.EncodeToString(derBytes), "=")

	return csr, nil
}