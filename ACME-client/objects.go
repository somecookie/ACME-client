package client

import "fmt"

type Directory struct {
	NewNonce   string
	NewAccount string
	NewOrder   string
	NewAuthz   string
	RevokeCert string
	KeyChange  string
	Meta       Meta
}

type Meta struct {
	TermsOfService          string
	Website                 string
	CaaIdentities           []string
	ExternalAccountRequired bool
}

type Account struct {
	Status               string
	Contact              []string
	TermsOfServiceAgreed bool
	//externalAccountBinding
	Orders string
}

type OrderLists []string

type Identifier struct {
	Type  string `json:"type"`
	Value string `json:"value"`
}

type Order struct {
	Status         string `json:"status,omitempty"`
	Expires        string `json:"expires,omitempty"`
	Identifiers    []Identifier `json:"identifiers,omitempty"`
	NotBefore      string `json:"notBefore,omitempty"`
	NotAfter       string `json:"notAfter,omitempty"`
	Error          string `json:"error,omitempty"`
	Authorizations []string `json:"authorizations,omitempty"`
	Finalize       string `json:"finalize,omitempty"`
	Certificate    string `json:"certificate,omitempty"`
}

type Challenge struct {
	Type string `json:"type"`
	Url string `json:"url"`
	Status string `json:"status"`
	Validated string `json:"validated,omitempty"`
	Error interface{} `json:"error, omitempty"`
	Token string `json:"token, omitempty"`
}

type Authorization struct {
	Identifier Identifier `json:"identifier"`
	Status string `json:"status"`
	Expires string `json:"expires,omitempty"`
	Challenges []Challenge `json:"challenges"`
	Wildcard bool `json:"wildcard,omitempty"`
}

type Empty struct {}

type Error struct {
	Type string `json:"type"`
	Detail string `json:"detail"`
	Subproblems interface{} `json:"subproblems"`
}

type CSRPayload struct {
	Csr string `json:"csr"`
}

type HTTPError struct {
	StatusCode int
}

type Certs struct {
	EndEntity string
	Issuer string
	Others []string
}

type Revocation struct {
	Certificate string `json:"certificate"`
	Reason int `json:"reason,omitempty"`
}

func (e *HTTPError) Error() string{
	return fmt.Sprintf("Server returned %d", e.StatusCode)
}
