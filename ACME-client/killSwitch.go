package client

import (
	"fmt"
	log "github.com/sirupsen/logrus"
	"net/http"
)

var killSwitch chan bool

func GetKillSwitch(cli *Client, kill chan bool) *http.Server {

	serverAddr := cli.IPv4 + ":5003"
	log.Info("Starting kill switch at ", serverAddr)
	killswitch := &http.Server{Addr: serverAddr}

	killSwitch = kill

	http.HandleFunc("/shutdown", Kill)

	return killswitch
}

func Kill(writer http.ResponseWriter, request *http.Request) {
	log.Info(fmt.Sprintf("%s %s %s %d %d %s %s", request.Method, request.URL, request.Proto, request.ProtoMajor, request.ProtoMinor, request.UserAgent(), request.RemoteAddr))
	writer.WriteHeader(http.StatusOK)
	killSwitch <- true
}
