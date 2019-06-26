package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/niftynei/glightning/glightning"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"
)

const VERSION = "0.0.1"

var plugin *glightning.Plugin
var lightning *glightning.Lightning
var rest *Rest
var local net.Conn

const paystreamWait = 10 * time.Second

type Rest struct {
	Username string
	Password string
	Host     string
	Port     string
	RPCFile  string
}

type RpcResult struct {
	Jsonrpc string      `json:"jsonrpc"`
	Id      int         `json:"id"`
	Result  interface{} `json:"result"`
}

func NewRest(options map[string]string) *Rest {
	return &Rest{
		Username: options["rest-user"],
		Password: options["rest-password"],
		Host:     options["rest-host"],
		Port:     options["rest-port"],
		RPCFile:  options["rpc-file"],
	}
}

func main() {
	plugin = glightning.NewPlugin(onInit)

	registerOptions(plugin)
	err := plugin.Start(os.Stdin, os.Stdout)
	if err != nil {
		log.Fatal(err)
	}
}

func authError(w http.ResponseWriter) {
	rpcerr := &RpcResult{
		Jsonrpc: "2.0",
		Result:  "Not Authorized",
	}
	rpcResponse, _ := json.Marshal(rpcerr)
	w.Write(rpcResponse)

}

func handleAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		authHeader := strings.SplitN(req.Header.Get("Authorization"), " ", 2)

		if len(authHeader) != 2 || authHeader[0] != "Basic" {
			authError(w)
			return
		}

		basic, _ := base64.StdEncoding.DecodeString(authHeader[1])
		userpass := strings.SplitN(string(basic), ":", 2)

		if userpass[0] == rest.Username && userpass[1] == rest.Password {
			next.ServeHTTP(w, req)
			return
		}
		authError(w)
	})
}

func authWrapper(path string, f func(http.ResponseWriter, *http.Request)) {
	handler := http.HandlerFunc(f)
	http.Handle(path, handleAuth(handler))
}

func handleRPC(w http.ResponseWriter, req *http.Request) {
	local, err := net.Dial("unix", rest.RPCFile)
	if err != nil {
		log.Fatal("unable to connect to clightning")
	}
	defer local.Close()

	var unix2http = make([]byte, 1024)

	_, errc := io.Copy(local, req.Body)
	if errc != nil && errc != io.EOF {
		log.Printf("Copy error: %s", errc)
	}

	var responseBuf []byte
	for {
		r, err := local.Read(unix2http)
		if err != nil {
			if err != io.EOF {
				log.Printf("RPC error to clightning: %s", err)
			}
			break
		}
		responseBuf = append(responseBuf, unix2http[:r]...)
		if unix2http[r-2] == '\n' && unix2http[r-1] == '\n' {
			break
		}
	}
	w.Header().Set("content-type", "application/json; charset=utf-8")
	w.Write(responseBuf)
}

func handleInfo(w http.ResponseWriter, req *http.Request) {
	info, _ := lightning.GetInfo()
	restResponse, _ := json.Marshal(info)
	w.Header().Set("content-type", "application/json; charset=utf-8")
	w.Write([]byte(restResponse))
}

func generateLabel() string { // TODO: remplace temporary with hmac
	return fmt.Sprintf("%d", time.Now().Unix())
}

type InvoiceRequest struct {
	MilliSatoshis      interface{} `json:"msatoshi"`
	Label              string      `json:"label"`
	Description        string      `json:"description"`
	ExpirySeconds      uint32      `json:"expiry,omitempty"`
	Fallbacks          []string    `json:"fallbacks,omitempty"`
	PreImage           string      `json:"preimage,omitempty"`
	ExposePrivateChans bool        `json:"exposeprivatechannels"`
}

func handleInvoice(w http.ResponseWriter, req *http.Request) {
	if req.Method == "POST" {
		handleCreateInvoice(w, req)
	} else if req.Method == "GET" {
		handleGetInvoice(w, req)
	} else {
		http.Error(w, "Invalid request method", http.StatusMethodNotAllowed)
	}
}

func handleCreateInvoice(w http.ResponseWriter, req *http.Request) {
	//TODO: parameters: msatoshi, currency, amount, description, expiry, metadata and webhook.

	if req.Method == "POST" {
		decoder := json.NewDecoder(req.Body)
		var invReq InvoiceRequest
		err := decoder.Decode(&invReq)
		if err != nil {
			panic(err)
		}
		var invoice *glightning.Invoice
		var reqmsat string
		reqmsat = fmt.Sprint(invReq.MilliSatoshis)
		if strings.Compare(reqmsat, "any") == 0 {
			invoice, err = lightning.CreateInvoiceAny(generateLabel(), invReq.Description, uint32(300), nil, "", false)
		} else {
			msat, err := strconv.ParseUint(reqmsat, 10, 64)
			if err != nil {
				panic(err)
			}
			invoice, err = lightning.CreateInvoice(msat, generateLabel(), invReq.Description, uint32(300), nil, "", false)
		}
		if err != nil {
			panic(err)
		}
		restResponse, _ := json.Marshal(invoice)
		w.Header().Set("content-type", "application/json; charset=utf-8")
		w.Write([]byte(restResponse))
	} else {
		http.Error(w, "Invalid request method", http.StatusMethodNotAllowed)
	}
}

func handleGetInvoice(w http.ResponseWriter, req *http.Request) {
	id := req.URL.Path[len("/invoice/"):]
	inv, err := lightning.GetInvoice(id)
	if err != nil {
		http.Error(w, "Invalid label", http.StatusBadRequest)
		return
	}
	restResponse, _ := json.Marshal(inv)
	w.Header().Set("content-type", "application/json; charset=utf-8")
	w.Write([]byte(restResponse))
}

func handleInvoices(w http.ResponseWriter, req *http.Request) {
	inv, _ := lightning.ListInvoices()
	restResponse, _ := json.Marshal(inv)
	w.Header().Set("content-type", "application/json; charset=utf-8")
	w.Write([]byte(restResponse))
}

func registerOptions(p *glightning.Plugin) {
	p.RegisterOption(glightning.NewOption("rest-user", "User used for authentication", "restuser"))
	p.RegisterOption(glightning.NewOption("rest-password", "Password used for authentication", "restpass"))
	p.RegisterOption(glightning.NewOption("rest-port", "Port to listen for rest requests", "9222"))
	p.RegisterOption(glightning.NewOption("rest-cert", "Server certificate", " ")) // crashes on empty
	p.RegisterOption(glightning.NewOption("rest-key", "Server key", " "))
}

func onInit(plugin *glightning.Plugin, options map[string]string, config *glightning.Config) {
	log.Printf("versiion: "+VERSION+" initialized for port %s\n", options["rest-port"])
	options["rpc-file"] = fmt.Sprintf("%s/%s", config.LightningDir, config.RpcFile)
	rest = NewRest(options)
	lightning = glightning.NewLightning()
	lightning.StartUp(config.RpcFile, config.LightningDir)

	authWrapper("/info", handleInfo)
	authWrapper("/rpc", handleRPC)
	authWrapper("/invoice/", handleInvoice)
	authWrapper("/invoices", handleInvoices)

	if options["rest-cert"] != " " {
		log.Fatal(http.ListenAndServeTLS(":"+rest.Port, options["rest-cert"], options["rest-key"], nil))
	} else {
		log.Fatal(http.ListenAndServe(":"+rest.Port, nil))
	}
}
