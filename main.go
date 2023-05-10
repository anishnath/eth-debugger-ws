package main

import (
	"encoding/json"
	"eth-ws/nodekey"
	"fmt"
	"log"
	"net/http"
)

type Devp2pNodeKeyRequestBody struct {
	Ip   string `json:"ip"`
	Sign bool   `json:"sign"`
	Tcp  int    `json:"tcp"`
	Udp  int    `json:"udp"`
}

type Libp2pNodeKeyRequestBody struct {
	Keytype         int    `json:"keytype"`
	Seed            bool   `json:"seed"`
	SeedValue       uint64 `json:"seed_value"`
	MarshalProtobuf bool   `json:"marshal_protobuf"`
}

func main() {
	http.HandleFunc("/generateDevp2pNodeKey", GenerateDevp2pNodeKey)
	http.HandleFunc("/generateLibp2pNodeKey", GenerateLibp2pNodeKey)
	log.Fatal(http.ListenAndServe(":1888", nil))
}

func GenerateDevp2pNodeKey(w http.ResponseWriter, r *http.Request) {

	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var requestBody Devp2pNodeKeyRequestBody

	err := json.NewDecoder(r.Body).Decode(&requestBody)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Generate node key
	fmt.Println(requestBody)
	key, err := nodekey.GenerateDevp2pNodeKey(requestBody.Ip, requestBody.Sign, requestBody.Tcp, requestBody.Udp)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Marshal node key to JSON
	resp, err := json.Marshal(map[string]string{"result": string(key)})
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "POST, GET, OPTIONS, PUT, DELETE")
	w.Header().Set("Access-Control-Allow-Headers", "Accept, Content-Type, Content-Length, Accept-Encoding, X-CSRF-Token, Authorization")

	// Send response
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write(resp)
}

func GenerateLibp2pNodeKey(w http.ResponseWriter, r *http.Request) {

	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var requestBody Libp2pNodeKeyRequestBody
	err := json.NewDecoder(r.Body).Decode(&requestBody)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Generate node key
	key, err := nodekey.GenerateLibp2pNodeKey(requestBody.Keytype, requestBody.Seed, requestBody.SeedValue, requestBody.MarshalProtobuf)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Marshal node key to JSON
	resp, err := json.Marshal(map[string]string{"result": string(key)})
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "POST, GET, OPTIONS, PUT, DELETE")
	w.Header().Set("Access-Control-Allow-Headers", "Accept, Content-Type, Content-Length, Accept-Encoding, X-CSRF-Token, Authorization")

	// Send response
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write(resp)
}
