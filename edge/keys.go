package main

import (
	"encoding/json"
	"fmt"
	"github.com/0xPolygon/polygon-edge/crypto"
	"github.com/0xPolygon/polygon-edge/helper/hex"
	"github.com/0xPolygon/polygon-edge/network"
	"github.com/libp2p/go-libp2p/core/peer"
)

type KeyInfo struct {
	ValidatorKey     string `json:"validator_key"`
	ValidatorAddress string `json:"validator_address"`
	Libp2pKey        string `json:"libp2p_key"`
	NodeID           string `json:"node_id"`
	BLSSecretKey     string `json:"bls_secret_key"`
	BLSPublicKey     string `json:"bls_public_key"`
}

func main() {
	fmt.Println("Hello, playground")
	keys, err := GenerateKeys(5)
	if err != nil {
		return
	}

	jsonData, err := json.Marshal(keys)
	if err != nil {
		fmt.Println("Error marshaling JSON:", err)
		return
	}
	fmt.Println(string(jsonData))

	ibftString, err := GetIBFTString(keys)
	if err != nil {
		return
	}
	fmt.Println(ibftString)

	ip := []string{"192.168.0.1", "192.168.0.2"}

	nodeString, err := GetBootNodeString(ip, keys)
	if err != nil {
		return
	}

	fmt.Println(nodeString)

	PrintKeyInfo(keys)
}

func GenerateKeys(no_of_key int) ([]KeyInfo, error) {

	keys := make([]KeyInfo, no_of_key)

	// Iterate over the number of keys to generate
	for i := 0; i < no_of_key; i++ {
		// Generate the IBFT validator private key
		validatorKey, validatorKeyEncoded, err := crypto.GenerateAndEncodeECDSAPrivateKey()
		if err != nil {
			return nil, err
		}
		validatorAddress := crypto.PubKeyToAddress(&validatorKey.PublicKey)
		//fmt.Println(string(validatorKeyEncoded))
		//fmt.Println(validatorAddress)

		// Generate the libp2p private key
		libp2pKey, libp2pKeyEncoded, err := network.GenerateAndEncodeLibp2pKey()
		if err != nil {
			return nil, err
		}
		nodeID, err := peer.IDFromPrivateKey(libp2pKey)
		//fmt.Println(string(libp2pKeyEncoded))
		//fmt.Println(nodeID)

		_, bksKeyEncoded, err := crypto.GenerateAndEncodeBLSSecretKey()
		if err != nil {
			return nil, err
		}

		bksKey, _ := crypto.BytesToBLSSecretKey(bksKeyEncoded)
		pubBLSKey, err := crypto.BLSSecretKeyToPubkeyBytes(bksKey)
		pubBLSKeyHex := hex.EncodeToHex(pubBLSKey)
		//fmt.Println(v)

		//fmt.Println(string(bksKeyEncoded))
		//fmt.Println(hex.EncodeToHex(blsPubKey))

		keys[i] = KeyInfo{
			ValidatorKey:     string(validatorKeyEncoded),
			ValidatorAddress: validatorAddress.String(),
			Libp2pKey:        string(libp2pKeyEncoded),
			NodeID:           nodeID.String(),
			BLSSecretKey:     string(bksKeyEncoded),
			BLSPublicKey:     pubBLSKeyHex,
		}

	}
	return keys, nil
}

func GetIBFTString(keys []KeyInfo) ([]string, error) {

	var ibftMaps []string
	for _, key := range keys {
		entry := key.ValidatorAddress + ":" + key.BLSPublicKey
		ibftMaps = append(ibftMaps, entry)
	}

	return ibftMaps, nil
}

func GetBootNodeString(ip []string, keys []KeyInfo) ([]string, error) {
	if len(ip) > len(keys) {
		return nil, fmt.Errorf("number of IPs exceeds the number of keys")
	}

	var bootNodes []string
	for i, k := range keys {
		if i >= len(ip) {
			break
		}
		nodeString := fmt.Sprintf("/ip4/%s/tcp/1478/p2p/%s", ip[i], k.NodeID)
		bootNodes = append(bootNodes, nodeString)
	}

	return bootNodes, nil
}

func PrintKeyInfo(keys []KeyInfo) {
	//fmt.Println("[SECRETS INIT]")
	for _, k := range keys {
		PrintSingleKeyInfo(k)
	}
}

func PrintSingleKeyInfo(key KeyInfo) {
	fmt.Println("[SECRETS INIT]")
	fmt.Println("BLS Public key:", key.BLSPublicKey)
	fmt.Println("Node ID:", key.NodeID)
	fmt.Println("Public key (address):", key.ValidatorAddress)
	fmt.Println()
}
