package nodekey

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	gethcrypto "github.com/ethereum/go-ethereum/crypto"
	gethenode "github.com/ethereum/go-ethereum/p2p/enode"
	libp2pcrypto "github.com/libp2p/go-libp2p/core/crypto"
	libp2ppeer "github.com/libp2p/go-libp2p/core/peer"
	"io"
	"net"
)

const RSAKeypairBits = 2048
const RSAKeypairExponent = 65537
const RSAKeypairType = "rsa"

type (
	nodeKeyOut struct {
		PublicKey      string `json:"publicKey"`
		PrivateKey     string `json:"privateKey"`
		FullPrivateKey string `json:"fullPrivateKey,omitempty"`
		ENR            string `json:"enr,omitempty"`
		Seed           uint64 `json:"seed,omitempty"`
	}
)

func GenerateLibp2pNodeKey(keyType int, seed bool, seed_value uint64, marshal_protobuf bool) ([]byte, error) {
	var nko nodeKeyOut
	reader := rand.Reader
	if seed {
		seedValue := seed_value
		seedData := make([]byte, 64)
		binary.BigEndian.PutUint64(seedData, seedValue)
		buf := bytes.NewBuffer(seedData)
		reader = io.LimitReader(buf, 64)
		nko.Seed = seedValue
	}

	prvKey, _, err := libp2pcrypto.GenerateKeyPairWithReader(keyType, RSAKeypairBits, reader)
	if err != nil {
		return nil, fmt.Errorf("unable to generate key pair, %w", err)
	}

	var rawPrvKey []byte
	if marshal_protobuf {
		rawPrvKey, err = libp2pcrypto.MarshalPrivateKey(prvKey)
	} else {
		rawPrvKey, err = prvKey.Raw()
	}
	if err != nil {
		return nil, fmt.Errorf("unable to convert the private key to a byte array, %w", err)
	}

	id, err := libp2ppeer.IDFromPrivateKey(prvKey)
	if err != nil {
		return nil, fmt.Errorf("unable to retrieve the node ID from the private key, %w", err)
	}

	nko.PublicKey = id.String()
	nko.PrivateKey = hex.EncodeToString(rawPrvKey[0:ed25519.PublicKeySize])
	nko.FullPrivateKey = hex.EncodeToString(rawPrvKey)
	jsonBytes, err := json.Marshal(nko)
	if err != nil {
		return nil, err
	}
	return jsonBytes, nil
}

func GenerateDevp2pNodeKey(inputNodeKeyIP string, inputNodeKeySign bool, inputNodeKeyTCP int, inputNodeKeyUDP int) ([]byte, error) {
	nodeKey, err := gethcrypto.GenerateKey()

	//if *inputNodeKeyFile != "" {
	//	nodeKey, err = gethcrypto.LoadECDSA(*inputNodeKeyFile)
	//}
	//if err != nil {
	//	return nodeKeyOut{}, fmt.Errorf("could not generate key: %w", err)
	//}

	nko := nodeKeyOut{}
	nko.PublicKey = fmt.Sprintf("%x", gethcrypto.FromECDSAPub(&nodeKey.PublicKey)[1:])
	prvKeyBytes := gethcrypto.FromECDSA(nodeKey)
	nko.PrivateKey = hex.EncodeToString(prvKeyBytes)

	ip := net.ParseIP(inputNodeKeyIP)
	n := gethenode.NewV4(&nodeKey.PublicKey, ip, inputNodeKeyTCP, inputNodeKeyUDP)

	if inputNodeKeySign {
		r := n.Record()
		err = gethenode.SignV4(r, nodeKey)
		if err != nil {
			return nil, err
		}
		n, err = gethenode.New(gethenode.ValidSchemes, r)
		if err != nil {
			return nil, err
		}
	}

	nko.ENR = n.String()
	jsonBytes, err := json.Marshal(nko)
	if err != nil {
		return nil, err
	}
	return jsonBytes, nil
}
