package wallet

import (
	"encoding/hex"
	"encoding/json"
	"eth-ws/hdwallet"
	"fmt"
	"github.com/ethereum/go-ethereum/accounts/keystore"
	"github.com/ethereum/go-ethereum/crypto/secp256k1"
	"golang.org/x/crypto/sha3"
	"io/ioutil"
	"net/http"
)

type WalletRequestBody struct {
	Words       int    `json:"words"`
	Iteraions   uint   `json:"iterations"`
	NoOfAddress int    `json:"no_of_address"`
	Language    string `json:"language"`
	Path        string `json:"path"`
	Password    string `json:"password"`
	Mnemonic    string `json:"mnemonic"`
	RawEntropy  bool   `json:"raw_entropy"`
	RootOnly    bool   `json:"root_only"`
}

type plainKeyJSON struct {
	Address string              `json:"address"`
	Crypto  keystore.CryptoJSON `json:"crypto"`
}
type outKey struct {
	Address    string
	PublicKey  string
	PrivateKey string
}

func NewWallet(w http.ResponseWriter, r *http.Request) {

	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var requestBody WalletRequestBody

	err := json.NewDecoder(r.Body).Decode(&requestBody)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	if requestBody.Words == 0 {
		requestBody.Words = 12
	}

	if requestBody.Language == "" {
		requestBody.Language = "english"
	}

	if requestBody.Path == "" {
		requestBody.Path = "m/44'/60'/0'/0/0"
	}

	if requestBody.Iteraions == 0 {
		requestBody.Iteraions = 2048
	}
	var mnemonic string
	if requestBody.Mnemonic == "" {
		mnemonic, err = hdwallet.NewMnemonic(requestBody.Words, requestBody.Language)
	} else {
		mnemonic = requestBody.Mnemonic
	}

	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	wallet, err := hdwallet.NewHDWallet(mnemonic, requestBody.Password)

	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	wallet.SetPath(requestBody.Path)
	wallet.SetIterations(requestBody.Iteraions)
	wallet.SetUseRawEntropy(requestBody.RawEntropy)

	if requestBody.RootOnly {
		var key *hdwallet.HDWalletExport
		key, err = wallet.ExportRootAddress()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		out, _ := json.MarshalIndent(key, " ", " ")
		resp, _ := json.Marshal(map[string]string{"result": string(out)})

		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "POST, GET, OPTIONS, PUT, DELETE")
		w.Header().Set("Access-Control-Allow-Headers", "Accept, Content-Type, Content-Length, Accept-Encoding, X-CSRF-Token, Authorization")

		// Send response
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)

		w.Write(resp)
		return
	}

	key, err := wallet.ExportHDAddresses(int(requestBody.NoOfAddress))
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	out, _ := json.MarshalIndent(key, " ", " ")
	resp, _ := json.Marshal(map[string]string{"result": string(out)})

	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "POST, GET, OPTIONS, PUT, DELETE")
	w.Header().Set("Access-Control-Allow-Headers", "Accept, Content-Type, Content-Length, Accept-Encoding, X-CSRF-Token, Authorization")

	// Send response
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)

	w.Write(resp)

}

func NewMnemonic(w http.ResponseWriter, r *http.Request) {

	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var requestBody WalletRequestBody

	err := json.NewDecoder(r.Body).Decode(&requestBody)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	if requestBody.Words == 0 {
		requestBody.Words = 12
	}

	if requestBody.Language == "" {
		requestBody.Language = "english"
	}

	mnemonic, err := hdwallet.NewMnemonic(requestBody.Words, requestBody.Language)

	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	resp, err := json.Marshal(map[string]string{"result": string(mnemonic)})

	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "POST, GET, OPTIONS, PUT, DELETE")
	w.Header().Set("Access-Control-Allow-Headers", "Accept, Content-Type, Content-Length, Accept-Encoding, X-CSRF-Token, Authorization")

	// Send response
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)

	w.Write(resp)

}

func HandleWalletUpload(w http.ResponseWriter, r *http.Request) {
	// Only allow POST requests
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	// Parse multipart form data with a maximum size of 1 MB
	maxSize := int64(1 << 20) // 1 MB
	err := r.ParseMultipartForm(maxSize)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprintf(w, "Error parsing form data: %v", err)
		return
	}

	// Get the file from the form data
	file, handler, err := r.FormFile("file")
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprintf(w, "Error retrieving file: %v", err)
		return
	}
	defer file.Close()

	// Check the file size
	if handler.Size > maxSize {
		w.WriteHeader(http.StatusBadRequest)
		fmt.Fprintf(w, "File size exceeds maximum size of 1 MB.")
		return
	}

	//// Save the file to disk
	//f, err := os.OpenFile(handler.Filename, os.O_WRONLY|os.O_CREATE, 0666)
	//if err != nil {
	//	w.WriteHeader(http.StatusInternalServerError)
	//	fmt.Fprintf(w, "Error saving file: %v", err)
	//	return
	//}
	//defer f.Close()
	//io.Copy(f, file)
	//
	//w.WriteHeader(http.StatusOK)
	//fmt.Fprint(w, "File uploaded successfully.")

	fileBytes, err := ioutil.ReadAll(file)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprintf(w, "Error reading file: %v", err)
		return
	}

	fmt.Fprintf(w, "File uploaded successfully. File size: %d bytes.", len(fileBytes))

	k := new(plainKeyJSON)
	err = json.Unmarshal(fileBytes, &k)
	if err != nil {
		fmt.Fprintf(w, "Error Marshling json: %v", err)
	}
	d, err := keystore.DecryptDataV3(k.Crypto, "123456")
	if err != nil {
		fmt.Fprintf(w, "Invalid Wallet: %v", err)
	}
	ok := toOutputKey(d)
	outData, err := json.Marshal(ok)
	if err != nil {
		fmt.Fprintf(w, "Failed to get neceesry information from Wallet: %v", err)
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write(outData)
}

func toOutputKey(key []byte) outKey {
	ok := outKey{}
	ok.PrivateKey = hex.EncodeToString(key)
	curve := secp256k1.S256()
	x1, y1 := curve.ScalarBaseMult(key)
	concat := append(x1.Bytes(), y1.Bytes()...)
	h := sha3.NewLegacyKeccak256()
	h.Write(concat)
	b := h.Sum(nil)
	ok.Address = fmt.Sprintf("0x%s", hex.EncodeToString(b[len(b)-20:]))
	ok.PublicKey = hex.EncodeToString(concat)
	return ok
}
