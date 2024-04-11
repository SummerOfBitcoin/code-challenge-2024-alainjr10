package handlers

import (
	"bytes"
	"encoding/hex"
	"fmt"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
)

func CreateCoinbaseTx() *wire.MsgTx {
	// var coinbaseTx types.TransactionData
	// let's create my public key, private key and address

	tx := wire.NewMsgTx(wire.TxVersion)
	// create the chain hash which is the hash of the genesis block which is actually just a 32 byte array of 0s
	chainHash := chaincfg.MainNetParams.GenesisHash
	// and then the index, which for this coinbase transaction is just an 8 byte array of 0xffffffff
	indexVal := ^uint32(0)
	prevOut := wire.NewOutPoint(chainHash, indexVal)
	sigScript := createCoinbaseScriptSig()
	txIn := wire.NewTxIn(prevOut, sigScript, nil)
	txIn.Sequence = wire.MaxTxInSequenceNum
	tx.AddTxIn(txIn)

	outputAddr, _ := btcutil.DecodeAddress(Address, &chaincfg.MainNetParams)
	output2ScriptPubKey, _ := txscript.PayToAddrScript(outputAddr)
	txOut := wire.NewTxOut(624000000, output2ScriptPubKey)
	tx.AddTxOut(txOut)

	return tx
}

func serializeTransaction(tx *wire.MsgTx) []byte {
	var txBuf bytes.Buffer
	tx.Serialize(&txBuf)
	return txBuf.Bytes()
}

func PrintCoinbaseTx() {
	tx := CreateCoinbaseTx()
	hexEncoded := hex.EncodeToString(serializeTransaction(tx))
	fileName := GetFileName(hexEncoded)
	fmt.Println("Coinbase transaction: ", hexEncoded, "\nFilename: ", hex.EncodeToString(fileName))

}

func createCoinbaseScriptSig() []byte {
	// Convert block height to a byte slice
	heightBytes := []byte(fmt.Sprintf("%08d", 820105))
	scriptBuilder := txscript.NewScriptBuilder()
	scriptBuilder.AddOp(txscript.OP_PUSHDATA4).AddData(heightBytes)
	script, _ := scriptBuilder.Script()
	return script
}

func CreateBtcAddress() string {
	privKey, _ := btcec.NewPrivateKey()
	pubKey := privKey.PubKey()
	pubKeyHash := btcutil.Hash160(pubKey.SerializeCompressed())
	myAddress, _ := btcutil.NewAddressPubKeyHash(pubKeyHash, &chaincfg.MainNetParams)
	encodedAddress := myAddress.EncodeAddress()
	fmt.Println("My address: ", encodedAddress, "\nMy private key: ", hex.EncodeToString(privKey.Serialize()), "\nMy public key: ", hex.EncodeToString(pubKey.SerializeCompressed()))
	return encodedAddress
}

const (
	Address = "17qdB4VXej7U4MWXF6HqoALVThA5Dsqy12"
	PubKey  = "030b44daeef5e794cf44e4440a9a077fe27dc548fd1037cbf1408939bd84238275"
	PrivKey = "f587103a6cdc2a2f60348d21513d1ba08b4970d29bb4af3ce5ad4c7e79bfa421"
)
