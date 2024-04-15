package handlers

import (
	"bytes"
	"encoding/hex"
	"fmt"

	"github.com/SummerOfBitcoin/code-challenge-2024-alainjr10/types"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
)

func CreateCoinbaseTx() (*wire.MsgTx, types.TransactionData) {
	// var coinbaseTx types.TransactionData
	// let's create my public key, private key and address
	var transaction types.TransactionData
	tx := wire.NewMsgTx(wire.TxVersion)
	// create the chain hash which is the hash of the genesis block which is actually just a 32 byte array of 0s
	chainHash := chaincfg.MainNetParams.HDCoinType
	coinbaseVinTxid, err := chainhash.NewHashFromStr(fmt.Sprint(chainHash))
	if err != nil {
		fmt.Println("Error creating coinbase transaction: ", err)
	}
	// and then the index, which for this coinbase transaction is just an 8 byte array of 0xffffffff
	indexVal := ^uint32(0)
	prevOut := wire.NewOutPoint(coinbaseVinTxid, indexVal)
	sigScript := createCoinbaseScriptSig()
	txIn := wire.NewTxIn(prevOut, sigScript, nil)
	txIn.Sequence = wire.MaxTxInSequenceNum
	tx.AddTxIn(txIn)

	outputAddr, _ := btcutil.DecodeAddress(Address, &chaincfg.MainNetParams)
	output2ScriptPubKey, _ := txscript.PayToAddrScript(outputAddr)
	txOut := wire.NewTxOut(624000000, output2ScriptPubKey)
	tx.AddTxOut(txOut)
	hexEncoded := hex.EncodeToString(SerializeWireMsgTx(tx))
	fileName := GetFileName(hexEncoded)
	fileNameHex := hex.EncodeToString(fileName)
	scriptPubKeyAsm, _ := txscript.DisasmString(output2ScriptPubKey)
	transaction = types.TransactionData{
		TxFilename: fileNameHex + ".json",
		Version:    int(tx.Version),
		Locktime:   int(tx.LockTime),
		Vin: []types.TransactionVin{
			{
				TxID:         coinbaseVinTxid.String(),
				Vout:         int(indexVal),
				ScriptSig:    "",
				ScriptSigAsm: "",
				Sequence:     int(txIn.Sequence),
				IsCoinbase:   true,
			},
		},
		Vout: []types.TransactionVout{
			{
				ScriptPubKey:        hex.EncodeToString(output2ScriptPubKey),
				ScriptPubKeyAsm:     scriptPubKeyAsm,
				ScriptPubKeyType:    "p2pkh",
				ScriptPubKeyAddress: Address,
				Value:               int(txOut.Value),
			},
		},
	}
	return tx, transaction
}

func SerializeWireMsgTx(tx *wire.MsgTx) []byte {
	var txBuf bytes.Buffer
	tx.Serialize(&txBuf)
	return txBuf.Bytes()
}

func SerializeWireBlockHeader(tx *wire.BlockHeader) []byte {
	var txBuf bytes.Buffer
	tx.Serialize(&txBuf)
	return txBuf.Bytes()
}

func ConbaseTxToTxStruct(tx *wire.MsgTx) {
	fmt.Println("Coinbase transaction: ", hex.EncodeToString(SerializeWireMsgTx(tx)))
}

func PrintCoinbaseTx() ([]byte, string) {
	tx, _ := CreateCoinbaseTx()
	hexEncoded := hex.EncodeToString(SerializeWireMsgTx(tx))
	// fileName := GetFileName(hexEncoded)
	// parse the transaction struct to a string
	// fmt.Println("Coinbase transaction: ", transcation)
	// fmt.Println("Coinbase transaction: ", hexEncoded, "\nFilename: ", hex.EncodeToString(fileName))
	return SerializeWireMsgTx(tx), hexEncoded
}

func CreateCoinbaseCommittmentScript(txs []*wire.MsgTx) []byte {
	witnessRootHash, _ := CreateWitnessMerkleTree(txs)
	witnessRootHashRev := ReverseBytesFromHexStr(witnessRootHash.String())
	witnessReservedValue := "0000000000000000000000000000000000000000000000000000000000000000"
	witnessRootHashBytes, _ := hex.DecodeString(witnessRootHashRev)
	witnessReservedValueBytes, _ := hex.DecodeString(witnessReservedValue)
	wTxIdCommitment := chainhash.DoubleHashH(append(witnessRootHashBytes, witnessReservedValueBytes...))
	wTxIdCommitmentHash, _ := hex.DecodeString(wTxIdCommitment.String())
	prefixBytes, _ := hex.DecodeString("aa21a9ed")
	commitmentScript, err := txscript.NewScriptBuilder().AddOp(txscript.OP_RETURN).AddData(append(prefixBytes, wTxIdCommitmentHash...)).Script()
	if err != nil {
		fmt.Println("Error creating commitment script: ", err)
	}
	return commitmentScript
}

func createCoinbaseScriptSig() []byte {
	// Convert block height to a byte slice
	height := fmt.Sprintf("%06x", 838770)
	heightBytes, _ := hex.DecodeString(height)
	heightBytes = ReverseSlice(heightBytes)
	scriptBuilder := txscript.NewScriptBuilder()
	scriptBuilder.AddOp(txscript.OP_DATA_4).AddData(heightBytes)
	script, _ := scriptBuilder.Script()
	// decryp, _ := txscript.DisasmString(script)
	// fmt.Println("Script: ", hex.EncodeToString(script), "\nDecrypted: ", decryp)
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
