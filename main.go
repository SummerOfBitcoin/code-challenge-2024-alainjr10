package main

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"

	"github.com/SummerOfBitcoin/code-challenge-2024-alainjr10/handlers"
	"github.com/SummerOfBitcoin/code-challenge-2024-alainjr10/types"
	"github.com/btcsuite/btcd/btcutil"
)

func main() {
	fmt.Println("Hello from golang module")

	var transactions []types.TransactionData

	// Read all transactions from the mempool
	// For each transaction, unmarshal it and add to the Transaction data slice
	fileDir, err := os.ReadDir("mempool")
	if err != nil {
		fmt.Println("Error reading file: ", err)
	}

	for _, file := range fileDir {
		var transaction types.TransactionData
		fileBytes, err := os.ReadFile("mempool/" + file.Name())
		if err != nil {
			fmt.Println("Error reading file: ", err)
		}
		err = json.Unmarshal(fileBytes, &transaction)
		transaction.TxFilename = file.Name()
		if err != nil {
			fmt.Println("Error unmarshaling JSON: ", err)
		}
		transactions = append(transactions, transaction)
	}

	// getValidTxOfCertainTypes(transactions, "p2pkh")
	for _, tx := range transactions {
		// handlers.ValidateTxHashes(tx)
		// 5d8839c29051c0a892730be6c4f6be086904b0a6d537097df1fc92bb8d30a5ad
		// 0a8b21af1cfcc26774df1f513a72cd362a14f5a598ec39d915323078efb5a240
		if tx.TxFilename == "0a768ce65115e0bf1b4fd4b3b1c5d1a66c56a9cc41d9fc1530a7ef3e4fdeaee7.json" {
			// handlers.ValidateTxHashes(tx)
			res := handlers.VerifyTxSig(tx)
			fmt.Println("Result: ", res)
		}
	}
	// handlers.PrintCoinbaseTx()

}

func getValidTxOfCertainTypes(transactions []types.TransactionData, txType string) {
	scanLimit := make([]bool, 0)
	scanLimit = append(scanLimit, true)
	for _, tx := range transactions {
		if scanLimit[len(scanLimit)-1] {
			if len(tx.Vin) == 1 {
				if tx.Vin[0].Prevout.ScriptPubKeyType == txType {
					res := handlers.VerifyTxSig(tx)
					scanLimit = append(scanLimit, res)
				}
			}
		}

	}
}

func hashAndValidate() {
	// signatureBytes, _ := hex.DecodeString("30450221008f619822a97841ffd26eee942d41c1c4704022af2dd42600f006336ce686353a0220659476204210b21d605baab00bef7005ff30e878e911dc99413edb6c1e022acd01") // Extract from 'scriptsig'
	// // if err != nil { ... }
	// signature, _ := btcec.parse.ParseDERSignature(signatureBytes)
	// if err != nil { ... }

	pubKeyBytes, _ := hex.DecodeString("02e57d639eb8ad9feeda51d951c33feed17c2ad7946c3a7223513fb912a5b2363b") // Extract from 'scriptsig'
	// if err != nil { ... }
	// pubKey, _ := btcec.ParsePubKey(pubKeyBytes)

	pubKeyHashBytes, _ := hex.DecodeString("4cf014394e1aa81ca0317ad24c3a886040e80da7") // Extract from 'scriptpubkey'

	val := btcutil.Hash160(pubKeyBytes)
	fmt.Println("pubkey bytes ", pubKeyBytes, "\nhash is: ", val, "pubKey: ", pubKeyHashBytes)

	if bytes.Equal(val, pubKeyHashBytes) {
		fmt.Println("Valid signature")
	} else {
		fmt.Println("Invalid signature")

	}
}

func hashAndValidatePSH() {
	// signatureBytes, _ := hex.DecodeString("30450221008f619822a97841ffd26eee942d41c1c4704022af2dd42600f006336ce686353a0220659476204210b21d605baab00bef7005ff30e878e911dc99413edb6c1e022acd01") // Extract from 'scriptsig'
	// // if err != nil { ... }
	// signature, _ := btcec.parse.ParseDERSignature(signatureBytes)
	// if err != nil { ... }

	redeemScriptBytes, _ := hex.DecodeString("0014a275e7990a2a2d7ffda637613b29e680b2cc7048") // Extract from 'scriptsig'
	// if err != nil { ... }
	// pubKey, _ := btcec.ParsePubKey(pubKeyBytes)

	redeemScriptHashBytes, _ := hex.DecodeString("06f19824aff9b90bb52b859f64f27c9837ee3fa9") // Extract from 'scriptpubkey'

	val := btcutil.Hash160(redeemScriptBytes)
	fmt.Println("pubkey bytes ", redeemScriptBytes, "\nhash is: ", val, "pubKey: ", redeemScriptHashBytes)

	if bytes.Equal(val, redeemScriptHashBytes) {
		fmt.Println("Valid signature")
	} else {
		fmt.Println("Invalid signature")

	}
}
