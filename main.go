package main

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"

	"github.com/SummerOfBitcoin/code-challenge-2024-alainjr10/handlers"
	"github.com/SummerOfBitcoin/code-challenge-2024-alainjr10/types"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"
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
	validTxIds := make([]string, 0)
	validRawTxs := make([]string, 0)
	var validTxs []*wire.MsgTx
	coinbaseTxBytes, coinbaseTxHex := handlers.PrintCoinbaseTx()
	coinbaseTxId := chainhash.DoubleHashH(coinbaseTxBytes)
	validTxIds = append(validTxIds, coinbaseTxId.String())
	validRawTxs = append(validRawTxs, coinbaseTxHex)
	for _, tx := range transactions {
		// handlers.ValidateTxHashes(tx)
		// 5d8839c29051c0a892730be6c4f6be086904b0a6d537097df1fc92bb8d30a5ad
		// 0a8b21af1cfcc26774df1f513a72cd362a14f5a598ec39d915323078efb5a240 p2pkh
		// 0a768ce65115e0bf1b4fd4b3b1c5d1a66c56a9cc41d9fc1530a7ef3e4fdeaee7 p2wpkh
		// 0a07736090b0677920c14d64e12e81cbb5e9d2fbcfeea536cda7d571b6d4607f p2wpkh
		// 002f5ff2f870154b109d823bbad6fd349582d5b85ead5ce0f9f7a4a0270ce37a p2wpkh
		// if tx.TxFilename == "002f5ff2f870154b109d823bbad6fd349582d5b85ead5ce0f9f7a4a0270ce37a.json" {
		// 	handlers.ValidateTxHashes(tx)
		// 	res := handlers.VerifyTxSig(tx)
		// 	fmt.Println("Result: ", res)
		// }
		if len(validTxIds) < 5 {
			if len(tx.Vin) == 1 {
				if tx.Vin[0].Prevout.ScriptPubKeyType == "p2pkh" || tx.Vin[0].Prevout.ScriptPubKeyType == "v0_p2wpkh" {
					res := handlers.FullTxValidation(tx)
					if res {
						serializedTx, serializedTxBytes := handlers.SerializeATx(tx)
						serializedTxHex := hex.EncodeToString(serializedTxBytes)
						serializedTxId := chainhash.DoubleHashH(serializedTxBytes)
						validTxIds = append(validTxIds, serializedTxId.String())
						validRawTxs = append(validRawTxs, serializedTxHex)
						validTxs = append(validTxs, serializedTx)
					}
				} else {
					continue
				}
			} else {
				continue
			}

		} else {
			break
		}

	}
	// fmt.Println("length of valid TxIds, ", len(validTxIds))
	// handlers.CreateMerkleTree(validTxIds)
	// handlers.SerializedBlockTxs(validRawTxs)

	// handlers.CreateBlockHeader()
	handlers.VerifyBlock(validTxs)

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
