package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"

	"github.com/SummerOfBitcoin/code-challenge-2024-alainjr10/handlers"
	"github.com/SummerOfBitcoin/code-challenge-2024-alainjr10/types"
	"github.com/btcsuite/btcd/wire"
)

func main() {
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
	handlers.SortTxs(transactions)
	var allTxs []*wire.MsgTx
	var validTxs []*wire.MsgTx
	var validTxsWithWitness []*wire.MsgTx
	txTotalSize := 0 // get the size of searialized txs (with witness and flags)
	txTotalBaseSize := 0
	totalBlockWeight := 320 + 800*2 // 320 is the size of the block header and 600 is the  approx size of the coinbase tx
	// with margin of error. we do 800*2 because... coinbase tx weight for nonsegwit and for segwit serialzing the tx with witness
	for i, tx := range transactions {
		if len(allTxs) < 200 && len(tx.Vin) > 1 {
			hasSameVins := true
			for _, vin := range tx.Vin {
				firstVin := tx.Vin[0]
				if vin.Prevout.ScriptPubKeyType != firstVin.Prevout.ScriptPubKeyType {
					hasSameVins = false
					break
				}
			}
			if !hasSameVins {
				fmt.Println("tx wit multiple vin: ", tx.TxFilename, "index: ", i)
			}
		}

		if len(tx.Vin) == 1 {
			// if len(allTxs) >= 10 {
			// 	break
			// }
			// if tx.Vin[0].Prevout.ScriptPubKeyType == "p2sh" {
			if tx.Vin[0].Prevout.ScriptPubKeyType == "p2pkh" || tx.Vin[0].Prevout.ScriptPubKeyType == "v0_p2wpkh" || tx.Vin[0].Prevout.ScriptPubKeyType == "v0_p2wsh" || tx.Vin[0].Prevout.ScriptPubKeyType == "v1_p2tr" || tx.Vin[0].Prevout.ScriptPubKeyType == "p2sh" {
				res := handlers.FullTxValidation(tx)
				serializedAllTx, _, _, _ := handlers.SerializeATx(tx)
				allTxs = append(allTxs, serializedAllTx)
				if res {
					serializedTx, serializedTxWithWitness, serializedTxBytes, serializedWitnessTxBytes := handlers.SerializeATx(tx)
					txBaseSize := len(serializedTxBytes)
					txSizeWWit := len(serializedWitnessTxBytes)
					txTotalBaseSize += txBaseSize
					txTotalSize += txSizeWWit
					totalBlockWeight += txBaseSize*3 + txSizeWWit
					if totalBlockWeight > 3999999 {
						break
					}
					validTxs = append(validTxs, serializedTx)
					validTxsWithWitness = append(validTxsWithWitness, serializedTxWithWitness)
				}
			} else {
				continue
			}
		} else {
			continue
		}
	}
	coinbaseComScript := handlers.CreateCoinbaseCommittmentScript(validTxsWithWitness)
	modCoinbaseTx := handlers.CreateAndModCoinbaseTxWithSecondOutput(coinbaseComScript)
	var coinbaseTxBytesBuf bytes.Buffer
	modCoinbaseTx.Serialize(&coinbaseTxBytesBuf)
	txTotalSize += len(coinbaseTxBytesBuf.Bytes())
	txTotalBaseSize += len(coinbaseTxBytesBuf.Bytes())
	fmt.Println("total txs: ", len(allTxs), "validtxs: ", len(validTxs), "block weight unit: ", totalBlockWeight)
	handlers.VerifyBlock(validTxs, modCoinbaseTx, txTotalSize)

}
