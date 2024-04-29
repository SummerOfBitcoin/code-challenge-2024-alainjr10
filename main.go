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
	// Sort transactions based on fee/weight ratio
	handlers.SortTxs(transactions)
	var allTxs []*wire.MsgTx
	var validTxs []*wire.MsgTx
	var validTxsWithWitness []*wire.MsgTx
	txTotalSize := 0 // get the size of searialized txs (with witness and flags)
	txTotalBaseSize := 0
	totalBlockWeight := 320 + 800*2 // 320 is the size of the block header and 600 is the  approx size of the coinbase tx
	// with margin of error. we do 800*2 because... coinbase tx weight for nonsegwit and for segwit serialzing the tx with witness
	for _, tx := range transactions {
		if len(tx.Vin) >= 1 {
			// we have several if's here because we initially picked a few types of transactions to verify. ideally, this code should
			// work on any of the given input types of transactions in the mempool currently
			if tx.Vin[0].Prevout.ScriptPubKeyType == "p2pkh" || tx.Vin[0].Prevout.ScriptPubKeyType == "v0_p2wpkh" || tx.Vin[0].Prevout.ScriptPubKeyType == "v0_p2wsh" || tx.Vin[0].Prevout.ScriptPubKeyType == "v1_p2tr" || tx.Vin[0].Prevout.ScriptPubKeyType == "p2sh" {
				// the FullTxValidation function performs several checks to see if the transaction is valid and if it is, it returns true
				res := handlers.FullTxValidation(tx)
				serializedAllTx, _, _, _ := handlers.SerializeATx(tx)
				allTxs = append(allTxs, serializedAllTx)
				// if the transaction is valid, we serialize it and add it to the validTxs slice
				if res {
					// our [SeruakuzeATx] function returns 4 outputs, a normal serialized transaction without any witnesses, a sealialized
					// transaction with witnesses, the bytes of the serialized transaction and the bytes of the serialized transaction with witnesses
					serializedTx, serializedTxWithWitness, serializedTxBytes, serializedWitnessTxBytes := handlers.SerializeATx(tx)
					txBaseSize := len(serializedTxBytes)
					txSizeWWit := len(serializedWitnessTxBytes)
					txTotalBaseSize += txBaseSize
					txTotalSize += txSizeWWit
					// we calculate the weight units of the transaction and add it to the total block weight, this block weight unit is calculated
					// by adding the base size of the transaction multiplied by 3 and the size of the transaction with witness
					// we stop adding transactions to the block if the total block weight is greater than 3999999 as max block weight is 4,000,000
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
	// after creating the commitment script, we then update our already created coinbase transaction with this witness script
	modCoinbaseTx := handlers.CreateAndModCoinbaseTxWithSecondOutput(coinbaseComScript)
	var coinbaseTxBytesBuf bytes.Buffer
	modCoinbaseTx.Serialize(&coinbaseTxBytesBuf)
	txTotalSize += len(coinbaseTxBytesBuf.Bytes())
	txTotalBaseSize += len(coinbaseTxBytesBuf.Bytes())
	fmt.Println("total txs: ", len(allTxs), "validtxs: ", len(validTxs), "block weight unit: ", totalBlockWeight)
	handlers.VerifyBlock(validTxs, modCoinbaseTx, txTotalSize)

}
