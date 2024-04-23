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
	// getValidTxOfCertainTypes(transactions, "p2pkh")
	// validTxIds := make([]string, 0)
	// validRawTxs := make([]string, 0)
	var validTxs []*wire.MsgTx
	var validTxsWithWitness []*wire.MsgTx
	// coinbaseTxBytes, coinbaseTxHex := handlers.PrintCoinbaseTx()
	// coinbaseTxId := chainhash.DoubleHashH(coinbaseTxBytes)
	// validTxIds = append(validTxIds, coinbaseTxId.String())
	// validRawTxs = append(validRawTxs, coinbaseTxHex)
	txTotalSize := 0 // get the size of searialized txs (with witness and flags)
	txTotalBaseSize := 0
	totalBlockWeight := 320 + 800*2 // 320 is the size of the block header and 600 is the  approx size of the coinbase tx
	// with margin of error. we do 800*2 because... coinbase tx weight for nonsegwit and for segwit serialzing the tx with witness
	for _, tx := range transactions {
		// hasSameVins := true
		// for _, vin := range tx.Vin {
		// 	firstVin := tx.Vin[0]
		// 	// if vin.Prevout.ScriptPubKeyType == "p2sh" && len(tx.Vin) == 1 && len(vin.Witness) == 2 {
		// 	// 	p2msno++
		// 	// 	hasSameVins = false
		// 	// 	break
		// 	// }
		// 	if vin.Prevout.ScriptPubKeyType != firstVin.Prevout.ScriptPubKeyType {
		// 		hasSameVins = false
		// 		break
		// 	}
		// }
		// if !hasSameVins {
		// 	fmt.Println("tx wit multiple vin: ", tx.TxFilename, "index: ", i, "p2msno: ", p2msno)
		// }
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
		// if len(validTxIds) < 5 {
		// if totalBlockWeight > 3999999 {
		// 	break
		// }
		if len(tx.Vin) == 1 {
			// if tx.Vin[0].Prevout.ScriptPubKeyType == "v0_p2wsh" {
			// 	fmt.Println("PSWSH: ", tx.TxFilename)
			// }
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
					// serializedTxHex := hex.EncodeToString(serializedTxBytes)
					// serializedTxId := chainhash.DoubleHashH(serializedTxBytes)
					totalBlockWeight += txBaseSize*3 + txSizeWWit
					if totalBlockWeight > 3999999 {
						break
					}
					// validTxIds = append(validTxIds, serializedTxId.String())
					// validRawTxs = append(validRawTxs, serializedTxHex)
					validTxs = append(validTxs, serializedTx)
					validTxsWithWitness = append(validTxsWithWitness, serializedTxWithWitness)
				}
			} else {
				continue
			}
		} else {
			continue
		}

		// } else {
		// 	break
		// }

	}
	// fmt.Println("length of valid TxIds, ", len(validTxIds))
	// handlers.CreateMerkleTree(validTxIds)
	// handlers.SerializedBlockTxs(validRawTxs)
	// handlers.CreateBlockHeader()
	coinbaseComScript := handlers.CreateCoinbaseCommittmentScript(validTxsWithWitness)
	modCoinbaseTx := handlers.CreateAndModCoinbaseTxWithSecondOutput(coinbaseComScript)
	var coinbaseTxBytesBuf bytes.Buffer
	modCoinbaseTx.Serialize(&coinbaseTxBytesBuf)
	txTotalSize += len(coinbaseTxBytesBuf.Bytes())
	txTotalBaseSize += len(coinbaseTxBytesBuf.Bytes())
	fmt.Println("total txs: ", len(allTxs), "validtxs: ", len(validTxs), "block weight unit: ", totalBlockWeight)
	handlers.VerifyBlock(validTxs, modCoinbaseTx, txTotalSize)

}
