package handlers

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/SummerOfBitcoin/code-challenge-2024-alainjr10/types"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/ecdsa"
	"github.com/btcsuite/btcd/btcutil"

	// "github.com/btcsuite/btcd/btcutil"
	// "github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	// "github.com/btcsuite/btcd/txscript"
	"github.com/btcsuite/btcd/wire"
)

func ValidateTxHashes(transaction types.TransactionData) {
	// we will take the already provided hash of pubkey/redeemscript from the scriptpubkey AND COMPARE
	// it with the hash of the pubkey/redeemscript extracted from the scriptsig
	// WE WILL CALL THE PUBKEY/REDEEMSCRIPT VARIABLE 'rawKey' FOR SIMPLICITY and 'rawKeyHash' FOR THE HASH
	txIsVerified := true
	overallStack := new(types.Stack)
	for i, input := range transaction.Vin {
		stack := new(types.Stack)
		if transaction.Vin[i].Prevout.ScriptPubKeyType == "v0_p2wpkh" {
			sigBytes, _ := hex.DecodeString(input.ScriptSig)
			pubKeyBytes, _ := hex.DecodeString(input.Witness[1])
			stack.Push(sigBytes)
			stack.Push(pubKeyBytes)
			hashPubKey := btcutil.Hash160(pubKeyBytes)
			stack.Push(hashPubKey)
			scriptPubKeyAsm := strings.Split(input.Prevout.ScriptPubKeyAsm, " ")
			if len(scriptPubKeyAsm) >= 3 {
				// here we extract hashed pubkey from scriptpubkey and add it to the stack
				hashedKey, _ := hex.DecodeString(scriptPubKeyAsm[2])
				stack.Push(hashedKey)
			}
			providedPubKeyHash, _ := stack.Pop()
			hashedPubKey, _ := stack.Pop()
			if bytes.Equal(providedPubKeyHash, hashedPubKey) {
				// fmt.Println("Valid input")
				stack.Push([]byte{0x01})
				overallStack.Push([]byte{0x01})
			} else {
				// fmt.Println("Invalid input")
				stack.Push([]byte{0x00})
				overallStack.Push([]byte{0x00})
				break
			}

		} else if transaction.Vin[i].Prevout.ScriptPubKeyType == "p2pkh" {
			fmt.Println("\n IS P2PKH ")
			splitScriptSigAsm := strings.Split(input.ScriptSigAsm, " ")
			sigBytes, _ := hex.DecodeString(splitScriptSigAsm[1])
			pubKeyBytes, _ := hex.DecodeString(splitScriptSigAsm[3]) // in this case, we are extracting the redeemscript
			stack.Push(sigBytes)
			stack.Push(pubKeyBytes)
			hashPubKey := btcutil.Hash160(pubKeyBytes)
			stack.Push(hashPubKey)
			scriptPubKeyAsm := strings.Split(input.Prevout.ScriptPubKeyAsm, " ")
			if len(scriptPubKeyAsm) >= 4 {
				// here we extract hashed pubkey from scriptpubkey and add it to the stack
				hashedKey, _ := hex.DecodeString(scriptPubKeyAsm[3])
				stack.Push(hashedKey)
			}
			providedPubKeyHash, _ := stack.Pop()
			hashedPubKey, _ := stack.Pop()
			if bytes.Equal(providedPubKeyHash, hashedPubKey) {
				// fmt.Println("Valid input")
				stack.Push([]byte{0x01})
				overallStack.Push([]byte{0x01})
			} else {
				// fmt.Println("Invalid input")
				stack.Push([]byte{0x00})
				overallStack.Push([]byte{0x00})
				break
			}
		} else if transaction.Vin[i].Prevout.ScriptPubKeyType == "p2sh" {
			fmt.Println("\n IS P2SH ")
			sigBytes, _ := hex.DecodeString(input.ScriptSig)
			splitScriptSigAsm := strings.Split(input.ScriptSigAsm, " ")
			pubKeyBytes, _ := hex.DecodeString(splitScriptSigAsm[1]) // in this case, we are extracting the redeemscript
			stack.Push([]byte{0x00})
			stack.Push(sigBytes)
			// stack.Push(pubKeyBytes)
			hashPubKey := btcutil.Hash160(pubKeyBytes)
			stack.Push(hashPubKey)
			scriptPubKeyAsm := strings.Split(input.Prevout.ScriptPubKeyAsm, " ")
			if len(scriptPubKeyAsm) >= 3 {
				// here we extract hashed pubkey from scriptpubkey and add it to the stack
				hashedKey, _ := hex.DecodeString(scriptPubKeyAsm[2])
				stack.Push(hashedKey)
			}
			providedPubKeyHash, _ := stack.Pop()
			hashedPubKey, _ := stack.Pop()
			if bytes.Equal(providedPubKeyHash, hashedPubKey) {
				// fmt.Println("Valid input")
				stack.Push([]byte{0x01})
				overallStack.Push([]byte{0x01})
			} else {
				// fmt.Println("Invalid input")
				stack.Push([]byte{0x00})
				overallStack.Push([]byte{0x00})
				break
			}
		} else if transaction.Vin[i].Prevout.ScriptPubKeyType == "v0_p2wsh" {
			// TODO Come to this later
			continue

			// fmt.Println("\n IS P2WSH ")
			// sigBytes, _ := hex.DecodeString(input.ScriptSig)
			// splitScriptSigAsm := strings.Split(input.ScriptSigAsm, " ")
			// pubKeyBytes, _ := hex.DecodeString(splitScriptSigAsm[1]) // in this case, we are extracting the redeemscript
			// stack.Push([]byte{0x00})
			// stack.Push(sigBytes)
			// // stack.Push(pubKeyBytes)
			// hashPubKey := btcutil.Hash160(pubKeyBytes)
			// stack.Push(hashPubKey)
			// scriptPubKeyAsm := strings.Split(input.Prevout.ScriptPubKeyAsm, " ")
			// if len(scriptPubKeyAsm) >= 3 {
			// 	// here we extract hashed pubkey from scriptpubkey and add it to the stack
			// 	hashedKey, _ := hex.DecodeString(scriptPubKeyAsm[2])
			// 	stack.Push(hashedKey)
			// }
			// providedPubKeyHash, _ := stack.Pop()
			// hashedPubKey, _ := stack.Pop()
			// if bytes.Equal(providedPubKeyHash, hashedPubKey) {
			// 	// fmt.Println("Valid input")
			// 	stack.Push([]byte{0x01})
			// 	overallStack.Push([]byte{0x01})
			// } else {
			// 	// fmt.Println("Invalid input")
			// 	stack.Push([]byte{0x00})
			// 	overallStack.Push([]byte{0x00})
			// 	break
			// }
		} else {
			overallStack.Push([]byte{0x01})
			fmt.Println("Not handled")
			continue
		}

	}
	stackT, _ := overallStack.Pop()
	if stackT[0] == 0x01 {
		fmt.Println("Valid transaction")
		txIsVerified = true
	} else {
		fmt.Println("Invalid transaction")
		txIsVerified = false
	}

	hexEncodedTx := hex.EncodeToString(SerializeATx(transaction))
	fileName := GetFileName(hexEncodedTx)
	fmt.Println("Tx Name:", hex.EncodeToString(fileName[:]), "File name: ", transaction.TxFilename, "\nverified:", txIsVerified)
}

func SerializeATx(transaction types.TransactionData) []byte {
	numberOfInputs := len(transaction.Vin)
	numberOfOutputs := len(transaction.Vout)
	tx := wire.NewMsgTx(int32(transaction.Version))

	// Add the inputs
	for i := 0; i < numberOfInputs; i++ {
		var txIn *wire.TxIn
		input := transaction.Vin[i]
		prevOutHash, _ := chainhash.NewHashFromStr(input.TxID)
		prevOut := wire.NewOutPoint(prevOutHash, uint32(input.Vout))
		scriptSig, _ := hex.DecodeString(input.ScriptSig)
		var witness [][]byte
		if transaction.Vin[i].Witness != nil && len(transaction.Vin[i].Witness) > 0 {
			witness = make([][]byte, len(input.Witness))
			for i, w := range input.Witness {
				witness[i], _ = hex.DecodeString(w)
			}
			txIn = wire.NewTxIn(prevOut, scriptSig, nil)
		} else {
			txIn = wire.NewTxIn(prevOut, scriptSig, nil)
		}

		txIn.Sequence = uint32(input.Sequence)
		tx.AddTxIn(txIn)
	}

	// Add the outputs
	for i := 0; i < numberOfOutputs; i++ {
		output := transaction.Vout[i]
		scriptPubKey, _ := hex.DecodeString(output.ScriptPubKey)
		txOut := wire.NewTxOut(int64(output.Value), scriptPubKey)
		tx.AddTxOut(txOut)
	}

	tx.LockTime = uint32(transaction.Locktime)

	// Serialize
	var txBuffer bytes.Buffer
	// tx.Serialize(&txBuffer)
	serializeErr := tx.Serialize(&txBuffer)
	if serializeErr != nil {
		fmt.Println("Error serializing transaction:", serializeErr)
		return nil
	}
	rawTxBytes := txBuffer.Bytes()
	return rawTxBytes
}

func SerializeATxWOSigScript(transaction types.TransactionData) []byte {
	numberOfInputs := len(transaction.Vin)
	numberOfOutputs := len(transaction.Vout)
	tx := wire.NewMsgTx(int32(transaction.Version))

	// Add the inputs
	for i := 0; i < numberOfInputs; i++ {
		var txIn *wire.TxIn
		input := transaction.Vin[i]
		prevOutHash, _ := chainhash.NewHashFromStr(input.TxID)
		prevOut := wire.NewOutPoint(prevOutHash, uint32(input.Vout))
		scripPubKey, _ := hex.DecodeString(input.Prevout.ScriptPubKey)
		if transaction.Vin[i].Prevout.ScriptPubKeyType == "p2sh" {
			// fmt.Println("IS P2SH from SerializeATxWOSigScript")
			// replaceWith, _ := hex.DecodeString("00ad905988127d78c35838f9bef57b90a612bd43c0")
			txIn = wire.NewTxIn(prevOut, []byte{}, nil)
		} else if transaction.Vin[i].Prevout.ScriptPubKeyType == "p2pkh" {
			// fmt.Println("\n IS P2PKH from SerializeATxWOSigScript")
			txIn = wire.NewTxIn(prevOut, scripPubKey, nil)
		} else if transaction.Vin[i].Prevout.ScriptPubKeyType == "v0_p2wpkh" {
			// fmt.Println("\n IS P2PKH from SerializeATxWOSigScript")
			witness0, _ := hex.DecodeString(input.Witness[0])
			witness1, _ := hex.DecodeString(input.Witness[1])
			witness := [][]byte{
				witness0,
				witness1,
				// []byte(input.Witness[0]),
				// []byte(input.Witness[1]),
			}
			txIn = wire.NewTxIn(prevOut, nil, witness)
		}

		txIn.Sequence = uint32(input.Sequence)
		tx.AddTxIn(txIn)
	}

	// Add the outputs
	for i := 0; i < numberOfOutputs; i++ {
		output := transaction.Vout[i]
		scriptPubKey, _ := hex.DecodeString(output.ScriptPubKey)
		txOut := wire.NewTxOut(int64(output.Value), scriptPubKey)
		tx.AddTxOut(txOut)
	}

	tx.LockTime = uint32(transaction.Locktime)

	// Serialize
	var txBuffer bytes.Buffer
	// tx.Serialize(&txBuffer)
	serializeErr := tx.Serialize(&txBuffer)
	if serializeErr != nil {
		fmt.Println("Error serializing transaction:", serializeErr)
		return nil
	}
	var rawTxBytes []byte
	if transaction.Vin[0].Prevout.ScriptPubKeyType == "p2pkh" { // this is just temporary and a more robust way of handling this should be implemented
		rawTxBytes = txBuffer.Bytes()
	} else if transaction.Vin[0].Prevout.ScriptPubKeyType == "v0_p2wpkhh" {
		input := transaction.Vin[0]
		intm := hex.EncodeToString(txBuffer.Bytes())
		// intermediateHash := chainhash.DoubleHashB(txBuffer.Bytes())
		// hexEncodedIntermediateHash := hex.EncodeToString(intermediateHash)
		// serializedOutpoint := tx.TxIn[0].PreviousOutPoint.String()
		hashedTxId, _ := chainhash.NewHashFromStr(input.TxID)
		reversedVoutBytes, _ := hex.DecodeString(fmt.Sprintf("%08x", input.Vout))
		reversedVout := hex.EncodeToString(ReverseSlice(reversedVoutBytes))
		serializedInput := hashedTxId.String() + reversedVout
		serializedOutpoint := serializedInput
		// serializedInputBytes, _ := hex.DecodeString(serializedInput)
		// spentOutpoint := hashSerializedOutpoint.String()
		scriptPubKeyAsm := strings.Split(transaction.Vin[0].Prevout.ScriptPubKeyAsm, " ")
		pubkeyHashStr := scriptPubKeyAsm[2]
		scriptCode := "1976a914" + pubkeyHashStr + "88ac"
		amt := tx.TxOut[0].Value
		amtP := fmt.Sprintf("%016x", amt)
		amtBytes, _ := hex.DecodeString(amtP)
		reversedAmt := ReverseSlice(amtBytes)
		hexEncodedAmt := hex.EncodeToString(reversedAmt)
		// seqHex := fmt.Sprintf("%x", tx.TxIn[0].Sequence)
		fmt.Println("intm:", intm, "\nserializedOutpoint:", serializedOutpoint, "\nscriptCode:", scriptCode, "\nhexEncodedAmt:", hexEncodedAmt)
		// preImg := hexEncodedIntermediateHash + serializedOutpoint + scriptCode + hexEncodedAmt
		preImg := intm + serializedOutpoint + scriptCode + hexEncodedAmt
		fmt.Println("Preimage:", preImg)
		preImgBytes, err := hex.DecodeString(preImg)
		if err != nil {
			fmt.Println("Error decoding preimage:", err)
		}
		hashedPreImg := chainhash.HashB(preImgBytes)
		return hashedPreImg
	} else {
		input := transaction.Vin[0]
		version := transaction.Version
		versionFormatted := fmt.Sprintf("%08x", version)
		versionBytes, _ := hex.DecodeString(versionFormatted)
		versionBytes = ReverseSlice(versionBytes)
		hexVersion := hex.EncodeToString(versionBytes)
		hashedTxId, _ := chainhash.NewHashFromStr(input.TxID)
		reversedVoutBytes, _ := hex.DecodeString(fmt.Sprintf("%08x", input.Vout))
		reversedVout := hex.EncodeToString(ReverseSlice(reversedVoutBytes))
		serializedInput := hashedTxId.String() + reversedVout
		serializedInputBytes, _ := hex.DecodeString(serializedInput)
		hashInput := chainhash.Hash(serializedInputBytes)
		// get all the sequences from inputs and hash each of them
		sequencesHex := fmt.Sprintf("%08x", input.Sequence)
		sequencesBytes, _ := hex.DecodeString(sequencesHex)
		sequencesHash := chainhash.HashH(sequencesBytes)
		// since i have just one input and it's what i want to sign, i use the value as gotten above
		serializedInputToSign := serializedInput
		scriptPubKeyAsm := strings.Split(transaction.Vin[0].Prevout.ScriptPubKeyAsm, " ")
		pubkeyHashStr := scriptPubKeyAsm[2]
		scriptCode := "1976a914" + pubkeyHashStr + "88ac"
		amt := tx.TxOut[0].Value
		amtP := fmt.Sprintf("%016x", amt)
		amtBytes, _ := hex.DecodeString(amtP)
		reversedAmt := ReverseSlice(amtBytes)
		hexEncodedAmt := hex.EncodeToString(reversedAmt)
		// get the sequence of the input we want to sign and serialize. this is same as above since we have just one input, so
		serializeSequenceToSign := sequencesHex
		// now serialize outputs and hash em
		output1AmtBytes, _ := hex.DecodeString(fmt.Sprintf("%016x", tx.TxOut[0].Value))
		hexReverseOutput1Amt := hex.EncodeToString(ReverseSlice(output1AmtBytes))
		output1ScriptPubKeyLen := len(tx.TxOut[0].PkScript)
		output1ScriptPubKey := hex.EncodeToString(tx.TxOut[0].PkScript)
		output2AmtBytes, _ := hex.DecodeString(fmt.Sprintf("%016x", tx.TxOut[1].Value))
		hexReverseOutput2Amt := hex.EncodeToString(ReverseSlice(output2AmtBytes))
		output2ScriptPubKeyLen := len(tx.TxOut[1].PkScript)
		output2ScriptPubKey := hex.EncodeToString(tx.TxOut[1].PkScript)
		outputsSerialized := hexReverseOutput1Amt + fmt.Sprintf("%02x", output1ScriptPubKeyLen) + output1ScriptPubKey + hexReverseOutput2Amt + fmt.Sprintf("%02x", output2ScriptPubKeyLen) + output2ScriptPubKey
		outputsHash := chainhash.HashB([]byte(outputsSerialized))
		outputsHashHex := hex.EncodeToString(outputsHash)
		preImg := hexVersion + hashInput.String() + sequencesHash.String() + serializedInputToSign + scriptCode + hexEncodedAmt + serializeSequenceToSign + outputsHashHex
		// let's print the various components separately
		fmt.Println("version: ", hexVersion, "\nhashInput: ", hashInput.String(), "\nsequencesHash: ", sequencesHash.String(), "\nserializedInputToSign: ", serializedInputToSign, "\nscriptCode: ", scriptCode, "\nhexEncodedAmt: ", hexEncodedAmt, "\nserializeSequenceToSign: ", serializeSequenceToSign, "\noutputsHashHex: ", outputsHashHex)
		fmt.Println("Preimage 2:", preImg)
		preImgBytes, err := hex.DecodeString(preImg)
		if err != nil {
			fmt.Println("Error decoding preimage2:", err)
		}
		hashedPreImg := chainhash.HashB(preImgBytes)
		return hashedPreImg
	}

	return rawTxBytes
}

func VerifyTxSig(transaction types.TransactionData) bool {

	rawTxBytes := SerializeATxWOSigScript(transaction)
	hextx := hex.EncodeToString(rawTxBytes)
	fmt.Println("Raw tx bytes:", hextx)
	var sig []byte
	var pubKeyBytes []byte
	if transaction.Vin[0].Prevout.ScriptPubKeyType == "p2pkh" {
		scriptSigAsm := strings.Split(transaction.Vin[0].ScriptSigAsm, " ")
		sig, _ = hex.DecodeString(scriptSigAsm[1])
		pubKeyBytes, _ = hex.DecodeString(scriptSigAsm[3])
	} else if transaction.Vin[0].Prevout.ScriptPubKeyType == "v0_p2wpkh" {
		sig, _ = hex.DecodeString(transaction.Vin[0].Witness[0])
		pubKeyBytes, _ = hex.DecodeString(transaction.Vin[0].Witness[1])
	} else if transaction.Vin[0].Prevout.ScriptPubKeyType == "p2sh" {
		sig, _ = hex.DecodeString(transaction.Vin[0].Witness[0])
		pubKeyBytes, _ = hex.DecodeString(transaction.Vin[0].Witness[1])
	} else if transaction.Vin[0].Prevout.ScriptPubKeyType == "v0_p2wsh" {
		// TODO Come to this later
		return false

	}
	// Parse the DER encoded signature
	signature, _ := ecdsa.ParseDERSignature(sig)
	pubKey, _ := btcec.ParsePubKey(pubKeyBytes)

	sigHashType := uint32(0x01)

	// make a copy of the rawtxbytes
	// rawTxBytesCopy := make([]byte, len(rawTxBytes))
	// Append the SIGHASH type to the serialized data
	rawTxBytes = append(rawTxBytes, byte(sigHashType))
	rawTxBytes = append(rawTxBytes, byte(sigHashType>>8))
	rawTxBytes = append(rawTxBytes, byte(sigHashType>>16))
	rawTxBytes = append(rawTxBytes, byte(sigHashType>>24))

	txDoubleHash := chainhash.DoubleHashB(rawTxBytes)
	verified := signature.Verify(txDoubleHash, pubKey)
	fmt.Println("verified:", verified)
	return verified
}

func SerializeTx() {
	tx := wire.NewMsgTx(1)

	// Input
	prevOutHash, _ := chainhash.NewHashFromStr("5f5f37217202525d50748cfa402f7b8ba76b133081ff075231fab63267cdc19c") // prev out txid
	prevOut := wire.NewOutPoint(prevOutHash, 1)
	scriptSig, _ := hex.DecodeString("160014ad905988127d78c35838f9bef57b90a612bd43c0")
	txIn := wire.NewTxIn(prevOut, scriptSig, nil)
	txIn.Sequence = 4294967293 // Max sequence number
	tx.AddTxIn(txIn)

	// Outputs
	output1ScriptPubKey, _ := hex.DecodeString("0014f232b1227ee9da844eac61068ffdec9da57f2112")
	txOut1 := wire.NewTxOut(72187, output1ScriptPubKey)
	tx.AddTxOut(txOut1)

	output2ScriptPubKey, _ := hex.DecodeString("a9143bca7dd81f2b55f433a088a7f6f42e194dcf6a1287")
	txOut2 := wire.NewTxOut(405008, output2ScriptPubKey)
	tx.AddTxOut(txOut2)

	tx.LockTime = 0

	// output1Addr, err := btcutil.DecodeAddress("bc1q7getzgn7a8dggn4vvyrgll0vnkjh7ggj8u9ufr", &chaincfg.MainNetParams)
	// if err != nil {
	// 	fmt.Println("Error decoding address:", err)
	// 	return
	// }
	// output1ScriptPubKey, err := txscript.PayToAddrScript(output1Addr)
	// if err != nil {
	// 	fmt.Println("Error creating scriptPubKey:", err)
	// 	return
	// }
	// txOut1 := wire.NewTxOut(72187, output1ScriptPubKey)
	// tx.AddTxOut(txOut1)

	// output2Addr, err := btcutil.DecodeAddress("379ANDuUCM54wS3kbwx9KMNzy2JinPJeGL", &chaincfg.MainNetParams)
	// if err != nil {
	// 	fmt.Println("Error creating scriptPubKey:", err)
	// 	return
	// }
	// output2ScriptPubKey, err := txscript.PayToAddrScript(output2Addr)
	// if err != nil {
	// 	fmt.Println("Error creating scriptPubKey:", err)
	// 	return
	// }
	// txOut2 := wire.NewTxOut(405008, output2ScriptPubKey)
	// tx.AddTxOut(txOut2)
	// parsse the DER encoded signature
	sig, err := hex.DecodeString("30450221008f619822a97841ffd26eee942d41c1c4704022af2dd42600f006336ce686353a0220659476204210b21d605baab00bef7005ff30e878e911dc99413edb6c1e022acd01")
	pubKeyBytes, _ := hex.DecodeString("02336e005ebfc45921ce98b699cb1769febbe0b5394058108c42df2e0f358eeb77")
	if err != nil {
		fmt.Println("Error decoding signature:", err)
		return
	}
	// Parse the DER encoded signature
	signature, _ := ecdsa.ParseDERSignature(sig)
	pubKey, _ := btcec.ParsePubKey(pubKeyBytes)
	// fmt.Println("Signature:", signature, "\nPublic key:", pubKey)

	// Serialize
	var txBuffer bytes.Buffer
	// tx.Serialize(&txBuffer)
	serializeErr := tx.Serialize(&txBuffer)
	if serializeErr != nil {
		fmt.Println("Error serializing transaction:", err)
		return
	}
	rawTxBytes := txBuffer.Bytes()
	rawTxHex := hex.EncodeToString(rawTxBytes)

	sigHashType := uint32(0x01)

	// make a copy of the rawtxbytes
	// rawTxBytesCopy := make([]byte, len(rawTxBytes))
	// Append the SIGHASH type to the serialized data
	rawTxBytes = append(rawTxBytes, byte(sigHashType))
	rawTxBytes = append(rawTxBytes, byte(sigHashType>>8))
	rawTxBytes = append(rawTxBytes, byte(sigHashType>>16))
	rawTxBytes = append(rawTxBytes, byte(sigHashType>>24))
	//// These two methods, append above and what we have below have same outcome
	// rawTxHexWithSigHash := hex.EncodeToString(rawTxBytes) + "01000000"
	// rawTxBytes2, _ := hex.DecodeString(rawTxHexWithSigHash)

	hasher := sha256.Sum256(rawTxBytes)
	secondHash := sha256.Sum256(hasher[:])
	txId := hex.EncodeToString(secondHash[:])

	fileName2 := GetFileName(rawTxHex)
	txDoubleHash := chainhash.DoubleHashB(rawTxBytes)
	verified := signature.Verify(txDoubleHash, pubKey)
	fmt.Println("Transaction ID:", txId, "\nfilename:", hex.EncodeToString(fileName2[:]), "\nverified:", verified)
}

func AddSigHashTypeAndHash(rawTxBytes []byte, sigHashType uint32) []byte {
	rawTxBytes = append(rawTxBytes, byte(sigHashType))
	rawTxBytes = append(rawTxBytes, byte(sigHashType>>8))
	rawTxBytes = append(rawTxBytes, byte(sigHashType>>16))
	rawTxBytes = append(rawTxBytes, byte(sigHashType>>24))
	return rawTxBytes
}

func GetTxId(rawTxBytes []byte) string {
	hasher := sha256.Sum256(rawTxBytes)
	secondHash := sha256.Sum256(hasher[:])
	txId := hex.EncodeToString(secondHash[:])
	return txId
}

func ReverseSlice(s []byte) []byte {
	// Create a copy of the original slice
	reversed := make([]byte, len(s))
	copy(reversed, s)

	// Reverse the elements in the new slice
	for i, j := 0, len(reversed)-1; i < j; i, j = i+1, j-1 {
		reversed[i], reversed[j] = reversed[j], reversed[i]
	}

	return reversed
}

func GetFileName(hexValue string) []byte {
	value, _ := hex.DecodeString(hexValue)
	doubleHash := chainhash.DoubleHashB(value)
	reversed := ReverseSlice(doubleHash[:])
	fileName := chainhash.HashB(reversed[:])
	// fmt.Println("File name:", hex.EncodeToString(fileName[:]))
	return fileName
}

// // Helper function to reverse byte order
// func reverseBytes(bytes []byte) []byte {
// 	for i, j := 0, len(bytes)-1; i < j; i, j = i+1, j-1 {
// 		bytes[i], bytes[j] = bytes[j], bytes[i]
// 	}
// 	return bytes
// }

// func CreateTx(privKey string, destination string, amount int64) (string, error) {
// 	txid := "fb7fe37919a55dfa45a062f88bd3c7412b54de759115cb58c3b9b46ac5f7c925"

// 	wif, err := btcutil.DecodeWIF(privKey)
// 	if err != nil {
// 		return "", err
// 	}

// 	// use TestNet3Params for interacting with bitcoin testnet
// 	// if we want to interact with main net should use MainNetParams
// 	addrPubKey, err := btcutil.NewAddressPubKey(wif.PrivKey.PubKey().SerializeUncompressed(), &chaincfg.TestNet3Params)
// 	if err != nil {
// 		return "", err
// 	}

// 	txid, balance, pkScript, err := GetUTXO(addrPubKey.EncodeAddress())
// 	if err != nil {
// 		return "", err
// 	}

// 	/*
// 	 * 1 or unit-amount in Bitcoin is equal to 1 satoshi and 1 Bitcoin = 100000000 satoshi
// 	 */

// 	// checking for sufficiency of account
// 	if balance < amount {
// 		return "", fmt.Errorf("the balance of the account is not sufficient")
// 	}

// 	// extracting destination address as []byte from function argument (destination string)
// 	destinationAddr, err := btcutil.DecodeAddress(destination, &chaincfg.TestNet3Params)
// 	if err != nil {
// 		return "", err
// 	}

// 	destinationAddrByte, err := txscript.PayToAddrScript(destinationAddr)
// 	if err != nil {
// 		return "", err
// 	}

// 	// creating a new bitcoin transaction, different sections of the tx, including
// 	// input list (contain UTXOs) and outputlist (contain destination address and usually our address)
// 	// in next steps, sections will be field and pass to sign
// 	redeemTx, err := NewTx()
// 	if err != nil {
// 		return "", err
// 	}

// 	utxoHash, err := chainhash.NewHashFromStr(txid)
// 	if err != nil {
// 		return "", err
// 	}

// 	// the second argument is vout or Tx-index, which is the index
// 	// of spending UTXO in the transaction that Txid referred to
// 	// in this case is 0, but can vary different numbers
// 	outPoint := wire.NewOutPoint(utxoHash, 0)

// 	// making the input, and adding it to transaction
// 	txIn := wire.NewTxIn(outPoint, nil, nil)
// 	redeemTx.AddTxIn(txIn)

// 	// adding the destination address and the amount to
// 	// the transaction as output
// 	redeemTxOut := wire.NewTxOut(amount, destinationAddrByte)
// 	redeemTx.AddTxOut(redeemTxOut)

// 	// now sign the transaction
// 	finalRawTx, err := SignTx(privKey, pkScript, redeemTx)

// 	return finalRawTx, nil
// }

// func NewTx() (*wire.MsgTx, error) {
// 	return wire.NewMsgTx(wire.TxVersion), nil
// }
