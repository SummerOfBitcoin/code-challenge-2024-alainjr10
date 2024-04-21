package handlers

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"
	"time"

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

func FullTxValidation(transaction types.TransactionData) bool {
	timeLockValid := ValidateTxTimeLock(transaction)
	var validateHashes bool
	var verifyTxSig bool
	if timeLockValid {
		validateHashes = ValidateTxHashes(transaction)
		verifyTxSig = VerifyTxSig(transaction)
	}

	return validateHashes && verifyTxSig && timeLockValid
}

func ValidateTxTimeLock(transaction types.TransactionData) bool {
	// assume relative time locks as valid tx, also absolute timelocs based on block height should be valid too
	// if the locktime is less than 500000000, then it's a block height locktime and should be valid
	txTimeIsValid := false
	relativeTimeLockSequenceMaxVal, strconvErr := strconv.ParseInt("0xefffffff", 0, 64)
	if strconvErr != nil {
		fmt.Println("Error converting hex to int: ", strconvErr)
		return false
	}
	timeNow := time.Now().Unix()
	if transaction.Locktime > int(timeNow) {
		txTimeIsValid = false
	} else if transaction.Locktime < 500000000 {
		txTimeIsValid = true
	} else {
		for _, vins := range transaction.Vin {
			hexSequence := fmt.Sprintf("%x", vins.Sequence)
			if hexSequence == "ffffffff" {
				txTimeIsValid = true
			} else if vins.Sequence <= int(relativeTimeLockSequenceMaxVal) {
				txTimeIsValid = true
			} else {
				txTimeIsValid = false
				break
			}
		}
	}

	return txTimeIsValid
}

func ValidateTxHashes(transaction types.TransactionData) bool {
	// we will take the already provided hash of pubkey/redeemscript from the scriptpubkey AND COMPARE
	// it with the hash of the pubkey/redeemscript extracted from the scriptsig
	// WE WILL CALL THE PUBKEY/REDEEMSCRIPT VARIABLE 'rawKey' FOR SIMPLICITY and 'rawKeyHash' FOR THE HASH
	txIsVerified := true
	overallStack := new(types.Stack)
	for i, input := range transaction.Vin {
		stack := new(types.Stack)
		if transaction.Vin[i].Prevout.ScriptPubKeyType == "v0_p2wpkh" {
			sigBytes, _ := hex.DecodeString(input.ScriptSig)
			pubKeyBytes, _ := hex.DecodeString(input.Witness[1]) // in this case, we are extracting the redeemscript
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
			// fmt.Println("\n IS P2PKH ")
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

			sigBytes, _ := hex.DecodeString(input.ScriptSig)
			pubKeyBytes, _ := hex.DecodeString(input.Witness[len(input.Witness)-1]) // in this case, we are extracting the redeemscript
			stack.Push(sigBytes)
			stack.Push(pubKeyBytes)
			hashPubKey := chainhash.HashB(pubKeyBytes)
			stack.Push(hashPubKey)
			scriptPubKeyAsm := strings.Split(input.Prevout.ScriptPubKeyAsm, " ")
			if len(scriptPubKeyAsm) >= 3 {
				// here we extract hashed pubkey from scriptpubkey and add it to the stack
				hashedKey, _ := hex.DecodeString(scriptPubKeyAsm[2])
				stack.Push(hashedKey)
			}
			providedPubKeyHash, _ := stack.Pop()
			hashedPubKey, _ := stack.Pop()
			// fmt.Println("hashed val: ", hex.EncodeToString(hashedPubKey))
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
		} else {
			overallStack.Push([]byte{0x01})
			fmt.Println("Not handled")
			continue
		}

	}
	stackT, _ := overallStack.Pop()
	if stackT[0] == 0x01 {
		// fmt.Println("Valid transaction")
		txIsVerified = true
	} else {
		fmt.Println("Invalid transaction")
		txIsVerified = false
	}
	// _, transactionBytes := SerializeATx(transaction)
	// hexEncodedTx := hex.EncodeToString(transactionBytes)
	// fmt.Println("Serialized tx: ", hexEncodedTx)
	// fileName := GetFileName(hexEncodedTx)
	// fmt.Println("Tx Name:", hex.EncodeToString(fileName[:]), "File name: ", transaction.TxFilename, "\nverified:", txIsVerified)
	return txIsVerified
}

func SerializeATx(transaction types.TransactionData) (*wire.MsgTx, *wire.MsgTx, []byte) {
	numberOfInputs := len(transaction.Vin)
	numberOfOutputs := len(transaction.Vout)
	tx := wire.NewMsgTx(int32(transaction.Version))
	wTx := wire.NewMsgTx(int32(transaction.Version))

	// Add the inputs
	for i := 0; i < numberOfInputs; i++ {
		var txIn *wire.TxIn
		var wTxIn *wire.TxIn
		input := transaction.Vin[i]
		prevOutHash, _ := chainhash.NewHashFromStr(input.TxID)
		prevOut := wire.NewOutPoint(prevOutHash, uint32(input.Vout))
		scriptSig, _ := hex.DecodeString(input.ScriptSig)
		var witness [][]byte
		// if transaction.Vin[i].Witness != nil && len(transaction.Vin[i].Witness) > 0 {
		if transaction.Vin[i].Prevout.ScriptPubKeyType == "v0_p2wpkh" || transaction.Vin[i].Prevout.ScriptPubKeyType == "v0_p2wsh" || transaction.Vin[i].Prevout.ScriptPubKeyType == "v1_p2tr" {

			witness = make([][]byte, len(input.Witness))
			for i, w := range input.Witness {
				witness[i], _ = hex.DecodeString(w)
			}
			txIn = wire.NewTxIn(prevOut, scriptSig, nil)
			wTxIn = wire.NewTxIn(prevOut, scriptSig, witness)
		} else {
			txIn = wire.NewTxIn(prevOut, scriptSig, nil)
			wTxIn = wire.NewTxIn(prevOut, scriptSig, nil)
		}

		txIn.Sequence = uint32(input.Sequence)
		wTxIn.Sequence = uint32(input.Sequence)
		tx.AddTxIn(txIn)
		wTx.AddTxIn(wTxIn)
	}

	// Add the outputs
	for i := 0; i < numberOfOutputs; i++ {
		output := transaction.Vout[i]
		scriptPubKey, _ := hex.DecodeString(output.ScriptPubKey)
		txOut := wire.NewTxOut(int64(output.Value), scriptPubKey)
		tx.AddTxOut(txOut)
		wTx.AddTxOut(txOut)
	}

	tx.LockTime = uint32(transaction.Locktime)
	wTx.LockTime = uint32(transaction.Locktime)

	// Serialize
	var txBuffer bytes.Buffer
	// tx.Serialize(&txBuffer)
	serializeErr := tx.Serialize(&txBuffer)
	if serializeErr != nil {
		fmt.Println("Error serializing transaction:", serializeErr)
		return nil, nil, nil
	}
	rawTxBytes := txBuffer.Bytes()
	return tx, wTx, rawTxBytes
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
			txIn = wire.NewTxIn(prevOut, nil, nil)
		} else if transaction.Vin[i].Prevout.ScriptPubKeyType == "p2pkh" {
			// fmt.Println("\n IS P2PKH from SerializeATxWOSigScript")
			txIn = wire.NewTxIn(prevOut, scripPubKey, nil)
		} else if transaction.Vin[i].Prevout.ScriptPubKeyType == "v0_p2wpkh" {
			// fmt.Println("\n IS P2PKH from SerializeATxWOSigScript")
			// witness0, _ := hex.DecodeString(input.Witness[0])
			// witness1, _ := hex.DecodeString(input.Witness[1])
			// witness := [][]byte{
			// 	witness0,
			// 	witness1,
			// 	// []byte(input.Witness[0]),
			// 	// []byte(input.Witness[1]),
			// }
			txIn = wire.NewTxIn(prevOut, nil, nil)
		} else if transaction.Vin[i].Prevout.ScriptPubKeyType == "v0_p2wsh" {
			txIn = wire.NewTxIn(prevOut, nil, nil)
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
		rawTxHex := hex.EncodeToString(rawTxBytes)
		rawTxHex = rawTxHex + "01000000"
		txWithSighashBytes, _ := hex.DecodeString(rawTxHex)
		hashedTx := chainhash.DoubleHashB(txWithSighashBytes)
		return hashedTx
	} else if transaction.Vin[0].Prevout.ScriptPubKeyType == "v0_p2wpkhh" {
		input := transaction.Vin[0]
		output := transaction.Vout
		version := transaction.Version
		versionFormatted := fmt.Sprintf("%08x", version)
		versionBytes, _ := hex.DecodeString(versionFormatted)
		versionBytes = ReverseSlice(versionBytes)
		hexVersion := hex.EncodeToString(versionBytes)
		// now to the inputs
		hashedTxId, _ := chainhash.NewHashFromStr(input.TxID)
		reversedTxIdBytes, _ := hex.DecodeString(hashedTxId.String())
		reversedTxId := hex.EncodeToString(ReverseSlice(reversedTxIdBytes))
		reversedVoutBytes, _ := hex.DecodeString(fmt.Sprintf("%08x", input.Vout))
		reversedVout := hex.EncodeToString(ReverseSlice(reversedVoutBytes))
		serializedInput := reversedTxId + reversedVout
		serializedInputBytes, _ := hex.DecodeString(serializedInput)
		hashInput := chainhash.DoubleHashH(serializedInputBytes)
		hashInputReversed := ReverseBytesFromHexStr(hashInput.String())
		// get all the sequences from inputs and hash each of them
		sequencesHex := fmt.Sprintf("%08x", input.Sequence)
		sequencesBytes, _ := hex.DecodeString(sequencesHex)
		reverseSequencesBytes := ReverseSlice(sequencesBytes)
		sequencesHash := chainhash.DoubleHashH(reverseSequencesBytes)
		sequencesHashReversed := ReverseBytesFromHexStr(sequencesHash.String())
		// since i have just one input and it's what i want to sign, i use the value as gotten above
		serializedInputToSign := serializedInput
		scriptPubKeyAsm := strings.Split(transaction.Vin[0].Prevout.ScriptPubKeyAsm, " ")
		pubkeyHashStr := scriptPubKeyAsm[2]
		scriptCode := "1976a914" + pubkeyHashStr + "88ac"
		amt := input.Prevout.Value
		amtP := fmt.Sprintf("%016x", amt)
		amtBytes, _ := hex.DecodeString(amtP)
		reversedAmt := ReverseSlice(amtBytes)
		hexEncodedAmt := hex.EncodeToString(reversedAmt)
		// get the sequence of the input we want to sign and serialize. this is same as above since we have just one input, so
		serializeSequenceToSign := hex.EncodeToString(reverseSequencesBytes)
		// now serialize outputs and hash em
		output1AmtBytes, _ := hex.DecodeString(fmt.Sprintf("%016x", output[0].Value))
		hexReverseOutput1Amt := hex.EncodeToString(ReverseSlice(output1AmtBytes))
		output1ScriptPubKeyLen := len(output[0].ScriptPubKey) / 2
		output1ScriptPubKeyLenHex := fmt.Sprintf("%02x", output1ScriptPubKeyLen)
		output1ScriptPubKey := output[0].ScriptPubKey
		output2AmtBytes, _ := hex.DecodeString(fmt.Sprintf("%016x", output[1].Value))
		hexReverseOutput2Amt := hex.EncodeToString(ReverseSlice(output2AmtBytes))
		output2ScriptPubKeyLen := len(output[1].ScriptPubKey) / 2
		output2ScriptPubKeyLenHex := fmt.Sprintf("%02x", output2ScriptPubKeyLen)
		output2ScriptPubKey := output[1].ScriptPubKey
		outputsSerialized := hexReverseOutput1Amt + output1ScriptPubKeyLenHex + output1ScriptPubKey + hexReverseOutput2Amt + output2ScriptPubKeyLenHex + output2ScriptPubKey
		// fmt.Println("Serialized outputs:", outputsSerialized)
		outputsSerializedBytes, _ := hex.DecodeString(outputsSerialized)
		outputsHash := chainhash.DoubleHashH(outputsSerializedBytes)
		outputsHashHex := outputsHash.String()
		outputsHashHex = ReverseBytesFromHexStr(outputsHashHex)
		// c1454cb6863eedd01c082cb202c7ab2cdc33476a24c80109f8cfe3d5333b0973
		/// THIS IS NOT RELEVANT. IT WAS JUST A MANUAL TEST
		// txId, _ := chainhash.NewHashFromStr("c6fa5cb4ac9f4f59b193a48bbb38b70b246bb109c91775160f35070f46838821")
		// serializedVoutBytes, _ := hex.DecodeString(txId.String() + "01000000")
		// voutHash := chainhash.DoubleHashH(serializedVoutBytes)
		// sequencesBytes2, _ := hex.DecodeString("ffffffff")
		// myPreImg := "01000000" + voutHash.String() + chainhash.DoubleHashH(sequencesBytes2).String()
		// myPreImg = myPreImg + txId.String() + "01000000" + "1976a9147ef8d1162a3f3691023a6fccb7723edd126ac80a88ac"
		// myPreImg = myPreImg + "325a8b0000000000" + "ffffffff"
		// concatOutputsBytes, _ := hex.DecodeString("5460000000000000" + "16" + "001437fff1c9ce1d770cf82b38a1cdeba3972cddbb08" + "a2ee8a0000000000" + "16" + "00147ef8d1162a3f3691023a6fccb7723edd126ac80a")
		// myPreImg = myPreImg + chainhash.DoubleHashH(concatOutputsBytes).String()
		// myPreImg = myPreImg + "00000000" + "01000000"
		// e71f93765b208862ef853200cd32f41c25b8986398d987f7999cf56a35355ca3
		// 52bc433bc0d1a9fc29e65195f7b632947b6e0f0741afcca3ef16de24525ef3ca sequences hash
		lockTime, _ := hex.DecodeString(fmt.Sprintf("%08x", transaction.Locktime))
		hexReverseLocktime := hex.EncodeToString(ReverseSlice(lockTime))
		preImg := hexVersion + hashInputReversed + sequencesHashReversed + serializedInputToSign + scriptCode + hexEncodedAmt + serializeSequenceToSign + outputsHashHex + hexReverseLocktime + "01000000"
		fmt.Println("Preimage 2: ", preImg)
		myPreImgBytes, _ := hex.DecodeString(preImg)
		hashedPreImg := chainhash.DoubleHashB(myPreImgBytes)
		hextx := hex.EncodeToString(hashedPreImg)
		fmt.Println("Hashed preimage:", hextx)
		return hashedPreImg
	} else {
		input := transaction.Vin[0]
		output := transaction.Vout
		version := transaction.Version
		versionFormatted := fmt.Sprintf("%08x", version)
		hexVersion := ReverseBytesFromHexStr(versionFormatted) // method basically reverses the hex string bytes
		// now to the inputs
		hashedTxId, _ := chainhash.NewHashFromStr(input.TxID)
		reversedTxId := ReverseBytesFromHexStr(hashedTxId.String())
		reversedVout := ReverseBytesFromHexStr(fmt.Sprintf("%08x", input.Vout))
		serializedInput := reversedTxId + reversedVout
		serializedInputBytes, _ := hex.DecodeString(serializedInput)
		hashInput := chainhash.DoubleHashH(serializedInputBytes)
		hashInputReversed := ReverseBytesFromHexStr(hashInput.String())
		// get all the sequences from inputs and hash each of them
		sequencesHex := fmt.Sprintf("%08x", input.Sequence)
		sequencesBytes, _ := hex.DecodeString(sequencesHex)
		reverseSequencesBytes := ReverseSlice(sequencesBytes)
		sequencesHash := chainhash.DoubleHashH(reverseSequencesBytes)
		sequencesHashReversed := ReverseBytesFromHexStr(sequencesHash.String())
		// since i have just one input and it's what i want to sign, i use the value as gotten above
		serializedInputToSign := serializedInput
		scriptPubKeyAsm := strings.Split(transaction.Vin[0].Prevout.ScriptPubKeyAsm, " ")
		pubkeyHashStr := scriptPubKeyAsm[2]
		var scriptCode string
		if input.Prevout.ScriptPubKeyType == "v0_p2wpkh" {
			scriptCode = "1976a914" + pubkeyHashStr + "88ac"
		} else if input.Prevout.ScriptPubKeyType == "v0_p2wsh" {
			witnessScript := input.Witness[len(input.Witness)-1]
			witnessScriptByteLength := len(witnessScript) / 2
			witnessScriptByteLengthHex := fmt.Sprintf("%02x", witnessScriptByteLength)
			scriptCode = witnessScriptByteLengthHex + witnessScript
		}

		amt := input.Prevout.Value
		amtP := fmt.Sprintf("%016x", amt)
		hexEncodedAmt := ReverseBytesFromHexStr(amtP)
		// get the sequence of the input we want to sign and serialize. this is same as above since we have just one input, so
		serializeSequenceToSign := hex.EncodeToString(reverseSequencesBytes)
		// now serialize outputs and hash em
		var outputsSerialized string
		for i := 0; i < len(output); i++ {
			hexReverseOutput1Amt := ReverseBytesFromHexStr(fmt.Sprintf("%016x", output[i].Value))
			output1ScriptPubKeyLen := len(output[i].ScriptPubKey) / 2
			output1ScriptPubKeyLenHex := fmt.Sprintf("%02x", output1ScriptPubKeyLen)
			output1ScriptPubKey := output[i].ScriptPubKey
			// hexReverseOutput2Amt := ReverseBytesFromHexStr(fmt.Sprintf("%016x", output[1].Value))
			// output2ScriptPubKeyLen := len(output[1].ScriptPubKey) / 2
			// output2ScriptPubKeyLenHex := fmt.Sprintf("%02x", output2ScriptPubKeyLen)
			// output2ScriptPubKey := output[1].ScriptPubKey
			currOutputSerialized := hexReverseOutput1Amt + output1ScriptPubKeyLenHex + output1ScriptPubKey
			outputsSerialized = outputsSerialized + currOutputSerialized
		}
		// hexReverseOutput1Amt := ReverseBytesFromHexStr(fmt.Sprintf("%016x", output[0].Value))
		// output1ScriptPubKeyLen := len(output[0].ScriptPubKey) / 2
		// output1ScriptPubKeyLenHex := fmt.Sprintf("%02x", output1ScriptPubKeyLen)
		// output1ScriptPubKey := output[0].ScriptPubKey
		// hexReverseOutput2Amt := ReverseBytesFromHexStr(fmt.Sprintf("%016x", output[1].Value))
		// output2ScriptPubKeyLen := len(output[1].ScriptPubKey) / 2
		// output2ScriptPubKeyLenHex := fmt.Sprintf("%02x", output2ScriptPubKeyLen)
		// output2ScriptPubKey := output[1].ScriptPubKey
		// outputsSerialized = hexReverseOutput1Amt + output1ScriptPubKeyLenHex + output1ScriptPubKey + hexReverseOutput2Amt + output2ScriptPubKeyLenHex + output2ScriptPubKey
		// fmt.Println("Serialized outputs:", outputsSerialized)
		outputsSerializedBytes, _ := hex.DecodeString(outputsSerialized)
		outputsHash := chainhash.DoubleHashH(outputsSerializedBytes)
		outputsHashHex := outputsHash.String()
		outputsHashHex = ReverseBytesFromHexStr(outputsHashHex)
		hexReverseLocktime := ReverseBytesFromHexStr(fmt.Sprintf("%08x", transaction.Locktime))
		preImg := hexVersion + hashInputReversed + sequencesHashReversed + serializedInputToSign + scriptCode + hexEncodedAmt + serializeSequenceToSign + outputsHashHex + hexReverseLocktime + "01000000"
		// fmt.Println("Preimage 2: ", preImg)
		myPreImgBytes, _ := hex.DecodeString(preImg)
		hashedPreImg := chainhash.DoubleHashB(myPreImgBytes)
		// hextx := hex.EncodeToString(hashedPreImg)
		// fmt.Println("Hashed preimage:", hextx)
		return hashedPreImg
	}
}

func VerifyTxSig(transaction types.TransactionData) bool {

	rawTxBytes := SerializeATxWOSigScript(transaction)
	// hextx := hex.EncodeToString(rawTxBytes)
	// fmt.Println("Raw tx bytes:", hextx)
	var sig []byte
	var pubKeyBytes []byte
	// pubKeysStack := new(types.Stack)
	multiSigRedeemStack := new(types.Stack)
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
		// TODO check if the witness first field is empty. if not. more complex script don't validate
		// fmt.Println("Currently verifying tx: ", transaction.TxFilename)
		witnesses := transaction.Vin[0].Witness
		if witnesses[0] != "" {
			return false
		}
		if witnesses[0] == "" {
			// fmt.Println("Empty witness")
			emptyStringByte, _ := hex.DecodeString("00")
			multiSigRedeemStack.Push(emptyStringByte)
		} else {
			// fmt.Println("Not empty witness")
			emptyStringByte, _ := hex.DecodeString(witnesses[0])
			multiSigRedeemStack.Push(emptyStringByte)
		}
		for i := 1; i < len(witnesses)-1; i++ { // len(witnesses)-1 be3cause we don't want to include last item (witness script)
			witnessBytes, _ := hex.DecodeString(witnesses[i])
			multiSigRedeemStack.Push(witnessBytes)
		}
		witnessScriptAsm := strings.Split(transaction.Vin[0].InnerWitnessScript, " ")
		for _, witness := range witnessScriptAsm {
			// var scriptOpCodeVal int
			if strings.Contains(witness, "PUSHBYTES") || strings.Contains(witness, "OP_CHECK") {
				continue
			} else if strings.Contains(witness, "PUSHNUM_") {
				opCodeSplit := strings.Split(witness, "_")
				scriptOpCodeVal := fmt.Sprintf("%02s", opCodeSplit[len(opCodeSplit)-1])
				opCodeVal, _ := hex.DecodeString(scriptOpCodeVal)
				// fmt.Println("pusshing opcode: ", hex.EncodeToString(opCodeVal))
				multiSigRedeemStack.Push(opCodeVal)
			} else {
				opCodeVal, _ := hex.DecodeString(witness)
				multiSigRedeemStack.Push(opCodeVal)
			}
			// witnessBytes, _ := hex.DecodeString(witness)
			// multiSigRedeemStack.Push(witnessBytes)
		}
		// NOW CHECK SIGNATURES
		var pubkeys []string
		var sigs []string
		numOfPupKeys, _ := multiSigRedeemStack.Pop()
		numOfPupKeysInt, _ := strconv.Atoi(hex.EncodeToString(numOfPupKeys))
		for i := 0; i < numOfPupKeysInt; i++ {
			pubKey, _ := multiSigRedeemStack.Pop()
			pubkeyStr := hex.EncodeToString(pubKey)
			pubkeys = append([]string{pubkeyStr}, pubkeys...)
		}
		numOfSigs, _ := multiSigRedeemStack.Pop()
		numOfSigsInt, _ := strconv.Atoi(hex.EncodeToString(numOfSigs))
		for i := 0; i < numOfSigsInt; i++ {
			sig, _ := multiSigRedeemStack.Pop()
			sigStr := hex.EncodeToString(sig)
			sigs = append([]string{sigStr}, sigs...)
		}
		// fmt.Println("Pubkeys: ", pubkeys, "Sigs: ", sigs)
		var checkMultiSigValid []bool
		for _, sig := range sigs {
			sigBytes, _ := hex.DecodeString(sig)
			signature, parseScriptErr := ecdsa.ParseDERSignature(sigBytes)
			if parseScriptErr != nil {
				fmt.Println("Error parsing signature:", parseScriptErr)
			}
			for _, pubkey := range pubkeys {
				pubKeyBytes, _ := hex.DecodeString(pubkey)
				pubKey, _ := btcec.ParsePubKey(pubKeyBytes)
				verified := signature.Verify(rawTxBytes, pubKey)
				if verified {
					// fmt.Println("Signature verified")
					checkMultiSigValid = append(checkMultiSigValid, true)
					break
				}
			}
		}
		if len(checkMultiSigValid) != numOfSigsInt {
			return false
		} else {
			return true
		}
		// return true

	}
	// Parse the DER encoded signature
	signature, _ := ecdsa.ParseDERSignature(sig)
	pubKey, _ := btcec.ParsePubKey(pubKeyBytes)

	// privKey, _ := hex.DecodeString(PrivKey)
	// privateKey, publicKey := btcec.PrivKeyFromBytes(privKey)
	// signRawTx := ecdsa.Sign(privateKey, rawTxBytes)
	// fmt.Println("Signature:", hex.EncodeToString(signRawTx.Serialize()), "\nPublic key:", hex.EncodeToString(publicKey.SerializeCompressed()), "private key", hex.EncodeToString(privateKey.Serialize()), "other pub", pubKey.SerializeCompressed()[0], signature.Serialize()[0])

	verified := signature.Verify(rawTxBytes, pubKey)
	// fmt.Println("verified:", verified)
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

func ReverseBytesFromHexStr(str string) string {
	bytes, _ := hex.DecodeString(str)
	reversed := ReverseSlice(bytes)
	return hex.EncodeToString(reversed)
}

func StringToBytes(str string) []byte {
	bytes, err := hex.DecodeString(str)
	if err != nil {
		fmt.Println("Error decoding string to bytes:", err)
		return nil
	}
	return bytes
}

func ReverseBytesFromBytes(bytes []byte) []byte {
	reversed := ReverseSlice(bytes)
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
