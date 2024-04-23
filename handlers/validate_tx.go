package handlers

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/SummerOfBitcoin/code-challenge-2024-alainjr10/types"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/ecdsa"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"
)

func FullTxValidation(transaction types.TransactionData) bool {
	timeLockValid := ValidateTxTimeLock(transaction)
	var validateHashes bool
	var verifyTxSig bool
	if timeLockValid {
		validateHashes = ValidateTxHashes(transaction)
		verifyTxSig = VerifyFullTxSig(transaction)
	}

	return validateHashes && verifyTxSig && timeLockValid
}

func SortTxs(transactions []types.TransactionData) {
	sort.Slice(transactions, func(i, j int) bool {
		inputAmountI := 0
		outputAmountI := 0
		for _, vin := range transactions[i].Vin {
			inputAmountI += vin.Prevout.Value
		}
		for _, vout := range transactions[i].Vout {
			outputAmountI += vout.Value
		}
		inputAmountJ := 0
		outputAmountJ := 0
		for _, vin := range transactions[j].Vin {
			inputAmountJ += vin.Prevout.Value
		}
		for _, vout := range transactions[j].Vout {
			outputAmountJ += vout.Value
		}
		_, _, txIWOWit, txIWithWith := SerializeATx(transactions[i])
		_, _, txJWOWit, txJWithWith := SerializeATx(transactions[j])
		txIBaseSize, txITotSize := len(txIWOWit), len(txIWithWith)
		txJBaseSize, txJTotSize := len(txJWOWit), len(txJWithWith)
		txIWeight := txIBaseSize*3 + txITotSize
		txJWeight := txJBaseSize*3 + txJTotSize
		feeI := inputAmountI - outputAmountI
		feeJ := inputAmountJ - outputAmountJ
		ratioI := float64(feeI) / float64(txIWeight)
		ratioJ := float64(feeJ) / float64(txJWeight)
		return ratioI > ratioJ
	})
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
			splitScriptSigAsm := strings.Split(input.ScriptSigAsm, " ")
			pubKeyBytes, _ := hex.DecodeString(splitScriptSigAsm[len(splitScriptSigAsm)-1]) // in this case, we are extracting the redeemscript
			stack.Push([]byte{0x00})
			// stack.Push(sigBytes)
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
			if bytes.Equal(providedPubKeyHash, hashedPubKey) {
				stack.Push([]byte{0x01})
				overallStack.Push([]byte{0x01})
			} else {
				stack.Push([]byte{0x00})
				overallStack.Push([]byte{0x00})
				break
			}
		} else if transaction.Vin[i].Prevout.ScriptPubKeyType == "v1_p2tr" {
			stack.Push([]byte{0x01})
			overallStack.Push([]byte{0x01})
			// return true
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
	return txIsVerified
}

func SerializeATx(transaction types.TransactionData) (*wire.MsgTx, *wire.MsgTx, []byte, []byte) {
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
		if transaction.Vin[i].Witness == nil {
			wTxIn = wire.NewTxIn(prevOut, scriptSig, nil)
		} else {
			witness = make([][]byte, len(input.Witness))
			for i, w := range input.Witness {
				witness[i], _ = hex.DecodeString(w)
			}
			wTxIn = wire.NewTxIn(prevOut, scriptSig, witness)
		}
		txIn = wire.NewTxIn(prevOut, scriptSig, nil)

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
	serializeErr := tx.Serialize(&txBuffer)
	if serializeErr != nil {
		fmt.Println("Error serializing transaction:", serializeErr)
		return nil, nil, nil, nil
	}
	var txBuf1 bytes.Buffer
	wTx.Serialize(&txBuf1)
	rawTxBytes := txBuffer.Bytes()
	return tx, wTx, rawTxBytes, txBuf1.Bytes()
}

// TODO: Rename this function as it effectively calculates th signature hash message, so an appropriate name should be given
func SerializeATxWOSigScript(transaction types.TransactionData, inputIndex int) []byte {
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
			txIn = wire.NewTxIn(prevOut, nil, nil)
		} else if transaction.Vin[i].Prevout.ScriptPubKeyType == "p2pkh" {
			txIn = wire.NewTxIn(prevOut, scripPubKey, nil)
		} else if transaction.Vin[i].Prevout.ScriptPubKeyType == "v0_p2wpkh" {
			txIn = wire.NewTxIn(prevOut, nil, nil)
		} else if transaction.Vin[i].Prevout.ScriptPubKeyType == "v0_p2wsh" {
			txIn = wire.NewTxIn(prevOut, nil, nil)
		} else if transaction.Vin[i].Prevout.ScriptPubKeyType == "v1_p2tr" {
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

	var rawTxBytes []byte
	if transaction.Vin[0].Prevout.ScriptPubKeyType == "p2pkh" { // this is just temporary and a more robust way of handling this should be implemented
		input := transaction.Vin[0]
		scripPubKey, _ := hex.DecodeString(input.Prevout.ScriptPubKey)
		tx.TxIn[0].SignatureScript = scripPubKey
		// Serialize
		var txBuffer bytes.Buffer
		serializeErr := tx.Serialize(&txBuffer)
		if serializeErr != nil {
			fmt.Println("Error serializing transaction:", serializeErr)
			return nil
		}
		rawTxBytes = txBuffer.Bytes()
		rawTxHex := hex.EncodeToString(rawTxBytes)
		rawTxHex = rawTxHex + "01000000"
		txWithSighashBytes, _ := hex.DecodeString(rawTxHex)
		hashedTx := chainhash.DoubleHashB(txWithSighashBytes)
		return hashedTx
	} else if transaction.Vin[0].Prevout.ScriptPubKeyType == "p2sh" && transaction.Vin[0].Witness == nil {
		scriptSigAsmSplitted := strings.Split(transaction.Vin[0].ScriptSigAsm, " ")
		redeemScriptBytes, _ := hex.DecodeString(scriptSigAsmSplitted[len(scriptSigAsmSplitted)-1])
		tx.TxIn[0].SignatureScript = redeemScriptBytes
		var txBuf bytes.Buffer
		tx.Serialize(&txBuf)
		rawTxBytes = txBuf.Bytes()
		rawTxHex := hex.EncodeToString(rawTxBytes)
		rawTxHex = rawTxHex + "01000000"
		txWithSighashBytes, _ := hex.DecodeString(rawTxHex)
		hashedTx := chainhash.DoubleHashB(txWithSighashBytes)
		// fmt.Println("\nserialized: ", rawTxHex, "tx id: ", transaction.TxFilename)
		return hashedTx
		// }
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
		} else if input.Prevout.ScriptPubKeyType == "p2sh" && len(input.Witness) == 2 {
			scriptSigAsmSplitted := strings.Split(transaction.Vin[0].InnerRedeemScript, " ")
			redeemScriptStr := scriptSigAsmSplitted[len(scriptSigAsmSplitted)-1]
			scriptCode = "1976a914" + redeemScriptStr + "88ac"
		} else if input.Prevout.ScriptPubKeyType == "v0_p2wsh" || (input.Prevout.ScriptPubKeyType == "p2sh" && len(input.Witness) > 2) {
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
			currOutputSerialized := hexReverseOutput1Amt + output1ScriptPubKeyLenHex + output1ScriptPubKey
			outputsSerialized = outputsSerialized + currOutputSerialized
		}
		outputsSerializedBytes, _ := hex.DecodeString(outputsSerialized)
		outputsHash := chainhash.DoubleHashH(outputsSerializedBytes)
		outputsHashHex := outputsHash.String()
		outputsHashHex = ReverseBytesFromHexStr(outputsHashHex)
		hexReverseLocktime := ReverseBytesFromHexStr(fmt.Sprintf("%08x", transaction.Locktime))
		preImg := hexVersion + hashInputReversed + sequencesHashReversed + serializedInputToSign + scriptCode + hexEncodedAmt + serializeSequenceToSign + outputsHashHex + hexReverseLocktime + "01000000"
		// fmt.Println("Preimage 2: ", preImg)
		myPreImgBytes, _ := hex.DecodeString(preImg)
		hashedPreImg := chainhash.DoubleHashB(myPreImgBytes)
		return hashedPreImg
	}
}

func VerifyTxSig(transaction types.TransactionData, inputIndex int) bool {

	rawTxBytes := SerializeATxWOSigScript(transaction, inputIndex)
	var sig []byte
	var pubKeyBytes []byte
	multiSigRedeemStack := new(types.Stack)
	if transaction.Vin[0].Prevout.ScriptPubKeyType == "p2pkh" {
		scriptSigAsm := strings.Split(transaction.Vin[0].ScriptSigAsm, " ")
		sig, _ = hex.DecodeString(scriptSigAsm[1])
		pubKeyBytes, _ = hex.DecodeString(scriptSigAsm[3])
	} else if transaction.Vin[0].Prevout.ScriptPubKeyType == "v1_p2tr" {
		return true
	} else if transaction.Vin[0].Prevout.ScriptPubKeyType == "v0_p2wpkh" {
		sig, _ = hex.DecodeString(transaction.Vin[0].Witness[0])
		pubKeyBytes, _ = hex.DecodeString(transaction.Vin[0].Witness[1])
	} else if transaction.Vin[0].Prevout.ScriptPubKeyType == "p2sh" && len(transaction.Vin[0].Witness) == 2 {
		sig, _ = hex.DecodeString(transaction.Vin[0].Witness[0])
		pubKeyBytes, _ = hex.DecodeString(transaction.Vin[0].Witness[1])
	} else if transaction.Vin[0].Prevout.ScriptPubKeyType == "v0_p2wsh" || (transaction.Vin[0].Prevout.ScriptPubKeyType == "p2sh" && (transaction.Vin[0].Witness == nil || len(transaction.Vin[0].Witness) > 2)) {
		// TODO check if the witness first field is empty. if not. more complex script don't validate
		// fmt.Println("Currently verifying tx: ", transaction.TxFilename)
		if transaction.Vin[0].Prevout.ScriptPubKeyType == "p2sh" && transaction.Vin[0].Witness == nil {
			scriptSigSplitted := strings.Split(transaction.Vin[0].ScriptSigAsm, " ")
			emptyStringByte, _ := hex.DecodeString("00")
			multiSigRedeemStack.Push(emptyStringByte)
			for _, op := range scriptSigSplitted {
				if strings.Contains(op, "_PUSHDATA") {
					break
				} else {
					if strings.HasPrefix(op, "OP") {
						continue
					} else {
						opBytes, _ := hex.DecodeString(op)
						multiSigRedeemStack.Push(opBytes)
					}
				}
			}

		} else {
			witnesses := transaction.Vin[0].Witness
			if witnesses[0] != "" {
				return false
			}
			if witnesses[0] == "" {
				emptyStringByte, _ := hex.DecodeString("00")
				multiSigRedeemStack.Push(emptyStringByte)
			} else {
				emptyStringByte, _ := hex.DecodeString(witnesses[0])
				multiSigRedeemStack.Push(emptyStringByte)
			}
			for i := 1; i < len(witnesses)-1; i++ { // len(witnesses)-1 be3cause we don't want to include last item (witness script)
				witnessBytes, _ := hex.DecodeString(witnesses[i])
				multiSigRedeemStack.Push(witnessBytes)
			}
		}
		var witnessScriptAsm []string
		if transaction.Vin[0].Prevout.ScriptPubKeyType == "p2sh" && transaction.Vin[0].Witness == nil {
			witnessScriptAsm = strings.Split(transaction.Vin[0].InnerRedeemScript, " ")
		} else {
			witnessScriptAsm = strings.Split(transaction.Vin[0].InnerWitnessScript, " ")
		}
		for _, witness := range witnessScriptAsm {
			if strings.Contains(witness, "PUSHBYTES") || strings.Contains(witness, "OP_CHECK") {
				continue
			} else if strings.Contains(witness, "PUSHNUM_") {
				opCodeSplit := strings.Split(witness, "_")
				scriptOpCodeVal := fmt.Sprintf("%02s", opCodeSplit[len(opCodeSplit)-1])
				opCodeVal, _ := hex.DecodeString(scriptOpCodeVal)
				multiSigRedeemStack.Push(opCodeVal)
			} else {
				opCodeVal, _ := hex.DecodeString(witness)
				multiSigRedeemStack.Push(opCodeVal)
			}
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
					// fmt.Println("Signature verified!!! Tx: ", transaction.TxFilename)
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
	}
	// Parse the DER encoded signature
	signature, _ := ecdsa.ParseDERSignature(sig)
	pubKey, _ := btcec.ParsePubKey(pubKeyBytes)
	verified := signature.Verify(rawTxBytes, pubKey)
	// fmt.Println("verified:", verified)
	return verified
}

func VerifyFullTxSig(transaction types.TransactionData) bool {
	var verified bool
	for i := 0; i < len(transaction.Vin); i++ {
		verifyTxInputSig := VerifyTxSig(transaction, i)
		if !verifyTxInputSig {
			verified = false
			break
		} else {
			verified = true
		}
	}

	return verified
}

func ReverseSlice(s []byte) []byte {
	reversed := make([]byte, len(s))
	copy(reversed, s)
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
