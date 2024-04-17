package handlers

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"log"
	"math/big"
	"os"
	"strings"
	"time"

	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"github.com/btcsuite/btcd/wire"
)

func CreateBlockHeader(merkleRootHash *chainhash.Hash) *wire.BlockHeader {
	// blockHeader := types.BlockHeader{
	// 	Version: btcutil.ve,
	// }
	// for this example, i'm using block 828015 id as prev block id
	// prevBlockHash := GetHashFromStr("00000000000000000000a9c619c4af8c09f10c11a8262bcde576450e45a126ca")
	prevBlockHash := GetHashFromStr("00000000000000000000a9c619c4af8c09f10c11a8262bcde576450e45a126ca")
	merkleRoot := merkleRootHash
	target := "0000ffff00000000000000000000000000000000000000000000000000000000"
	targetBytes, _ := hex.DecodeString(target)
	targetInt := new(big.Int).SetBytes(targetBytes)
	bits := HexToCompactHex(targetInt)
	wireBh := wire.NewBlockHeader(
		4,             /* version */
		prevBlockHash, /* previous block hash */
		merkleRoot,    /* merkle root */
		bits,          /* bits */
		0,
	)
	// GetNonce(4294967295)
	return wireBh
}

func ModBlockHeaderForMining(blockHeader *wire.BlockHeader, nonce uint32, modTime bool) *wire.BlockHeader {
	blockHeader.Nonce = GetNonce(nonce)
	if modTime {
		blockHeader.Timestamp = time.Unix(time.Now().Unix(), 0)
	}
	return blockHeader
}

func CreateAndModCoinbaseTxWithSecondOutput(commitmentScript []byte) *wire.MsgTx {
	coinbaseTx, _ := CreateCoinbaseTx()
	// commitmentScript := CreateCoinbaseCommittmentScript(txs)
	commitmentOutput := wire.NewTxOut(0, commitmentScript)
	coinbaseTx.AddTxOut(commitmentOutput)
	witnessItem := fmt.Sprintf("%064x", 0)
	witnessItemBytes, _ := hex.DecodeString(witnessItem)
	coinbaseTx.TxIn[0].Witness = append(coinbaseTx.TxIn[0].Witness, witnessItemBytes)
	return coinbaseTx
}

func ParseBlock(txs []*wire.MsgTx, coinbaseTx *wire.MsgTx) *wire.MsgBlock {
	// Create the block header
	// Create the coinbase transaction and update it with second output
	// coinbaseTx := CreateAndModCoinbaseTxWithSecondOutput(txs)
	// commitmentScript := CreateCoinbaseCommittmentScript(txs)
	// commitmentOutput := wire.NewTxOut(0, commitmentScript)
	// coinbaseTx.AddTxOut(commitmentOutput)

	merkleRoot, err := CreateMerkleTree(txs, false, coinbaseTx)
	if err != nil {
		fmt.Println("Error creating Merkle tree: ", err)
		return nil
	}
	revMerkleRootStr := hex.EncodeToString(merkleRoot.CloneBytes())
	revMerkleRootHash := GetHashFromStr(revMerkleRootStr)
	fmt.Println("new merkle root: ", revMerkleRootHash.String())
	blockHeader := CreateBlockHeader(revMerkleRootHash)

	// Add the coinbase transaction to the block
	block := wire.NewMsgBlock(blockHeader)
	block.AddTransaction(coinbaseTx)

	// Add the remaining transactions to the block
	for _, tx := range txs {
		// tx := GetTxFromID(txid)
		block.AddTransaction(tx)
	}

	// Serialize the block
	var blockBuffer bytes.Buffer
	blockSerializeErr := block.Serialize(&blockBuffer)
	if blockSerializeErr != nil {
		fmt.Println("Error serializing block: ", blockSerializeErr)
		return nil
	}
	// fmt.Println("Block: ", hex.EncodeToString(blockBuffer.Bytes()))
	return block

}

func CreateMerkleTree(txs []*wire.MsgTx, isWTxId bool, coinbaseTx *wire.MsgTx) (*chainhash.Hash, error) {
	var coinbaseBy bytes.Buffer
	coinbaseTx.Serialize(&coinbaseBy)
	coinbaseTxHash := coinbaseTx.TxHash()
	// coinbaseTx2 := hex.EncodeToString(coinbaseTxHash.CloneBytes())
	// newCoinbaseTxHash, _ := chainhash.NewHashFromStr(coinbaseTx2)
	coinbaseWTxId := fmt.Sprintf("%016x", 0)
	coinbaseWTxIdHash, _ := chainhash.NewHashFromStr(coinbaseWTxId)
	// Calculate the merkle root of the block
	var hashes []*chainhash.Hash
	if isWTxId {
		hashes = append(hashes, coinbaseWTxIdHash)
	} else {
		hashes = append(hashes, &coinbaseTxHash)
	}

	// Convert txids to chainhash.Hash
	for _, tx := range txs {
		hash := tx.TxHash()
		// let's reverse the order of the hash, so as to get the txid in natural byte order
		// val2 := hex.EncodeToString(hash.CloneBytes())
		// newHash, _ := chainhash.NewHashFromStr(val2)
		hashes = append(hashes, &hash)
	}

	// Construct the Merkle tree
	for len(hashes) > 1 {
		if len(hashes)%2 != 0 {
			hashes = append(hashes, hashes[len(hashes)-1])
		}

		var newHashes []*chainhash.Hash
		for i := 0; i < len(hashes); i += 2 {
			// for some reason, when i change this to chainhash.DoubleHashH , it gives a different/wrong hash
			merkleRootTxHash := chainhash.DoubleHashH(append(hashes[i][:], hashes[i+1][:]...))
			newHashes = append(newHashes, &merkleRootTxHash)
		}

		hashes = newHashes
	}
	fmt.Println("Merkle Root: ", hashes[0].String())
	return hashes[0], nil
}

func CreateWitnessMerkleTree(txs []*wire.MsgTx) (*chainhash.Hash, error) {
	// commitmentScript := CreateCoinbaseCommittmentScript(txs)
	// commitmentOutput := wire.NewTxOut(0, commitmentScript)
	// coinbaseTx.AddTxOut(commitmentOutput)
	coinbaseWTxId := "0000000000000000000000000000000000000000000000000000000000000000"
	coinbaseWTxIdHash, _ := chainhash.NewHashFromStr(coinbaseWTxId)
	// validTxs := make([]string, 0)
	// validTxs = append(validTxs, coinbaseTx.TxHash().String())
	// Calculate the merkle root of the block
	var hashes []*chainhash.Hash
	hashes = append(hashes, coinbaseWTxIdHash)

	// Convert txids to chainhash.Hash
	for _, tx := range txs {
		var txBytes bytes.Buffer
		tx.Serialize(&txBytes)
		// fmt.Println("Tx: ", hex.EncodeToString(txBytes.Bytes()))
		// hash2 := tx.TxHash() // this actuall gives the txid, excluding witness data and flags
		hash := chainhash.DoubleHashB(txBytes.Bytes())
		// fmt.Println("Tx Hash: ", hex.EncodeToString(hash))
		// revWTxId := ReverseBytesFromBytes(hash)
		hashRev, revHashErr := chainhash.NewHashFromStr(hex.EncodeToString(hash))
		if revHashErr != nil {
			fmt.Println("Error reversing hash: ", revHashErr)
		}
		hashes = append(hashes, hashRev)
	}

	// Construct the Merkle tree
	for len(hashes) > 1 {
		if len(hashes)%2 != 0 {
			hashes = append(hashes, hashes[len(hashes)-1])
		}

		var newHashes []*chainhash.Hash
		for i := 0; i < len(hashes); i += 2 {
			hash := chainhash.DoubleHashB(append(hashes[i][:], hashes[i+1][:]...))
			hashHash, _ := chainhash.NewHashFromStr(hex.EncodeToString(hash))
			newHashes = append(newHashes, hashHash)
		}

		hashes = newHashes
	}
	fmt.Println("Witness Merkle Root: ", hashes[0].String())
	return hashes[0], nil
}

func SerializedBlockTxs(validTxs []string) string {
	serializedTxs := strings.Join(validTxs, "")
	return serializedTxs
}

func GetHashFromStr(s string) *chainhash.Hash {
	hash, err := chainhash.NewHashFromStr(s)
	if err != nil {
		panic(err)
	}
	return hash
}

func VerifyBlock(txs []*wire.MsgTx, updatedCoinbaseTx *wire.MsgTx) {
	block := ParseBlock(txs, updatedCoinbaseTx)
	blockMined := false
	nonceElapsed := false
	var currNonce uint32
	if currNonce < wire.MaxTxInSequenceNum {
		currNonce++
	} else {
		nonceElapsed = true
		currNonce = 0
	}
	coinbaseTx := block.Transactions[0]
	// Following section isn't needed because the coinbase transaction is already modified in the [[ParseBlock]] function
	// commitmentScript := CreateCoinbaseCommittmentScript(txs)
	// commitmentOutput := wire.NewTxOut(0, commitmentScript)
	// coinbaseTx.AddTxOut(commitmentOutput)
	for !blockMined {
		var blockHeader *wire.BlockHeader
		if nonceElapsed {
			blockHeader = ModBlockHeaderForMining(&block.Header, currNonce, true)
		} else {
			blockHeader = ModBlockHeaderForMining(&block.Header, currNonce, false)
		}

		headerHash := block.BlockHash()
		headerHashBytes, _ := hex.DecodeString(headerHash.String())
		// for numerical calculations, we gotta convert our little endian hash to big endian, before conerting to big int
		// headerHashReversed := ReverseBytesFromHexStr(headerHash.String())
		// headerHashRevBytes, _ := hex.DecodeString(headerHashReversed)

		// blockHeaderSerialized := SerializeWireBlockHeader(blockHeader)
		// fmt.Println("Block Header: ", hex.EncodeToString(blockHeaderSerialized), "\nBlock Hash: ", headerHash.String())
		// break

		hashInt := new(big.Int).SetBytes(headerHashBytes)

		// Convert the target to its compact representation
		compactTarget := blockHeader.Bits
		serializedBlockHeader := SerializeWireBlockHeader(blockHeader)
		txIdsInBlock := make([]string, 0)
		for _, tx := range block.Transactions {
			txIdHash := tx.TxHash()
			// newTxIdStr := hex.EncodeToString(txIdHash.CloneBytes())
			// newTxId,_ := chainhash.NewHashFromStr(newTxIdStr)
			txIdsInBlock = append(txIdsInBlock, txIdHash.String())
		}

		compactHash := HexToCompactHex(hashInt)
		var coinbaseBytesBuf bytes.Buffer
		coinbaseTxSerializeErr := coinbaseTx.Serialize(&coinbaseBytesBuf)
		if coinbaseTxSerializeErr != nil {
			fmt.Println("Error serializing coinbase tx: ", coinbaseTxSerializeErr)
			return
		}
		coinbaseTxSerialized := hex.EncodeToString(coinbaseBytesBuf.Bytes())
		if compactHash <= compactTarget {
			fmt.Println("Block found with hash: ", headerHash.String())
			fmt.Println("Block successfully mined! with hash:", compactHash, "nonce used: ", currNonce)
			WriteOutputToFile(hex.EncodeToString(serializedBlockHeader), coinbaseTxSerialized, txIdsInBlock)
			break
		} else {
			currNonce++
			// fmt.Println("\\/\\/\\/Not mined. Cur Nonce: .", currNonce, "Target: ", blockHeader.Bits, "Hash: ", compactHash, "/\\/\\/\\")
		}
	}

}

func Uint32ToBigInt(value uint32) *big.Int {
	bigInt := big.NewInt(int64(value))
	return bigInt
}

func GetNonce(value uint32) uint32 {
	// nonceHex := fmt.Sprintf("%08x", value)
	// nonceHex = ReverseBytesFromHexStr(nonceHex)
	nonceBytes := make([]byte, 4)
	binary.LittleEndian.PutUint32(nonceBytes, value)
	// returnValue := binary.LittleEndian.Uint32(nonceBytes)
	// fmt.Printf("Input: %d Nonce: %x, nonce hex: %s\n", value, returnValue, nonceHex)
	return binary.LittleEndian.Uint32(nonceBytes)
}

func HexToCompactHex(target *big.Int) uint32 {
	// Calculate the size of the target in bytes
	size := (target.BitLen() + 7) / 8

	// Create a big integer to hold the compact representation
	compact := new(big.Int)

	if size <= 3 {
		// If the target size is 3 bytes or less, shift it to the right by 8*(3-size) bits
		compact.SetBytes(target.Bytes())
		compact.Rsh(compact, uint(8*(3-size)))
	} else {
		// If the target size is more than 3 bytes, shift it to the right by 8*(size-3) bits
		compact.SetBytes(target.Bytes())
		compact.Rsh(compact, uint(8*(size-3)))
	}

	// If the bit at position 0x00800000 is set, shift the compact target to the right by 8 bits
	if compact.Bit(23) == 1 {
		compact.Rsh(compact, 8)
		size++
	}

	// Set the size as the exponent in the compact target
	compact.Or(compact, big.NewInt(int64(size<<24)))

	// Return the compact target as a uint32
	return uint32(compact.Uint64())
}

func WriteOutputToFile(blockHeader string, serializedCoinbaseTx string, txIds []string) {
	val := blockHeader + "\n"
	val += serializedCoinbaseTx + "\n"
	for _, txId := range txIds {
		val += txId + "\n"
	}
	data := []byte(val)

	err := os.WriteFile("output.txt", data, 0644)

	if err != nil {
		log.Fatal(err)
	}
}
