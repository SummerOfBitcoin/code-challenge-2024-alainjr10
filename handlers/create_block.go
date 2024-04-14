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

func ParseBlock(txs []*wire.MsgTx) *wire.MsgBlock {
	// Create the block header
	merkleRoot, err := CreateMerkleTree(txs)
	if err != nil {
		fmt.Println("Error creating Merkle tree: ", err)
		return nil
	}
	blockHeader := CreateBlockHeader(merkleRoot)

	// Create the coinbase transaction
	coinbaseTx, _ := CreateCoinbaseTx()

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

func CreateMerkleTree(txs []*wire.MsgTx) (*chainhash.Hash, error) {
	coinbaseTx, _ := CreateCoinbaseTx()
	coinbaseTxHash := coinbaseTx.TxHash()
	// validTxs := make([]string, 0)
	// validTxs = append(validTxs, coinbaseTx.TxHash().String())
	// Calculate the merkle root of the block
	var hashes []*chainhash.Hash
	hashes = append(hashes, &coinbaseTxHash)

	// Convert txids to chainhash.Hash
	for _, tx := range txs {
		hash := tx.TxHash()
		hashes = append(hashes, &hash)
	}

	// Construct the Merkle tree
	for len(hashes) > 1 {
		if len(hashes)%2 != 0 {
			hashes = append(hashes, hashes[len(hashes)-1])
		}

		var newHashes []*chainhash.Hash
		for i := 0; i < len(hashes); i += 2 {
			hash := chainhash.DoubleHashH(append(hashes[i][:], hashes[i+1][:]...))
			newHashes = append(newHashes, &hash)
		}

		hashes = newHashes
	}
	fmt.Println("Merkle Root: ", hashes[0].String())
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

func VerifyBlock(txs []*wire.MsgTx) {
	block := ParseBlock(txs)
	blockMined := false
	nonceElapsed := false
	var currNonce uint32
	if currNonce < wire.MaxTxInSequenceNum {
		currNonce++
	} else {
		nonceElapsed = true
		currNonce = 0
	}
	for !blockMined {
		var blockHeader *wire.BlockHeader
		if nonceElapsed {
			blockHeader = ModBlockHeaderForMining(&block.Header, currNonce, true)
		} else {
			blockHeader = ModBlockHeaderForMining(&block.Header, currNonce, false)
		}

		headerHash := block.BlockHash()
		// for numerical calculations, we gotta convert our little endian hash to big endian, before conerting to big int
		headerHashReversed := ReverseBytesFromHexStr(headerHash.String())
		headerHashRevBytes, _ := hex.DecodeString(headerHashReversed)

		// blockHeaderSerialized := SerializeWireBlockHeader(blockHeader)
		// fmt.Println("Block Header: ", hex.EncodeToString(blockHeaderSerialized), "\nBlock Hash: ", headerHash.String())
		// break

		hashInt := new(big.Int).SetBytes(headerHashRevBytes)

		// Convert the target to its compact representation
		compactTarget := blockHeader.Bits
		serializedBlockHeader := SerializeWireBlockHeader(blockHeader)
		txIdsInBlock := make([]string, 0)
		for _, tx := range block.Transactions {
			txIdsInBlock = append(txIdsInBlock, tx.TxHash().String())
		}

		compactHash := HexToCompactHex(hashInt)
		var coinbaseBytesBuf bytes.Buffer
		coinbaseTxSerializeErr := block.Transactions[0].Serialize(&coinbaseBytesBuf)
		if coinbaseTxSerializeErr != nil {
			fmt.Println("Error serializing coinbase tx: ", coinbaseTxSerializeErr)
			return
		}
		coinbaseTxSerialized := hex.EncodeToString(coinbaseBytesBuf.Bytes())
		if compactHash <= compactTarget {
			fmt.Println("Block successfully mined! with hash:", compactHash)
			WriteOutputToFile(hex.EncodeToString(serializedBlockHeader), coinbaseTxSerialized, txIdsInBlock)
			break
		} else {
			currNonce++
			fmt.Println("\\/\\/\\/Not mined. Cur Nonce: .", currNonce, "Target: ", blockHeader.Bits, "Hash: ", compactHash, "/\\/\\/\\")
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