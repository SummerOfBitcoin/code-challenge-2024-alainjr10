package main

import (
	"encoding/hex"
	"fmt"
	"strconv"

	"github.com/btcsuite/btcd/txscript"
)

func main() {
	num := txscript.OP_DATA_7
	fmt.Println("num iss: ", num)
	script := "0x00"
	decodedscript, _ := hex.DecodeString(script)
	opCodeVal, _ := strconv.Atoi("22")
	fmt.Println("decode string: ", decodedscript, "alt is: ", []byte(script))
	fmt.Println("Encode string: ", hex.EncodeToString(decodedscript), "alt is: ", hex.EncodeToString([]byte(script)))
	fmt.Println("op code val: ", opCodeVal)

}
