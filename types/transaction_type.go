package types

type TransactionVin struct {
	TxID               string          `json:"txid"`
	Vout               int             `json:"vout"`
	Prevout            TransactionVout `json:"prevout"`
	ScriptSig          string          `json:"scriptsig"`
	ScriptSigAsm       string          `json:"scriptsig_asm"`
	Witness            []string        `json:"witness"`
	IsCoinbase         bool            `json:"is_coinbase"`
	Sequence           int             `json:"sequence"`
	InnerRedeemScript  string          `json:"inner_redeemscript_asm"`
	InnerWitnessScript string          `json:"inner_witnessscript_asm"`
}

type TransactionVout struct {
	ScriptPubKey        string `json:"scriptpubkey"`
	ScriptPubKeyAsm     string `json:"scriptpubkey_asm"`
	ScriptPubKeyType    string `json:"scriptpubkey_type"`
	ScriptPubKeyAddress string `json:"scriptpubkey_address"`
	Value               int    `json:"value"`
}

type TransactionData struct {
	TxFilename string            `json:"tx_filename"`
	Version    int               `json:"version"`
	Locktime   int               `json:"locktime"`
	Vin        []TransactionVin  `json:"vin"`
	Vout       []TransactionVout `json:"vout"`
}

type UTXOSetEntry struct {
	TxID         string `json:"txid"`         // Transaction ID where the output originated
	Index        uint32 `json:"index"`        // Index of the output within the transaction
	Value        int64  `json:"value"`        // Amount of Bitcoin in the output
	ScriptPubKey string `json:"scriptPubKey"` // Locking script defining how to spend the output
}

type BlockHeader struct {
	Version          int    `json:"version"`
	PreviousHash     string `json:"previous_hash"`
	MerkleRoot       string `json:"merkle_root"`
	Timestamp        uint32 `json:"timestamp"`
	Nonce            uint32 `json:"nonce"`
	DifficultyTarget string `json:"difficulty_target"`
}

type Block struct {
	Header           BlockHeader       `json:"header"`
	TransactionCount int               `json:"transaction_count"`
	Transactions     []TransactionData `json:"transactions"`
}
