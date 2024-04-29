# Summer of Bitcoin 2024: Mine your first block - Assignment Solution Documentation

## Design approach
**the main.go file**
So I started this project by going through a lot of document, including the Grokking Bitcoin document, and the Bitcoin improvement proposals, after which, i started the pseudocode and coding phase thereafter using the following high level phases.
- I first started by trying to validate transactions of just one input, and one transaction type (more on this later), since i was still trying to figure a way of working.
- I created a `TransationData` struct, and a `Block` struct. these structs contain several sub structs, such as structs for `TransactionVin` and `TransactionVout` etc
- Next, i fetched all the transactions from the mempool and parsed them to the `TransactionData` struct, and added them to a slice of `TransactionData`
- Next up, i sorted the transactions based on fee and size. Actually, this was done right towards the end when i was optimizing my solution, but for the sake of this documentation, it is the next logical phase. So I chose to sort not based on one criteria alone, but based on the transaction price to size ratio. This is so that i don't include extremely heavy transactions with high fees ahead of very small transactions with an average fee.
- I then looped through all the transactions, and for each transaction with greater than or equal to 1 input, i call my `FullTxValidation` function which checks if all the transaction validation checks are valid, and returns a bool.
- If the transaction is valid we call our `SerializeATx` function, which returns both the serialized transaction with witness data and the serialized transaction without witness as a `*wire.MsgTx` object.
- Also, i calculate the transaction weight here and adding to the overall block weight and check to ensure the block weight units is still less than 4000000, which is the maximum block weight unit.
- I then have two slices of type `*wire.MsgTx` which i append the serialized transaction with witness data and the serialized transaction without witness data to.
- After looping through all the transactions, `CreateCoinbaseCommittmentScript` function is called. this function contains the code to create the Witness merkle root, and it takes as input, the slice which contains all transactions with their respective witnesses. This function creates the coinbase transaction commitment script.
- The result of the above method is then fed to the `CreateAndModCoinbaseTxWithSecondOutput` function which calls the `CreateCoinbaseTx` method (Which we will get to shortly) and then updates the coinbase modified coinbase transaction which contains the witness script.
- Finally, this file calls the `VerifyBlock` function, which accepts the modified coinbase transaction, the slice of valid transactions without witness data and the total block weight.

***The create_coinbase_tx.go file***
This file mostly contains functions related to creating the coinbase transaction which we will summarize as follows
- The `CreateCoinbaseTx` function has two return types `*wire.MsgTx` and `types.TransactionData`
- This function basically creates a wire.MsgTx transaction with one input and a single output. The input contains a previous outpoint which contains the script sig created with the `createCoinbaseScriptSig` function, and an index, which is just 32 bytes of zeros. The input also has a sequence *0xffffffff* which indicates no locking. 
The output contains the reward i pay myself as a reward for mining the block as well as any transaction fees accrued, along with a script pub key, which was generated from my pubkeyhash
- This transaction is then parsed to a `TransactionData` struct and returned along with the wire.msgtx transaction
- `createCoinbaseScriptSig` just creates the script sig for the coinbase transaction by appending the length of the block  height to the block height bytes itself.
