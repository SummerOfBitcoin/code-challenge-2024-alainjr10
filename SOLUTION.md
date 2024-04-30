# Summer of Bitcoin 2024: Mine your first block - Assignment Solution Documentation

## Design approach
### the main.go file 
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

### The create_coinbase_tx.go file
This file mostly contains functions related to creating the coinbase transaction which we will summarize as follows
- The `CreateCoinbaseTx` function has two return types `*wire.MsgTx` and `types.TransactionData`
- This function basically creates a wire.MsgTx transaction with one input and a single output. The input contains a previous outpoint which contains the script sig created with the `createCoinbaseScriptSig` function, and an index, which is just 32 bytes of zeros. The input also has a sequence *0xffffffff* which indicates no locking. 
The output contains the reward i pay myself as a reward for mining the block as well as any transaction fees accrued, along with a script pub key, which was generated from my pubkeyhash
- This transaction is then parsed to a `TransactionData` struct and returned along with the wire.msgtx transaction
- `createCoinbaseScriptSig` just creates the script sig for the coinbase transaction by appending the length of the block  height to the block height bytes itself.

### validate_tx.go file
This function contains the core part of the verification process. some functions here are fairly straight forward and they explain for themselves what they do, I'll pick a few functions here to brief about
- The very first function in ths file, `FullTxValidation` just basically calls three functions, the `ValidateTxTimeLock`, the `ValidateTxHashes` and the `VerifyFullTxSig`. If all these functions return true, then the transaction is valid.

    - `ValidateTxTimeLock`This function just checks the lock time. First it checks if current time is greater than the lock time, if so, the transaction is invalid, because it wouldn't have been published even, so no need for verification. It then checks if the locktime is less than 500000000, then it's a block height locktime and should be considered valid. Finally we check if the sequence is the max sequence (0xffffffff) or if the sequence is less than or equal to the relative locktime max sequence `0xefffffff` then the transaction is valid, else, it is invalid.
    - `ValidateTxHashes` function takes in a transaction and loops through all of it's inputs. It first of all keeps track of an `overallStack` stack instance. Then at each iteration over the input, it creates a new instance of a stack and goes through the opcodes and operands responsible for comparing hashes and performs operations such as hashing the script pubkey and pushing the hash to the stack and then popping top 2 items, which include this hash  and the hash provided in the scriptpubkey and comparing them. In the end, if the particular input is valid, we push `0x01` to the overall stack. else, we push `0x00` to the stack and break out of the loop. In the end, if our overall stack contains `0x01` after going through all the inputs, then the transaction passed this test.
    - `VerifyFullTxSig` takes a transaction, loops through all the inputs sequentially, and then calls the `VerifyTxSig` function on the said input. This function carries out the process of verifying transaction signatures. If the signature is valid here, we return true and continue with the next input, until we've looped through all the inputs, if the input is still true, then the signatures for the transaction is valid. If however at any input, the signature verification fails, we break out of the loop and return false. The transaction is invalid.
This file contains some other important functions such as `SerializeATxWOSigScript` and `SerializeATx` which does what the name suggests, serializes a transaction with the signature script and witness,  and serializes a transaction without witness and script data respectively. These 2 functions could be augmented into one single function, but for simplicity, i decided to split the functions. Ideally, we would rename the `SerializeATxWOSigScript` function to something like `CalculateHashMessage` or similar, because this function essentially calculates the hash pre image message which is used to verify signatures in `VerifyTxSig` function we just saw above. 

Notice how these functions `VerifyTxSig` and `SerializeATxWOSigScript` take in as input a transaction and in index value. This index is the index of the currently verifying input in the Transaction inputs array.

### create_block.go
Finally, we get to the create block file which it contains the functions responsible for helping in the mining process.
- `CreateBlockHeader` creates the block header and returns the result as a `*wire.BlockHeader`. Block header creation involves adding parameters such as the target, previous block header, merkle root, version number
- Remember our coinbase having just one transaction output as mentioned above? well we actually do have two outputs in the coinbase transaction. The second output just pays 0 zero as the amount and has as pubkey script, the commitment script, as designed in the `CreateAndModCoinbaseTxWithSecondOutput` method. We add the second output to the coinbase transaction and return the updated coinbase tx
- `ParseBlock` function takes in all the valid transaction, and coinbase transaction, calculates the merkle root using `CreateMerkleTree` function and then adds this merkel root to the block header. It then adds the coinbase transaction to a slice of transactions, and then loops through all the other transactions and adds to this slice. finally, we serialize this block and return the result as a `*wire.MsgBlock` object
- Next we create the merkle roots. I say root(s) because we need to create two merkle roots, if  our block contains segwit transactions, which it does. I have two functions for this which again, could be combined into a single function, but for simplicity sake, we keep them in separate functions, `CreateMerkleTree` and `CreateWitnessMerkleTree`. Witness merkletree is created with witness transaction ids and not the "normal transaction id"
- Finally, we have the `VerifyBlock` which first of all calls the `ParseBlock` function and stores the result in a block variable  We then increment the nonce if the value is less than max sequence number (0xffffffff)

Now if the block has not been mined yet, we update our block header by incrementing the nonce and replacing the previous nonce. We then hash this header and compare to the compact version of the target. if it isn't less than the target, we increment the nonce and go again. We continue doing this (incrementing nonce, updating block header, hashing and comparing), until we find the appropriate target. Then we stop trying, write our ouput to a file, and then close the mining process, and just like that, our block has been mined.


This is like a high level overview of what has been done in the code. while this doesn't cover all the functions used, and the ordering isn't very appropriate, it does give the overall picture of what was implemented during the mining process.


## Implementation Details
The design approach explained above already covered some of the implementation details, as it mentioned some of the functions and their roles. However, here we will go into more details about the implementation of the functions and the logic behind them.

- `SortTxs`: This function was responsible for sorting transactions based on their fee/weight ratio, with most profitable transactions based on this metric, placed at the top of our array. Here's a basic pseudocode of how this function works. For this, we use Go's `sort.Slice` to sort the slice based on the criteria provided in the function. Under the hood, we do something as follows;
```lk
// For each pair of transactions (i and j) within the 'transactions' list:
  for i in transactions:
    for j in transactions:

      // Calculate input and output amounts for transaction i
      inputAmountI = 0
      outputAmountI = 0
      for each input in transaction i:
        inputAmountI += input.value
      for each output in transaction i:
        outputAmountI += output.value

      // Do the same for transaction j
      inputAmountJ = 0
      outputAmountJ = 0
      for each input in transaction j:
        inputAmountJ += input.value
      for each output in transaction j:
        outputAmountJ += output.value

      // Serialize transaction i and j. The serialize A TX function returns result of serialized transaction with and without witness data in bytes

      serialized_i_no_witness, serialized_i_with_witness = SerializeATx(transaction i)
      serialized_j_no_witness, serialized_j_with_witness = SerializeATx(transaction j)

      // Calculate transaction weights 
      weight_i = (length of serialized_i_no_witness) * 3 + (length of serialized_i_with_witness) 
      weight_j = (length of serialized_j_no_witness) * 3 + (length of serialized_j_with_witness) 

      // Calculate fee-to-weight ratios
      feeI = inputAmountI - outputAmountI
      feeJ = inputAmountJ - outputAmountJ
      ratioI = feeI / weight_i
      ratioJ = feeJ / weight_j

      // Compare ratios and modify the order of transactions i and j in the 'transactions' list accordingly:
      if ratioI > ratioJ:
        # Place transaction i before transaction j (prioritize higher ratio)
      else:
        # Keep order of i and j or place j before i (prioritize lower or equal ratio) 

```

- `ValidateTxTimeLock`: This function was responsible for validating the locktime of a transaction as explained above

```
function ValidateTxTimeLock(transaction)
  // Define a constant for relative timelock maximum value
  max_relative_timelock = 0xefffffff

  // Get the current time (Unix timestamp)
  current_time = get_current_unix_timestamp()

  // Check for absolute block height locktime:
  if transaction.Locktime < 500000000:  
    return True # Valid block height locktime

  // Check locktime against current time
  if transaction.Locktime > current_time:
    return False # Transaction locked in the future

  // Check for relative timelocks in inputs
  for each input in transaction.Vin:
    if input.Sequence == 0xffffffff:
      return True # Input is immediately spendable

    if input.Sequence <= max_relative_timelock:
      return True # Valid relative timelock

  // If none of the above conditions match:
  return False # Transaction is timelocked
```
There are some other crucial transactions that implemented some logic, but mostly, these functions just followed spcifications stated in the BIP documentation, for instance the `SerializeATxWOSigScript` function, which serializes a transaction without the signature script, and returns the signature hash message follows the guidelines stated in the [BIP 0143](https://github.com/bitcoin/bips/blob/master/bip-0143.mediawiki) and the `VerifyTxSig` function which verifies the signature of a transaction. using the hash message and the signature script.



## Results and Performance
**Results**

The solution was able to successfully mine a block with the given set of transactions. The block was mined efficiently, and the output was generated as expected. The block was mined with the difficulty target of `0000ffff00000000000000000000000000000000000000000000000000000000`, I successfully mined `3468` valid transactions in the block, and the block weight was `3997183`, which which admittedly could be improved upon, to get closer to the maximum block weight of `4000000`. The block was mined in a reasonable amount of time, and the output was generated as expected. I was able to get a fee of `25780179` which was fantastic, and enhanced due to my optimization of the transactions to be mined. The block header when the block was mined was `0000d1a0ee7479fb0fd08ccb005f30def2dc3f1c4171a4bcd0022d597d2631b4`, and the nonce had a value of `59795`

My output.txt file was generated as expected, and looked something like this

``` 
04000000ca26a1450e4576e5cd2b26a8110cf1098cafc419c6a900000000000000000000381696d356317d7c423bcdc9a0a4ca5562180755aea0bdeee4f1aedfa7cea95d7c9f3066ffff001f93e90000
010000000001010000000000000000000000000000000000000000000000000000000000000000ffffffff05040372cc0cffffffff02007c3125000000001976a9144b02eabcefed9565eebeed205f88b2f2881b124388ac0000000000000000266a24aa21a9ed8325aa3017492293aeee31d81c44213bd196c6d3c9c1dd71d70f6aba728add340120000000000000000000000000000000000000000000000000000000000000000000000000
9aa483e583e6a0529fbb52a2d98611bc2bbc4619f06b5d0eb84450c3ce4624be
82f9f96db7bdbb9e70626747632e373b34eefd50d613dfea7092744169591b6e
7cb2a4f55245bae141a5d6ad51c08d7a9fdf2c2b905e4d97639ed80b82e69800
a9e537569db3c64340ed5abcdd983e9bb1b6ad6f90c93bc80d31c5cc0490bcea
4ab3cc4296fee78153d60d2884323a84260157db0b83a72309272f109ad9dd32
99bf982da397947eb0999292e909c17c78d884e18d3e59ac03fd2aa7f0241c7e
dcd522b3588c7adb0418454539e1a929fff936f211e5a20383fdcbc3ad8751b9
423c61f1ec58b9400a373e1052c26debdd5d55eb0057900c3dcf41f54762486c
etc...
```

**As For peformance**, 

While the solution was able to mine the block efficiently, there are still areas that could be improved upon. For example, the block weight could be optimized further to get closer to the maximum block weight of `4000000`. The solution could also be optimized to peform some operations more efficiently and manage memory better. I would say the sorting of transactions based on the metrics I used was pretty optimized.  The transaction was loaded into our slice of Transaction struct in linear time and read operations from this slice was also done in linear time. However, we created many more data structures that could and probably should be optimized better for better memory usage. For instance, we have a `validTxs` slice and `validTxsWithWitness` which basically store the transaction, but one of the slices store the transactions with the witness data, while the other stores without. This could be optimized to use a single slice, and then just serialize the transaction with or without the witness data as needed. This would save memory and make the solution more efficient. However, when passing transactions array to most of the functions, we passed them by reference, in order to avoid unnecessary copying of the data. This was done to optimize memory usage and improve performance.

Overall, I came into this project with very limited knowledge on how exactly to proceed, which libraries to use, how exactly to peform certain operations, and I had to learn them on the fly, and how to implement them in Go, hence the solution might not be the most optimized, but it was a great learning experience, and I'm happy with the results I was able to achieve. Given the time, I would have loved to optimize the solution further, and maybe even implement some additional features, but then time is limited as I have to prepare for contributing to potential organisations.


## Conclusion
<!-- Discuss any insights gained from solving the problem, and outline potential areas for future improvement or research. Include a list of references or resources consulted during the problem-solving process.
 -->

In conclusion, this was a very challenging project, but also a very rewarding one. I learned a lot about how Bitcoin works under the hood, and how to implement a basic mining algorithm from scratch. I also learned a lot about Go, and how to use it to implement complex algorithms. I also learned a lot about how to optimize code for performance and memory usage. In addition to the code part, I came to find out some very valuable online resources and communities where i can always turn to for help, such as the [Bitcoin improvement proposals](https://github.com/bitcoin/bips/tree/master) (Which were very key for me to get to where I am now with regards to the project), the Bitcoin wiki, and the [Bitcoin stack exchange](https://bitcoin.stackexchange.com/) (Whose forum played a huge role, especially in helping me overcome a few blockages), I cannot even begin to mention how the [LearnmeABitcoin website](https://learnmeabitcoin.com) helped me throughout. It is a fantastic resource for anyone looking to learn about Bitcoin and I would recommend it a thousand percent. Not forgetting [Grokking Bitcoin](https://rosenbaum.se/book) online book and resources which laid a very strong foundation for my knowledge and interest in bitcoin. The discord Summer of bitcoin forum was also very vital, as i got some valuable knowledge from my peers on there, as well as sharing my knowledge to others when neccessary.

In the future, I would love to optimize my code better, and go on to do more research and learn more advance bitcoin concepts.

 I think I'm pretty contented with the results I was able to achieve, albeit always looking to learn and improve, and I'm proud of the work I put into this project. I would like to thank the Summer of Bitcoin team for this opportunity, and I look forward to contributing to potential organisations in the future.

 **Some references that helped me throughout thi project include, but not limited to:**
 - Signature verification for segwit transactions [https://github.com/bitcoin/bips/blob/master/bip-0143.mediawiki](https://github.com/bitcoin/bips/blob/master/bip-0143.mediawiki)
 - Everything about the foundation of bitcoin [https://rosenbaum.se/book](https://rosenbaum.se/book)
 - Well, pretty much every sub topic of bitcoin from https://learnmeabitcoin.com
 - Sign transactions with multiple inputs (this is also covered in learnmeabitcoin) https://bitcoin.stackexchange.com/questions/41209/how-to-sign-a-transaction-with-multiple-inputs
 - Redeeming a p2pkh transaction https://bitcoin.stackexchange.com/questions/3374/how-to-redeem-a-basic-tx
 - Creating and signing segwit transaction with multiple inputs https://medium.com/coinmonks/creating-and-signing-a-segwit-transaction-from-scratch-ec98577b526a
 - Create raw multisig p2sh transaction in Go https://mahdidarabi.medium.com/build-p2sh-address-and-spend-its-fund-in-golang-1a03a4131512

 These are just some of the resources that i used, but it was a very lengthy and extensive learning process for me