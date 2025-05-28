# GOAT Bitvm2 Node

A universal node for Operator, Challenger and Covenant Signer.

## Tutorial

See [Node](node/README.md).

## Roles

There are three main roles in this protocol, Committee, Operator, Challenger and Relayer.

| Role       | Functions                                                                                                                                                                                                                                                                                  |
|------------|--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Committee  | N-of-n signers for the presign transactions                                                                                                                                                                                                                                                |
| Operator   | Anyone can be an operator. <br>1. Exchange PeggleBTC to native BTC with users <br>2. Kickoff the reimbursement from Committee <br> 3. Generate the preimage of the hash time lock to each watchtower <br>4. Exchange PegBTC to BTC with end-user via AtomicSwap                            |
| Challenger | Anyone can be a challenger <br>1. Verify the valid of the reimbursement from operators offchain <br>2. Submit the challenge transaction on Bitcoin to force the kick off to unhappy path                                                                                                   |
| Watchtower | A special kind of challenger, selected from the Sequencer candidates, maintains the longest chain headers and spends the Watchtower output of the Kickoff transaction.                                                                                                                     |
| Verifier   | Another kind of challenger. Once the kickoff is on the unhappy path, and the operator unveils all the execution trace(Circuit F below), verify finds the flow in the execution trace, and can spend the UTXO from Assert transaction, and stop the operator to continue the reimbursement. |
| Relayer    | Operated by official nodes.<br>1.Provide bootnode services  <br>2 Supports asset transfer services between Layer 1 and Layer 2 of the BTVM2 system, including tracing L1 txn; calling and monitoring L2 gateway contract <br>3 Starting pegin processing.                                  |                                                                    |

## BitVM2 protocol

### Peg-in

<!-- https://mermaid.js.org/syntax/stateDiagram.html#state-diagrams -->

```mermaid
sequenceDiagram
    participant U as User
    participant R as Relayer
    participant F as Committee 
    participant O as Operator
    participant A as All Roles
    participant B as Bitcoin Network
    participant L2 as Layer 2

    U->>B: Broadcast incomplete Peg-in tx
    U->>R: Send Peg-in Request
    R->>F: Generate Peg-in instance from user request
    F->>A: Generate & broadcast keypair + Musig2 Nonce
    O->>F: Generate BitVM2 tx graph & Presign Challenge 
    F->>A: Presign Take1/Take2/Disprove/Assert tx
    R->>U: Update Peg-in instance & store graph & notify user to broadcast Peg-in tx  through front end
    U->>B: Sign & broadcast  Peg-in tx
    R->>B: Monitor Peg-in tx Transaction confirmation
    R->>L2: Submit Peg-in tx_id & graph info & mint pegBTC
```

**Message Type**

### Kick-Off

```mermaid
sequenceDiagram
    participant U as User
    participant R as Relayer
    participant O as Operator
    participant A as All Roles
    participant B as Bitcoin Network
    participant L2 as Layer 2

    U->>L2: InitWithdraw tx (lock pegBTC & UTXO & mark graph could be used to kickoff the process)
    R->>L2: Get graph id & instance id related to initWithdraw tx
    R->>O: Notify O to sign & broadcast Kickoff tx
    O->>B: Sign & broadcast Kickoff tx
    R->>B: Monitor Kickoff tx confirmation
    R->>L2: Submit Kickoff tx to burn locked pegBTC & update contract state
    R->>A: Broadcast Kickoff tx confirmation
```

**Message Type**

### Claim

```mermaid
sequenceDiagram
    participant R as Relayer
    participant O as Operator
    participant A as All Roles
    participant B as Bitcoin Network
    participant L2 as Layer 2

    R->>O: After Kickoff, notify O to do Take-1 action until challenge period timeout
    O->>B: Sign & broadcast Take-1 tx
    O->>A: Broadcast Take-1 tx confirmation
    R->>B: Monitor Take-1 tx confirmation & update graph state
    R->>L2: Submit Take-1 tx to update contract state
```

**Message Type**

### Challenge

```mermaid
sequenceDiagram
    participant R as Relayer
    participant C as Challenger
    participant O as Operator
    participant A as All Roles
    participant B as Bitcoin Network
    participant L2 as Layer 2
    
    R->>B: Monitor Kickoff tx confirmation 
    R->>A: Broadcast Kickoff tx confirmation
    C->>L2: Check initWithdraw validity
    C->>B: If invalid, broadcast Challenge tx
    C->>A: Send challenge notification
    O->>B: Generate & broadcast Assert tx with proof
    R->>B: Monitor Assert tx confirmation
    R->>A: Assert tx confirmation
    C->>B: Verify proof from Assert witness
    alt Proof incorrect
        C->>B: Broadcast Disprove tx
        C->>A: Broadcast Disprove tx confirmation
        R->>L2: Monitor Disprove tx confirmation
        R->>L2: Submit Disprove tx to update contract state
    else Proof correct
        Note over C: Challenge failed
        R->>O: Notify O do Take-2 action until disproving period timeout
        O->>B: broadcast Take-2
        O->>A: Broadcast Take-2 tx confirmation
        R->>L2: Monitor Take-2 tx confirmation
        R->>L2: Submit Take-2 to update contract state
    end
```

**Message Type**

## Node

### Run a node

```bash
./target/debug/goat-bitvm2-node
```

It should print out the address to listen on.

In another console, run

```bash
./target/debug/goat-bitvm2-node --bootnodes /ip4/127.0.0.1/tcp/50022
```

Replace the peer address with above.

#### Operation

**Requirement**

Committee Member: need approval from all committee members

Challenger: anyone can be a challenger

Operator: anyone who holds PegBTC can be an operator

**Operation**

1. Generate identity
2. Configure the bootnode and launch the node

**Unjoin**

#### Identity and Authentication

Generate the identity by cli.

P2P: ed25519

Committee n-of-n: musig2 (secp256k1)

### Store

**Local Store**: Sqlite
**Memory Store**

**Scheme**

| Field name       | Description                    | Field type      |
|------------------|--------------------------------|-----------------|
| Peg-in txid      | Peg-in Bitcoin transaction id  | bytes: 32-byte  |
| Covenant address | BitVM2 covenant address        | bytes: 64-byte  |
| Amount           | The amount pegged-in           | integer: 32-bit |
| Operator         | The operator's bitcoin address | string          |
| Step             | Current step                   | integer: 8-bit  |
| BitVM2 instance  | BitVM2 transaction graph       | string          |

### Middleware

Define all the behaviours
and [metrics server](https://github.com/libp2p/rust-libp2p/blob/e1bba263070194282cad48f07fb4aa0c87d03b55/examples/metrics/src/http_service.rs#L32).

* Peer discovery protocol: KAD
* Basic behaviours
* Custom behaviours 
