# GN-WALLET

Production-ready `Signer` for [scrypt-ts](https://github.com/sCrypt-Inc/scrypt-ts) that automatically splits change outputs into multiple UTXOs, keeping your wallet always ready with enough UTXOs for future contract deployments and transactions.

## Features

- **Automatic change splitting** – Divides the change output into multiple UTXOs to reach a target count (default 50).
- **Fee adjustment** – Recalculates transaction fees after splitting to ensure the transaction is valid.
- **Seamless integration** – Works with any `Provider` (e.g., `GNProvider`, `DefaultProvider`).
- **TypeScript ready** – Full type definitions included.
- **Tested on mainnet & testnet** – Safe for production use.

## Installation

    npm install gn-wallet

You also need to install `gn-provider` (or any other `Provider`) and `scrypt-ts`:

    npm install gn-provider scrypt-ts @scrypt-inc/bsv

## Usage

### Basic setup

    import { bsv } from 'scrypt-ts';
    import { GNProvider } from 'gn-provider';
    import { GNWallet } from 'gn-wallet';
    import { MyContract } from './my-contract';

    // 1. Create a provider (example using GNProvider)
    const provider = new GNProvider(
        bsv.Networks.mainnet,
        'your-woc-api-key',
        ''
    );

    // 2. Create the wallet signer with your private key
    const privateKey = bsv.PrivateKey.fromWIF('your-wif-here');
    const wallet = new GNWallet(privateKey, provider, {
        targetUtxos: 50,    // desired number of UTXOs for the change address
        dustLimit: 546,     // minimum satoshis per output (default 546)
        cacheTTL: 30000,    // UTXO cache TTL in milliseconds
    });

    // 3. Connect your contract
    const contract = new MyContract(/* constructor args */);
    await contract.connect(wallet);

    // 4. Deploy – change will be split automatically
    const deployTx = await contract.deploy(1000);
    console.log('Deployed at:', deployTx.id);

### Calling a contract method

    // The change output will be split automatically in every transaction
    const callTx = await contract.methods.transfer(500, receiverAddress);
    console.log('Transaction ID:', callTx.tx.id);

## Configuration options

| Option        | Type                  | Default  | Description |
|---------------|-----------------------|----------|-------------|
| `targetUtxos` | `number`              | `50`     | Desired total number of UTXOs for the change address after splitting. |
| `dustLimit`   | `number`              | `546`    | Minimum satoshis per output (must be >= 546). |
| `cacheTTL`    | `number`              | `30000`  | UTXO cache time-to-live in milliseconds. |
| `network`     | `bsv.Networks.Network`| `mainnet`| Network (`mainnet` or `testnet`). |

## Using with other providers

`GNWallet` works with any `scrypt-ts` `Provider`. Example with `DefaultProvider`:

    import { DefaultProvider } from 'scrypt-ts';

    const provider = new DefaultProvider({
        network: bsv.Networks.testnet
    });
    const wallet = new GNWallet(privateKey, provider, { targetUtxos: 10 });

## How it works

1. Before signing a transaction, `GNWallet` inspects the transaction outputs to find the change output (the output that sends funds back to your address).
2. It fetches your current UTXO count for that address.
3. If the number of UTXOs is below `targetUtxos` and the change amount is sufficient, it replaces the single change output with multiple smaller outputs.
4. The transaction fee is recalculated based on the new size, and the extra fee is deducted from one of the split outputs.
5. The transaction is then signed and broadcast as usual.

If splitting is not possible (e.g., change amount too small), the transaction is sent unchanged.

## Testing on testnet

Always test first on testnet:

    const provider = new GNProvider(bsv.Networks.testnet, 'your-woc-api-key');
    const wallet = new GNWallet(privateKey, provider, { targetUtxos: 10 });

After deployment, check your address on a testnet explorer (e.g., [WhatsOnChain testnet](https://test.whatsonchain.com)). You should see multiple small UTXOs instead of one large change output.

## Error handling

- If the change output is not found or its value is below `dustLimit`, splitting is skipped.
- If the fee adjustment would make any output drop below `dustLimit`, splitting is aborted and the original transaction is sent.
- All errors are logged to the console; the transaction will still be broadcast (but without split).

## Requirements

- Node.js >= 14
- `scrypt-ts` >= 1.4.5
- `@scrypt-inc/bsv` (automatically installed with `scrypt-ts`)

## License

MIT

## Repository

[https://github.com/borisjavier/gn-wallet](https://github.com/borisjavier/gn-wallet)

## Author

borisjavier

## Acknowledgements

Built with [scrypt-ts](https://scrypt.io/) and [GNProvider](https://www.npmjs.com/package/gn-provider).