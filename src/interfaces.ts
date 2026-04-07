// src/interfaces.ts
import * as bsv from '@scrypt-inc/bsv';

export interface GNWalletOptions {
    network?: bsv.Networks.Network;
    cacheTTL?: number;
    targetUtxos?: number;
    dustLimit?: number;
}

export interface SignedTransactionResult {
    tx: bsv.Transaction;
    signedInputs: number[];
}