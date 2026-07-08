import { UTXO, Signer, Provider, AddressOption, SignTransactionOptions, SignatureRequest, SignatureResponse, DEFAULT_SIGHASH_TYPE } from 'scrypt-ts';
import * as bsv from '@scrypt-inc/bsv';
import { GNWalletOptions } from './interfaces';
import { signTx } from 'scryptlib/dist';

export class GNWallet extends Signer {
    private privateKeys: Map<string, bsv.PrivateKey> = new Map();
    private address!: bsv.Address;
    private pubKey!: bsv.PublicKey;
    private options: Required<GNWalletOptions>;

    constructor(privateKeys: (bsv.PrivateKey | string)[] | bsv.PrivateKey | string, provider?: Provider, options?: GNWalletOptions) {
        super(provider);
        const keysArray = Array.isArray(privateKeys) ? privateKeys : [privateKeys];
        if (keysArray.length === 0) throw new Error("Se requiere al menos una llave privada");
        keysArray.forEach(pk => this.addPrivateKey(pk));
        
        const firstKey = this.privateKeys.values().next().value as bsv.PrivateKey;
        this.pubKey = firstKey.toPublicKey();
        this.address = firstKey.toAddress();
        this.options = {
            network: options?.network ?? bsv.Networks.mainnet,
            cacheTTL: options?.cacheTTL ?? 30000,
            targetUtxos: options?.targetUtxos ?? 50,
            dustLimit: options?.dustLimit ?? 546,
        };
    }

    // --- Implementaciones requeridas por la clase abstracta Signer ---

    async getNetwork(): Promise<bsv.Networks.Network> {
        return this.options.network;
    }

    async isAuthenticated(): Promise<boolean> {
        return true;
    }

    async requestAuth(): Promise<{ isAuthenticated: boolean; error: string }> {
        return { isAuthenticated: true, error: '' };
    }

    setProvider(provider: Provider): void {
        this.provider = provider;
    }

    async getDefaultAddress(): Promise<bsv.Address> {
        return this.address;
    }

    async getDefaultPubKey(): Promise<bsv.PublicKey> {
        return this.pubKey;
    }

    async getPubKey(address?: AddressOption): Promise<bsv.PublicKey> {
        if (address) {
            const key = this.privateKeys.get(address.toString());
            if (!key) throw new Error(`Llave no encontrada para: ${address.toString()}`);
            return key.toPublicKey();
        }
        return this.pubKey;
    }

    // --- Métodos de Firma ---

    async getSignatures(rawTxHex: string, sigRequests: SignatureRequest[]): Promise<SignatureResponse[]> {
        const tx = new bsv.Transaction(rawTxHex);
        const responses: SignatureResponse[] = [];

        for (const req of sigRequests) {
            // Validación defensiva para tipos opcionales
            if (!req.scriptHex || req.satoshis === undefined) {
                throw new Error(`Datos incompletos en input ${req.inputIndex}`);
            }

            const privKey = this.privateKeys.get(req.address?.toString() ?? this.address.toString());
            if (!privKey) continue;

            const script = bsv.Script.fromHex(req.scriptHex);
            
            // Inyectar el output para permitir la firma
            if (tx.inputs[req.inputIndex]) {
                tx.inputs[req.inputIndex].output = new bsv.Transaction.Output({
                    script: script,
                    satoshis: req.satoshis
                });
            }

            const subScript = req.csIdx !== undefined ? script.subScript(req.csIdx) : script;
            const signature = signTx(
                tx, 
                privKey, 
                subScript, 
                req.satoshis, 
                req.inputIndex, 
                req.sigHashType ?? DEFAULT_SIGHASH_TYPE
            );
            
            responses.push({
                inputIndex: req.inputIndex,
                sig: signature,
                publicKey: privKey.toPublicKey().toString(),
                sigHashType: req.sigHashType ?? DEFAULT_SIGHASH_TYPE,
                csIdx: req.csIdx,
            });
        }
        return responses;
    }

    async signTransaction(tx: bsv.Transaction, options?: SignTransactionOptions): Promise<bsv.Transaction> {
        // Firmamos inputs P2PKH que poseamos sin mutar la estructura
        tx.sign(Array.from(this.privateKeys.values()));
        return tx;
    }

    async _signAndSendTransaction(tx: bsv.Transaction): Promise<string> {
        if (!this.provider) throw new Error("Provider no conectado");
        // No mutamos la tx, delegamos el balanceo al provider/scrypt-ts
        const signedTx = await this.signTransaction(tx);
        return await this.provider.sendTransaction(signedTx);
    }

    // --- Métodos auxiliares ---

    public addPrivateKey(privateKey: bsv.PrivateKey | string): void {
        const key = typeof privateKey === 'string' ? bsv.PrivateKey.fromString(privateKey) : privateKey;
        this.privateKeys.set(key.toAddress().toString(), key);
    }

    async getBalance(address?: AddressOption): Promise<{ confirmed: number; unconfirmed: number }> {
        if (!this.provider) throw new Error("Provider no conectado");
        return this.provider.getBalance(address ? address : this.address);
    }

    async signMessage(message: string, address?: AddressOption): Promise<string> {
        let key = this.privateKeys.values().next().value as bsv.PrivateKey;
        if (address) {
            const requestedKey = this.privateKeys.get(address.toString());
            if (requestedKey) key = requestedKey;
        }
        return bsv.Message.sign(message, key).toString();
    }
}