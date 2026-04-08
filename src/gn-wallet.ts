// src/gn-wallet.ts (v1.0.10)
import { Signer, Provider, AddressOption, SignTransactionOptions, SignatureRequest, SignatureResponse, DEFAULT_SIGHASH_TYPE } from 'scrypt-ts';
import * as bsv from '@scrypt-inc/bsv';
import { GNWalletOptions } from './interfaces';

export class GNWallet extends Signer {
    private privateKey: bsv.PrivateKey;
    private address: bsv.Address;
    private pubKey: bsv.PublicKey;
    private options: Required<GNWalletOptions>;

    constructor(privateKey: bsv.PrivateKey | string, provider?: Provider, options?: GNWalletOptions) {
        super(provider);
        if (typeof privateKey === 'string') {
            this.privateKey = bsv.PrivateKey.fromString(privateKey);
        } else {
            this.privateKey = privateKey;
        }
        this.pubKey = this.privateKey.toPublicKey();
        this.address = this.pubKey.toAddress();
        this.options = {
            network: options?.network ?? bsv.Networks.mainnet,
            cacheTTL: options?.cacheTTL ?? 30000,
            targetUtxos: options?.targetUtxos ?? 50,
            dustLimit: options?.dustLimit ?? 546,
        };
    }

    async connect(provider: Provider): Promise<this> {
        this.provider = provider;
        return this;
    }

    async getNetwork(): Promise<bsv.Networks.Network> {
        return this.options.network;
    }

    async getDefaultAddress(): Promise<bsv.Address> {
        return this.address;
    }

    async getDefaultPubKey(): Promise<bsv.PublicKey> {
        return this.pubKey;
    }

    async getPubKey(address?: AddressOption): Promise<bsv.PublicKey> {
        if (address && address.toString() !== this.address.toString()) {
            throw new Error("GNWallet solo posee una dirección");
        }
        return this.pubKey;
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

    async getSignatures(rawTxHex: string, sigRequests: SignatureRequest[]): Promise<SignatureResponse[]> {

        console.log(`[GNWallet] Mi llave pública es: ${this.pubKey.toString()}`);
        const tx = new bsv.Transaction(rawTxHex);
        const responses: SignatureResponse[] = [];

        for (const req of sigRequests) {
            try {

                if (req.scriptHex !== undefined && req.satoshis !== undefined) {
                    tx.inputs[req.inputIndex].output = new bsv.Transaction.Output({
                        script: bsv.Script.fromHex(req.scriptHex),
                        satoshis: req.satoshis
                    });
                } else {
                    throw new Error(`Faltan scriptHex o satoshis para el input ${req.inputIndex}`);
                }
                const sighashType = req.sigHashType ?? DEFAULT_SIGHASH_TYPE;
                const sigHex = tx.getSignature(req.inputIndex, this.privateKey, sighashType);

                if (!sigHex || typeof sigHex !== 'string') {
                    throw new Error(`No se pudo generar firma para input ${req.inputIndex}`);
                }

                //const sighashByte = (sighashType & 0xff).toString(16).padStart(2, '0');
                //const fullSig = sigHex + sighashByte;

                responses.push({
                    inputIndex: req.inputIndex,
                    sig: sigHex,
                    publicKey: this.pubKey.toString(), 
                    //publicKey: this.pubKey.toBuffer().toString('hex'),
                    sigHashType: sighashType,
                    csIdx: req.csIdx,
                });
            } catch (e) {
                console.warn(`Error firmando input ${req.inputIndex}:`, e);
                responses.push({
                    inputIndex: req.inputIndex,
                    sig: '',
                    publicKey: '',
                    sigHashType: req.sigHashType ?? DEFAULT_SIGHASH_TYPE,
                    csIdx: req.csIdx,
                });
            }
        }
        return responses;
    }

    async signRawTransaction(rawTxHex: string, options?: SignTransactionOptions): Promise<string> {
        const tx = new bsv.Transaction(rawTxHex);
        const signedTx = await this.signTransaction(tx, options);
        return signedTx.serialize();
    }

    async signTransaction(tx: bsv.Transaction, options?: SignTransactionOptions): Promise<bsv.Transaction> {
        for (let i = 0; i < tx.inputs.length; i++) {
            try {
                tx.sign(this.privateKey);
            } catch (e) {
                console.warn(`No se pudo firmar input ${i}:`, e);
            }
        }
        return tx;
    }

    async signMessage(message: string, address?: AddressOption): Promise<string> {
        return bsv.Message.sign(message, this.privateKey).toString();
    }

    async getBalance(address?: AddressOption): Promise<{ confirmed: number; unconfirmed: number }> {
        if (!this.provider) throw new Error("Provider no conectado");
        const addr = address ? address : this.address;
        return this.provider.getBalance(addr);
    }

    async _signAndSendTransaction(tx: bsv.Transaction): Promise<string> {
        if (!this.provider) throw new Error("Provider no conectado");
        const changeAddress = this.address;
        const currentUtxos = await this.provider.listUnspent(changeAddress);
        const currentCount = currentUtxos.length;
        const txWithSplit = await this.splitChangeOutput(tx, changeAddress, currentCount);
        const signedTx = await this.signTransaction(txWithSplit);
        const txid = await this.provider.sendTransaction(signedTx);
        return txid;
    }

    /*private async splitChangeOutput(
        tx: bsv.Transaction,
        changeAddress: bsv.Address,
        currentUtxoCount: number
    ): Promise<bsv.Transaction> {
        const dustLimit = this.options.dustLimit;
        const target = this.options.targetUtxos;
        const myScript = bsv.Script.buildPublicKeyHashOut(changeAddress);
        const myScriptHex = myScript.toHex();

        // 1. Encontrar el output de cambio
        const changeIndex = tx.outputs.findIndex(out => out.script.toHex() === myScriptHex);
        if (changeIndex === -1) return tx;

        const changeAmount = tx.outputs[changeIndex].satoshis;
        const needed = target - currentUtxoCount;

        if (changeAmount < dustLimit || needed <= 1) return tx;

        const maxSplits = Math.floor(changeAmount / dustLimit);
        let splits = Math.min(needed, maxSplits);
        if (splits < 2) return tx;

        // 2. Distribución equitativa
        const valuePerSplit = Math.floor(changeAmount / splits);
        let remaining = changeAmount;
        const newOutputs = tx.outputs.filter((_, idx) => idx !== changeIndex);

        for (let i = 0; i < splits; i++) {
            const isLast = i === splits - 1;
            const val = isLast ? remaining : valuePerSplit;
            if (val >= dustLimit) {
                newOutputs.push(new bsv.Transaction.Output({
                    satoshis: val,
                    script: myScript
                }));
            }
            remaining -= val;
        }
        tx.outputs = newOutputs;

        // 3. Recalcular fee exactamente (como en la versión original)
        const oldFee = tx.getFee();
        const rawHex = tx.serialize();
        const txSizeBytes = rawHex.length / 2;
        const feePerKb = await this.provider!.getFeePerKb();
        const newFee = Math.ceil((txSizeBytes * feePerKb) / 1000);
        const feeDiff = newFee - oldFee;

        if (feeDiff > 0) {
            const lastIndex = tx.outputs.length - 1;
            const lastOutput = tx.outputs[lastIndex];
            if (lastOutput.satoshis - feeDiff >= dustLimit) {
                const adjustedOutput = new bsv.Transaction.Output({
                    satoshis: lastOutput.satoshis - feeDiff,
                    script: lastOutput.script
                });
                tx.outputs[lastIndex] = adjustedOutput;
                console.log(`[GNWallet] Fee ajustado: +${feeDiff} sats`);
            } else {
                console.warn(`[GNWallet] Fee extra (${feeDiff}) imposible de cubrir, abortando split.`);
                return tx;
            }
        }

        console.log(`[GNWallet] Split: ${splits} UTXOs de ~${valuePerSplit} sats, fee ${newFee} sats`);
        return tx;
    }*/
   /**
 * Función de ayuda para extraer una dirección de un script P2PKH.
 * No depende de métodos inexistentes en la API.
 */
private extractAddressFromScript(script: bsv.Script, network: bsv.Networks.Network): bsv.Address | null {
    try {
        // La estructura de un script P2PKH es: OP_DUP (0x76) OP_HASH160 (0xA9) [20 bytes pubkeyhash] OP_EQUALVERIFY (0x88) OP_CHECKSIG (0xAC)
        // En hex: "76a9" + "20 bytes de pubkeyhash" + "88ac"
        const scriptHex = script.toHex();
        if (!scriptHex.startsWith('76a9') || !scriptHex.endsWith('88ac') || scriptHex.length !== 50) {
            console.warn(`[GNWallet] Script no es P2PKH estándar: ${scriptHex}`);
            return null;
        }

        // Extraer el pubkeyhash (los 20 bytes centrales)
        const pubKeyHashHex = scriptHex.substring(4, 44); // 4 para '76a9', 44 es '4 + 40 (20 bytes * 2)'
        const pubKeyHashBuffer = Buffer.from(pubKeyHashHex, 'hex');

        // Crear la dirección a partir del pubkeyhash y la red
        const versionByte = network === bsv.Networks.mainnet ? Buffer.from('00', 'hex') : Buffer.from('6f', 'hex');
        const addressBuffer = Buffer.concat([versionByte, pubKeyHashBuffer]);
        // 'bsv.Address.fromHex' espera un hex de 21 bytes (version + hash)
        return bsv.Address.fromHex(addressBuffer.toString('hex'));
    } catch (e) {
        console.error(`[GNWallet] Error extrayendo dirección del script: ${e}`);
        return null;
    }
}

private async splitChangeOutput(
        tx: bsv.Transaction,
        changeAddress: bsv.Address,
        currentUtxoCount: number
    ): Promise<bsv.Transaction> {
        const dustLimit = this.options.dustLimit;
        const target = this.options.targetUtxos;
        const needed = target - currentUtxoCount;

        console.log(`[GNWallet] ---- SPLIT DEBUG ----`);
        console.log(`[GNWallet] UTXOs actuales: ${currentUtxoCount}, target: ${target}, necesarios: ${needed}`);

        if (needed <= 1) {
            console.log(`[GNWallet] No se necesita split (needed=${needed})`);
            return tx;
        }

        // 1. Script hex esperado para nuestra dirección
        const myScriptHex = bsv.Script.buildPublicKeyHashOut(changeAddress).toHex();
        console.log(`[GNWallet] Script hex esperado: ${myScriptHex}`);

        let changeIndex = -1;
        let changeAmount = 0;

        for (let i = 0; i < tx.outputs.length; i++) {
            const output = tx.outputs[i];
            const outputScriptHex = output.script.toHex();
            console.log(`[GNWallet] Output ${i}: script=${outputScriptHex.substring(0, 20)}..., valor=${output.satoshis}`);

            // Estrategia 1: Comparación directa de scripts hex
            if (outputScriptHex === myScriptHex) {
                changeIndex = i;
                changeAmount = output.satoshis;
                console.log(`[GNWallet] Output de cambio encontrado por coincidencia de hex en índice ${i}`);
                break;
            }

            // Estrategia 2 (Respaldo): Extraer dirección del script y comparar
            const outputAddress = this.extractAddressFromScript(output.script, this.options.network);
            if (outputAddress && outputAddress.toString() === changeAddress.toString()) {
                changeIndex = i;
                changeAmount = output.satoshis;
                console.log(`[GNWallet] Output de cambio encontrado por dirección extraída en índice ${i}`);
                break;
            }
        }

        if (changeIndex === -1) {
            console.error(`[GNWallet] No se encontró output de cambio. Transacción no modificada.`);
            return tx;
        }

        if (changeAmount < dustLimit) {
            console.log(`[GNWallet] Cambio insuficiente (${changeAmount} < ${dustLimit})`);
            return tx;
        }

        const maxSplits = Math.floor(changeAmount / dustLimit);
        let splits = Math.min(needed, maxSplits);
        if (splits < 2) {
            console.log(`[GNWallet] No es posible dividir (splits=${splits})`);
            return tx;
        }

        // 2. Distribución equitativa del cambio
        const valuePerSplit = Math.floor(changeAmount / splits);
        let remaining = changeAmount;
        const newOutputs = tx.outputs.filter((_, idx) => idx !== changeIndex);

        for (let i = 0; i < splits; i++) {
            const isLast = i === splits - 1;
            const val = isLast ? remaining : valuePerSplit;
            if (val >= dustLimit) {
                newOutputs.push(new bsv.Transaction.Output({
                    satoshis: val,
                    script: bsv.Script.buildPublicKeyHashOut(changeAddress)
                }));
            }
            remaining -= val;
        }
        tx.outputs = newOutputs;

        // 3. Recalcular fee
        const oldFee = tx.getFee();
        const rawHex = tx.serialize();
        const txSizeBytes = rawHex.length / 2;
        const feePerKb = await this.provider!.getFeePerKb();
        const newFee = Math.ceil((txSizeBytes * feePerKb) / 1000);
        const feeDiff = newFee - oldFee;

        if (feeDiff > 0) {
            const lastIndex = tx.outputs.length - 1;
            const lastOutput = tx.outputs[lastIndex];
            if (lastOutput.satoshis - feeDiff >= dustLimit) {
                const adjustedOutput = new bsv.Transaction.Output({
                    satoshis: lastOutput.satoshis - feeDiff,
                    script: lastOutput.script
                });
                tx.outputs[lastIndex] = adjustedOutput;
                console.log(`[GNWallet] Fee ajustado: +${feeDiff} sats, nuevo fee total=${newFee}`);
            } else {
                console.warn(`[GNWallet] Fee extra (${feeDiff}) imposible de cubrir, abortando split.`);
                return tx;
            }
        }

        console.log(`[GNWallet] Split realizado: ${splits} UTXOs de ~${valuePerSplit} sats (cambio original ${changeAmount})`);
        console.log(`[GNWallet] ---- FIN SPLIT DEBUG ----`);
        return tx;
    }
}