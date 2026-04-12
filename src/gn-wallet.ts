// src/gn-wallet.ts (v1.0.11)
import { UTXO, Signer, Provider, AddressOption, SignTransactionOptions, SignatureRequest, SignatureResponse, DEFAULT_SIGHASH_TYPE } from 'scrypt-ts';
import * as bsv from '@scrypt-inc/bsv';
import { GNWalletOptions } from './interfaces';
import { signTx } from 'scryptlib/dist';

export class GNWallet extends Signer {
    private privateKeys: Map<string, bsv.PrivateKey> = new Map();
    private address!: bsv.Address;
    private pubKey!: bsv.PublicKey;
    private options: Required<GNWalletOptions>;

    /**
     * Getter para mantener compatibilidad. 
     * Devuelve siempre la primera llave cargada (la identidad principal).
     */
    get privateKey(): bsv.PrivateKey {
        return this.privateKeys.values().next().value as bsv.PrivateKey;
    }

    constructor(privateKeys: (bsv.PrivateKey | string)[] | bsv.PrivateKey | string, provider?: Provider, options?: GNWalletOptions) {
        super(provider);

        const keysArray = Array.isArray(privateKeys) ? privateKeys : [privateKeys];
        
        if (keysArray.length === 0) {
            throw new Error("Se requiere al menos una llave privada para inicializar GNWallet");
        }

        keysArray.forEach(pk => this.addPrivateKey(pk));

        // Establecer identidad principal
        const firstKey = this.privateKey;
        this.pubKey = firstKey.toPublicKey();
        this.address = firstKey.toAddress();

        this.options = {
            network: options?.network ?? bsv.Networks.mainnet,
            cacheTTL: options?.cacheTTL ?? 30000,
            targetUtxos: options?.targetUtxos ?? 50,
            dustLimit: options?.dustLimit ?? 546,
        };
    }

    public addPrivateKey(privateKey: bsv.PrivateKey | string): void {
        const key = typeof privateKey === 'string' 
            ? bsv.PrivateKey.fromString(privateKey) 
            : privateKey;
        
        this.privateKeys.set(key.toAddress().toString(), key);
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
        if (address) {
            const addrStr = address.toString();
            const key = this.privateKeys.get(addrStr);
            if (key) return key.toPublicKey();
            // IMPORTANTE: Si no tenemos la llave, lanzamos error. 
            // Si devolvemos 'this.pubKey' por defecto, scrypt-ts cree que 
            // esta billetera es dueña de esa dirección con la llave equivocada.
            throw new Error(`GNWallet no posee la llave para la dirección: ${addrStr}`);
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
        const tx = new bsv.Transaction(rawTxHex);
        const responses: SignatureResponse[] = [];

        for (const req of sigRequests) {
            // Determinar las direcciones a firmar
            let addresses: bsv.Address[] = [];
            if (req.address) {
                addresses = Array.isArray(req.address) ? req.address : [req.address];
            } else {
                // Si no hay dirección, usar todas las claves (poco común, pero por compatibilidad)
                addresses = Array.from(this.privateKeys.keys()).map(addrStr => new bsv.Address(addrStr));
            }

            for (const addr of addresses) {
                const privKey = this.privateKeys.get(addr.toString());
                if (!privKey) {
                    console.warn(`[GNWallet] No se encontró clave para ${addr}`);
                    continue;
                }
                if (!req.scriptHex || !req.satoshis) {
                    throw new Error(`Datos insuficientes para input ${req.inputIndex}`);
                }

                // 1. Reconstruir el locking script
                const script = bsv.Script.fromHex(req.scriptHex);
                // 2. Inyectar el output en el input (¡fundamental!)
                if (tx.inputs[req.inputIndex]) {
                    tx.inputs[req.inputIndex].output = new bsv.Transaction.Output({
                        script: script,
                        satoshis: req.satoshis
                    });
                }
                // 3. Manejar OP_CODESEPARATOR si existe
                const subScript = req.csIdx !== undefined ? script.subScript(req.csIdx) : script;
                const sighashType = req.sigHashType ?? DEFAULT_SIGHASH_TYPE;
                // 4. Firmar con signTx (la misma función que TestWallet)
                const signature = signTx(
                    tx,
                    privKey,
                    subScript,
                    req.satoshis,
                    req.inputIndex,
                    sighashType
                );
                responses.push({
                    inputIndex: req.inputIndex,
                    sig: signature,
                    publicKey: privKey.toPublicKey().toString(),
                    sigHashType: sighashType,
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
        // Firmamos con la llave por defecto todos los inputs P2PKH reconocidos
        for (let i = 0; i < tx.inputs.length; i++) {
            try {
                tx.sign(this.privateKey);
            } catch (e) {
                console.warn(`No se pudo firmar input ${i} con la llave por defecto:`, e);
            }
        }
        return tx;
    }

    async signMessage(message: string, address?: AddressOption): Promise<string> {
        let key = this.privateKey;
        if (address) {
            const requestedKey = this.privateKeys.get(address.toString());
            if (requestedKey) key = requestedKey;
        }
        return bsv.Message.sign(message, key).toString();
    }

    async getBalance(address?: AddressOption): Promise<{ confirmed: number; unconfirmed: number }> {
        if (!this.provider) throw new Error("Provider no conectado");
        const addr = address ? address : this.address;
        return this.provider.getBalance(addr);
    }

    /*async _signAndSendTransaction(tx: bsv.Transaction): Promise<string> {
        if (!this.provider) throw new Error("Provider no conectado");
        const changeAddress = this.address;
        const currentUtxos = await this.provider.listUnspent(changeAddress);
        const currentCount = currentUtxos.length;
        const txWithSplit = await this.splitChangeOutput(tx, changeAddress, currentCount);
        const signedTx = await this.signTransaction(txWithSplit);
        const txid = await this.provider.sendTransaction(signedTx);
        return txid;
    }*/
   async _signAndSendTransaction(tx: bsv.Transaction): Promise<string> {
        if (!this.provider) throw new Error("Provider no conectado");
        const changeAddress = this.address;
        const feePerKb = await this.provider.getFeePerKb();
        const dustLimit = this.options.dustLimit;

        // 1. Obtener UTXOs disponibles
        const allUtxos = await this.provider.listUnspent(changeAddress);
        const currentUtxoCount = allUtxos.length;

        // 2. Calcular déficit de fee inicial
        const currentSize = tx.serialize().length / 2;
        let requiredFee = Math.ceil((currentSize * feePerKb) / 1000);
        let currentFee = tx.getFee();
        let feeDeficit = requiredFee - currentFee;

        // 3. Selección quirúrgica si falta balance para el fee
        if (feeDeficit > 0) {
            const neededValue = feeDeficit + dustLimit;
            const selected = await this.selectUtxosForFee(allUtxos, neededValue, feePerKb);
            
            for (const utxo of selected) {
                tx.from(utxo); // Añade inputs sin borrar los previos (contratos)
            }

            // IMPORTANTE: Asegurar que existe un output de cambio para los fondos añadidos
            tx.change(changeAddress);

            // Recalcular tras añadir inputs y output de cambio
            const newSize = tx.serialize().length / 2;
            requiredFee = Math.ceil((newSize * feePerKb) / 1000);
            
            const totalInputValue = tx.inputs.reduce((sum, input) => sum + (input.output?.satoshis || 0), 0);
            const totalOutputValue = tx.outputs.reduce((sum, out) => sum + out.satoshis, 0);
            currentFee = totalInputValue - totalOutputValue;
            feeDeficit = requiredFee - currentFee;

            // Ajuste fino: si falta un remanente pequeño, se resta del cambio
            if (feeDeficit > 0) {
                let changeIndex = -1;
                for (let i = 0; i < tx.outputs.length; i++) {
                    const out = tx.outputs[i];
                    try {
                        const addr = out.script.toAddress(this.options.network);
                        if (addr.toString() === changeAddress.toString()) {
                            changeIndex = i;
                            break;
                        }
                    } catch (e) {
                        // Script no es P2PKH, ignorar
                    }
                }
                if (changeIndex === -1) {
                    throw new Error("No hay output de cambio para ajustar el fee");
                }
                const changeOutput = tx.outputs[changeIndex];
                const newValue = changeOutput.satoshis - feeDeficit;
                if (newValue >= dustLimit) {
                    // Reemplazar el output por uno nuevo con el valor ajustado
                    tx.outputs[changeIndex] = new bsv.Transaction.Output({
                        satoshis: newValue,
                        script: changeOutput.script
                    });
                } else {
                    throw new Error("Saldo insuficiente para cubrir el fee tras el ajuste");
                }
            }
        }

        // 4. Aplicar split para mantener la billetera líquida
        const txWithSplit = await this.splitChangeOutput(tx, changeAddress, currentUtxoCount);

        // 5. Firmar y enviar
        const signedTx = await this.signTransaction(txWithSplit);
        const txid = await this.provider.sendTransaction(signedTx);
        return txid;
    }

    private async selectUtxosForFee(utxos: UTXO[], neededValue: number, feePerKb: number): Promise<UTXO[]> {
        // Ordenamos de mayor a menor para usar la menor cantidad de inputs posible
        const sorted = [...utxos].sort((a, b) => b.satoshis - a.satoshis);
        const selected: UTXO[] = [];
        let collected = 0;

        for (const utxo of sorted) {
            selected.push(utxo);
            collected += utxo.satoshis;
            
            // Estimación: cada input P2PKH añade ~148 bytes
            const estimatedFee = Math.ceil((selected.length * 148 * feePerKb) / 1000);
            if (collected >= neededValue + estimatedFee) break;
        }

        if (collected < neededValue) {
            throw new Error(`Fondos insuficientes para cubrir el fee. Falta: ${neededValue - collected} sats`);
        }
        return selected;
    }

    private extractAddressFromScript(script: bsv.Script, network: bsv.Networks.Network): bsv.Address | null {
        try {
            const scriptHex = script.toHex();
            if (!scriptHex.startsWith('76a9') || !scriptHex.endsWith('88ac') || scriptHex.length !== 50) {
                return null;
            }
            const pubKeyHashHex = scriptHex.substring(4, 44);
            const pubKeyHashBuffer = Buffer.from(pubKeyHashHex, 'hex');
            const versionByte = network === bsv.Networks.mainnet ? Buffer.from('00', 'hex') : Buffer.from('6f', 'hex');
            const addressBuffer = Buffer.concat([versionByte, pubKeyHashBuffer]);
            return bsv.Address.fromHex(addressBuffer.toString('hex'));
        } catch (e) {
            return null;
        }
    }

    private async splitChangeOutput(tx: bsv.Transaction, changeAddress: bsv.Address, currentUtxoCount: number): Promise<bsv.Transaction> {
        const dustLimit = this.options.dustLimit;
        const target = this.options.targetUtxos;
        const needed = target - currentUtxoCount;

        if (needed <= 1) return tx;

        const myScriptHex = bsv.Script.buildPublicKeyHashOut(changeAddress).toHex();
        let changeIndex = -1;
        let changeAmount = 0;

        for (let i = 0; i < tx.outputs.length; i++) {
            const output = tx.outputs[i];
            if (output.script.toHex() === myScriptHex) {
                changeIndex = i;
                changeAmount = output.satoshis;
                break;
            }
            const outputAddress = this.extractAddressFromScript(output.script, this.options.network);
            if (outputAddress && outputAddress.toString() === changeAddress.toString()) {
                changeIndex = i;
                changeAmount = output.satoshis;
                break;
            }
        }

        if (changeIndex === -1 || changeAmount < dustLimit) return tx;

        const maxSplits = Math.floor(changeAmount / dustLimit);
        let splits = Math.min(needed, maxSplits);
        if (splits < 2) return tx;

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
                tx.outputs[lastIndex] = new bsv.Transaction.Output({
                    satoshis: lastOutput.satoshis - feeDiff,
                    script: lastOutput.script
                });
            } else {
                return tx;
            }
        }
        return tx;
    }
}