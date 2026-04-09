// src/gn-wallet.ts (v1.0.11)
import { Signer, Provider, AddressOption, SignTransactionOptions, SignatureRequest, SignatureResponse, DEFAULT_SIGHASH_TYPE } from 'scrypt-ts';
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

    /*async getPubKey(address?: AddressOption): Promise<bsv.PublicKey> {
        if (address) {
            const addrStr = address.toString();
            const key = this.privateKeys.get(addrStr);
            if (key) return key.toPublicKey();
            throw new Error(`GNWallet no posee la llave para la dirección: ${addrStr}`);
        }
        return this.pubKey;
    }*/
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

    /*async getSignatures(rawTxHex: string, sigRequests: SignatureRequest[]): Promise<SignatureResponse[]> {
        const tx = new bsv.Transaction(rawTxHex);
        const responses: SignatureResponse[] = [];

        for (const req of sigRequests) {
            try {
                // Determinar qué dirección debe firmar
                const addressesToTry = req.address 
                    ? (Array.isArray(req.address) ? req.address : [req.address]) 
                    : [this.address];

                let signingKey: bsv.PrivateKey | undefined;
                for (const addr of addressesToTry) {
                    signingKey = this.privateKeys.get(addr.toString());
                    if (signingKey) break;
                }

                if (!signingKey) {
                    throw new Error(`No se encontró llave privada para firmar el input ${req.inputIndex}`);
                }

                const script = req.scriptHex 
                    ? bsv.Script.fromHex(req.scriptHex) 
                    : bsv.Script.buildPublicKeyHashOut(signingKey.toAddress());
                
                const subScript = req.csIdx !== undefined ? script.subScript(req.csIdx) : script;
                const sighashType = req.sigHashType ?? DEFAULT_SIGHASH_TYPE;
                
                const hash = bsv.Transaction.Sighash.sighash(
                    tx,
                    sighashType,
                    req.inputIndex,
                    subScript,
                    new bsv.crypto.BN(req.satoshis)
                );

                const sigObj = bsv.crypto.ECDSA.sign(hash, signingKey);
                const sigHex = sigObj.toString();
                const sighashByte = (sighashType & 0xff).toString(16).padStart(2, '0');
                const fullSig = sigHex + sighashByte;

                responses.push({
                    inputIndex: req.inputIndex,
                    sig: fullSig,
                    publicKey: signingKey.toPublicKey().toString(),
                    sigHashType: sighashType,
                    csIdx: req.csIdx,
                });

            } catch (e) {
                console.error(`[GNWallet] Error firmando input ${req.inputIndex}:`, e);
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
    }*/
   /*async getSignatures(rawTxHex: string, sigRequests: SignatureRequest[]): Promise<SignatureResponse[]> {
        const tx = new bsv.Transaction(rawTxHex);
        const responses: SignatureResponse[] = [];

        for (const req of sigRequests) {
            try {
                // 1. Buscamos si tenemos la llave para alguna de las direcciones solicitadas
                const addressesToTry = req.address 
                    ? (Array.isArray(req.address) ? req.address : [req.address]) 
                    : [this.address];

                let signingKey: bsv.PrivateKey | undefined;
                for (const addr of addressesToTry) {
                    signingKey = this.privateKeys.get(addr.toString());
                    if (signingKey) break;
                }

                // --- CAMBIO CRUCIAL ---
                // Si no tenemos la llave, NO agregamos nada al array de respuestas.
                if (!signingKey) {
                    continue; 
                }

                const script = req.scriptHex 
                    ? bsv.Script.fromHex(req.scriptHex) 
                    : bsv.Script.buildPublicKeyHashOut(signingKey.toAddress());
                
                const subScript = req.csIdx !== undefined ? script.subScript(req.csIdx) : script;
                const sighashType = req.sigHashType ?? DEFAULT_SIGHASH_TYPE;
                
                const hash = bsv.Transaction.Sighash.sighash(
                    tx,
                    sighashType,
                    req.inputIndex,
                    subScript,
                    new bsv.crypto.BN(req.satoshis)
                );

                const sigObj = bsv.crypto.ECDSA.sign(hash, signingKey);
                const sigHex = sigObj.toString();
                const sighashByte = (sighashType & 0xff).toString(16).padStart(2, '0');
                const fullSig = sigHex + sighashByte;

                responses.push({
                    inputIndex: req.inputIndex,
                    sig: fullSig,
                    publicKey: signingKey.toPublicKey().toString(), // Siempre será válida aquí
                    sigHashType: sighashType,
                    csIdx: req.csIdx,
                });

            } catch (e) {
                // Si hay un error real en el proceso de firma, logueamos pero no 
                // enviamos una respuesta rota que haga crashear la ejecución.
                console.error(`[GNWallet] Error procesando firma para input ${req.inputIndex}:`, e);
            }
        }
        return responses;
    }*/
   /*async getSignatures(rawTxHex: string, sigRequests: SignatureRequest[]): Promise<SignatureResponse[]> {
        const tx = new bsv.Transaction(rawTxHex);
        const responses: SignatureResponse[] = [];

        for (const req of sigRequests) {
            try {
                // 1. Identificar qué llaves vamos a probar para este requerimiento
                let keysToTry: bsv.PrivateKey[] = [];

                if (req.address) {
                    // Si el request pide una dirección específica (o varias)
                    const addresses = Array.isArray(req.address) ? req.address : [req.address];
                    for (const addr of addresses) {
                        const key = this.privateKeys.get(addr.toString());
                        if (key) keysToTry.push(key);
                    }
                } else {
                    // Si el request NO especifica dirección (común en contratos complejos),
                    // probamos con TODAS las llaves que tenemos en el Map.
                    keysToTry = Array.from(this.privateKeys.values());
                }

                // 2. Firmar con cada llave válida encontrada
                for (const signingKey of keysToTry) {
                    const script = req.scriptHex 
                        ? bsv.Script.fromHex(req.scriptHex) 
                        : bsv.Script.buildPublicKeyHashOut(signingKey.toAddress());
                    
                    const subScript = req.csIdx !== undefined ? script.subScript(req.csIdx) : script;
                    const sighashType = req.sigHashType ?? DEFAULT_SIGHASH_TYPE;
                    
                    const hash = bsv.Transaction.Sighash.sighash(
                        tx,
                        sighashType,
                        req.inputIndex,
                        subScript,
                        new bsv.crypto.BN(req.satoshis)
                    );

                    const sigObj = bsv.crypto.ECDSA.sign(hash, signingKey);
                    const sigHex = sigObj.toString();
                    const sighashByte = (sighashType & 0xff).toString(16).padStart(2, '0');
                    const fullSig = sigHex + sighashByte;

                    responses.push({
                        inputIndex: req.inputIndex,
                        sig: fullSig,
                        publicKey: signingKey.toPublicKey().toString(),
                        sigHashType: sighashType,
                        csIdx: req.csIdx,
                    });
                }
            } catch (e) {
                console.error(`[GNWallet] Error procesando firmas para input ${req.inputIndex}:`, e);
            }
        }
        return responses;
    }*/

    /*async getSignatures(rawTxHex: string, sigRequests: SignatureRequest[]): Promise<SignatureResponse[]> {
        const tx = new bsv.Transaction(rawTxHex);
        const responses: SignatureResponse[] = [];

        // Obtenemos todas las llaves que tiene la billetera
        const allPrivateKeys = Array.from(this.privateKeys.values());
        console.log(`[DEBUG] GNWallet posee ${allPrivateKeys.length} llaves.`);
        allPrivateKeys.forEach((k, i) => {
            console.log(`[DEBUG] Llave ${i} -> Public Key: ${k.toPublicKey().toString()}`);
        });
        console.log(`[DEBUG] El contrato está pidiendo específicamente: 02166c5a6c7f6146821c18c39bfe80ed1541c5317ace48d5892f9ba680a130e154`);

        for (const req of sigRequests) {
            // Para cada requerimiento de firma del contrato...
            for (const privKey of allPrivateKeys) {
                try {
                    const pubKeyHex = privKey.toPublicKey().toString();
                    
                    // Generamos la firma técnica
                    const script = req.scriptHex 
                        ? bsv.Script.fromHex(req.scriptHex) 
                        : bsv.Script.buildPublicKeyHashOut(privKey.toAddress());
                    
                    const subScript = req.csIdx !== undefined ? script.subScript(req.csIdx) : script;
                    const sighashType = req.sigHashType ?? DEFAULT_SIGHASH_TYPE;
                    
                    const hash = bsv.Transaction.Sighash.sighash(
                        tx, sighashType, req.inputIndex, subScript, new bsv.crypto.BN(req.satoshis)
                    );

                    const sigObj = bsv.crypto.ECDSA.sign(hash, privKey);
                    const fullSig = sigObj.toString() + (sighashType & 0xff).toString(16).padStart(2, '0');

                    // ENVIAMOS LA FIRMA
                    // scrypt-ts usará el campo 'publicKey' para saber si esta firma le sirve
                    responses.push({
                        inputIndex: req.inputIndex,
                        sig: fullSig,
                        publicKey: pubKeyHex, // <--- Este es el ID que hace el match
                        sigHashType: sighashType,
                        csIdx: req.csIdx,
                    });
                } catch (e) {
                    // Si una llave no puede firmar este input, simplemente la saltamos
                    continue;
                }
            }
        }
        return responses;
    }*/

    async getSignatures(rawTxHex: string, sigRequests: SignatureRequest[]): Promise<SignatureResponse[]> {
        const tx = new bsv.Transaction(rawTxHex);
        const responses: SignatureResponse[] = [];
        const allPrivateKeys = Array.from(this.privateKeys.values());

        for (const req of sigRequests) {
            // Validar que tengamos los datos necesarios
            if (!req.scriptHex || !req.satoshis) {
                console.error(`[GNWallet] Faltan scriptHex o satoshis para input ${req.inputIndex}`);
                continue;
            }

            for (const privKey of allPrivateKeys) {
                try {
                    // Reconstruir el locking script (usar el proporcionado, no construir P2PKH)
                    const script = bsv.Script.fromHex(req.scriptHex);
                    // Manejar OP_CODESEPARATOR
                    const subScript = req.csIdx !== undefined ? script.subScript(req.csIdx) : script;
                    const sighashType = req.sigHashType ?? DEFAULT_SIGHASH_TYPE;

                    // ✅ Usar signTx (la misma que TestWallet)
                    const sig = signTx(
                        tx,
                        privKey,
                        subScript,
                        req.satoshis,
                        req.inputIndex,
                        sighashType
                    );

                    responses.push({
                        inputIndex: req.inputIndex,
                        sig: sig,                 // signTx ya devuelve DER + sighash byte
                        publicKey: privKey.toPublicKey().toString(),
                        sigHashType: sighashType,
                        csIdx: req.csIdx,
                    });
                } catch (e) {
                    // Si esta clave no puede firmar, continuar
                    continue;
                }
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