/**
 * Calculates the total supply of a cryptocurrency based on the current block height and the initial supply.
 * @param initialSupply The initial supply of the cryptocurrency.
 * @param blocksPerEpoch The number of blocks in each epoch.
 * @param rewardPerEpoch The reward per epoch.
 * @param currentBlockHeight The current block height.
 * @returns The total supply of the cryptocurrency.
 */
function calculateTotalSupply(initialSupply: number, blocksPerEpoch: number, rewardPerEpoch: number, currentBlockHeight: number): number {
    const epochsPassed = Math.floor(currentBlockHeight / blocksPerEpoch);
    const totalReward = epochsPassed * rewardPerEpoch;
    return initialSupply + totalReward;
}

import *as crypto from  'crypto'; // reuse crypto library




class Transaction {
    constructor (
       public id: string,
       public amount: number,
       public timestamp: number, 
       public sender: string,
       public payee: string,
       public signature: Buffer,
       public hash: string

    ) {}
    tostring(): string {
        return JSON.stringify(this);
    }
}

class Block 
{
    public nonce =Math.round(Math.random() *888888888888888);
    constructor (
        public previousHash: string,
        public transactions: Transaction[],
        public timestamp =Date.now(),
        public hash: string,
        )
        {}
        get Hash(): string {
        const string = JSON.stringify(this);
        const hash = crypto.createHash('SHA256');
        return hash.update(string).digest('hex');
    }
    
}

class Chain 
{
public static instance = new Chain();
Chain:Block [] = [];
    constructor() {
        this.Chain = [new Block('', [], Date.now(), '')];
    }

 get lastBlock()
 { return this.Chain[this.Chain.length-1];}

    mine(nonce:number)
    { let solution=1;
        console.log("mining|\/|")
        while (true)    
        {const hash =crypto.createHash ("MD5");
        hash.update((nonce+solution).toString()).end();
        const attempt:string = hash.digest('hex');

        if (attempt.substring(0,4) ==='0000')
        {console.log('Solved: ${Solution}'); 
        return solution; }
        solution += 1;
         }
         
    }
    addBlock(id: string, amount: number, transaction: Transaction, timestamp: number, senderPublicKey: string, signature: Buffer,hash:string) {
        const verifier = crypto.createVerify('SHA256');
        verifier.update(transaction.tostring());

             (verifier.verify(senderPublicKey, signature)) 
            const transactions = [transaction];
            const newBlock = new Block( this.lastBlock.Hash, transactions, timestamp, hash );
            this.Chain.push(newBlock);

        const isvalid = verifier.verify(senderPublicKey, signature);

        if (isvalid) {
            const transactions = [transaction];
            const newBlock = new Block( this.lastBlock.Hash, transactions, timestamp, hash);
            this.mine(newBlock.nonce);
            this.Chain.push(newBlock);
        }
    }
    static addBlock(transaction: Transaction[], timestamp: number, sender: string, signature: Buffer, hash: string) {
        throw new Error('Method not implemented.');
        
    }
  
} 


class Wallet 
{
    public publickey: string = '';
    public privatekey: string= '';

    constructor() 
    {
        const keypair = crypto.generateKeyPairSync('rsa',
         {
            modulusLength: 2048,
            publicKeyEncoding: { type: 'spki', format: 'pem' },
            privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
        });

        this.privatekey = keypair.privateKey;
        this.publickey = keypair.publicKey!;
    }
   
    sendMoney(id: string, amount: number, timestamp: number, sender: string,  payeePublicKey: string,  signature: Buffer, hash:string) 
    {
        const transaction = new Transaction(id, amount, timestamp, sender, payeePublicKey,  signature, hash);
      
        const sign = crypto.createHash('SHA256');
        sign.update(transaction.toString()).end();
      
        const signatureHex = sign.digest('hex');
        Chain.instance.addBlock(id, amount, transaction, timestamp, payeePublicKey, signature,hash);
    }




}
   
const bob = new Wallet();
const PI = new Wallet();
const Sally = new Wallet();


console.log(Chain.instance)
