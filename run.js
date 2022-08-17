const crypto = require('node:crypto');
const fs = require('node:fs')
const path = require('node:path')

var pubKey = undefined;
var privKey = undefined;
const motto = "Don't complain make progress."
const cipher = 'aes-256-cbc'

function write(){
    const { publicKey, privateKey } = crypto.generateKeyPairSync("rsa", {
        modulusLength: 2048,
    });

    fs.writeFileSync(path.join(__dirname,'keys','pub.pem'),publicKey.export({type:'pkcs1',format:'pem'}),{flag:"w"})
    fs.writeFileSync(path.join(__dirname,'keys','priv.pem'),privateKey.export({type:'pkcs1',format:'pem',cipher: cipher,passphrase: motto}),{flag:"w"})

    pubKey = publicKey
    privKey = privateKey
}

function CheckIf_RSA_Exists(){
    return new Promise((resolve,reject)=>{
        try{
            if(fs.existsSync(path.join(__dirname,'keys','pub.pem')) && fs.existsSync(path.join(__dirname,'keys','priv.pem'))){
                let pubData = fs.readFileSync(path.join(__dirname,'keys','pub.pem')).toString().trim('\n').split('\n')
                let privData = fs.readFileSync(path.join(__dirname,'keys','priv.pem')).toString().trim('\n').split('\n')
        
                if(pubData.includes('BEGIN') && privData.includes('BEGIN')){
                    // LOAD
                    let pubData = fs.readFileSync(path.join(__dirname,'keys','pub.pem')).toString().trim('\n')
                    let privData = fs.readFileSync(path.join(__dirname,'keys','priv.pem')).toString().trim('\n')    
        
                    pubKey = crypto.createPublicKey(pubData)
                    privKey = crypto.createPrivateKey(privData)
                }
                else{
                    // WRITE
                    // RSA 2048 BITS
                    write()
                }
            }   
            else {
                // WRITE
                // RSA 2048 BITS
                write()
            }
            resolve(1)
        }
        catch(err){
            reject('Unknown Error, probably you have none "keys" directory next to this node script')
        }
    })
}

async function main(){
    try{
        let state = await CheckIf_RSA_Exists()
    
        if(state){
            console.log('RSA PUB/PRIV key is successfully loaded and or generated if your system had none')

            let data = 'Pix4 Z3NTL3'

            let encrypted = crypto.privateEncrypt({key: privKey,passphrase:motto,encoding: 'utf-8',padding:crypto.constants.RSA_PKCS1_PADDING},Buffer.from(data))
            console.log("Encrypted:\n" + Buffer.from(encrypted).toString())

            console.log()

            let decrypted = crypto.publicDecrypt({key: pubKey,padding:crypto.constants.RSA_PKCS1_PADDING, encoding: 'utf-8'},encrypted)
            console.log("Decrypted:\n" + decrypted.toString())
        }
    }
    catch(err){
        console.log(err)
    }
}
main()