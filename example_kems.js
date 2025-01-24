const oqs = require('./build/Release/oqs_node')

console.log("Provided KEMs: ", oqs.KEMs.getEnabledAlgorithms())


const kem = new oqs.KeyEncapsulation('ML-KEM-512')

const keypair = kem.generateKeypair()
console.log('Public key: ', keypair)

const secret_key = kem.exportSecretKey()
console.log('Secret key: ', secret_key)

const ciphertext = kem.encapsulateSecret(keypair)
console.log(ciphertext)
console.log('cipherText: ',ciphertext.ciphertext)
console.log('sharedSecret: ',ciphertext.sharedSecret)

const decapsulatedSecret = kem.decapsulateSecret(ciphertext.ciphertext)
console.log('Decapsulated secret: ', decapsulatedSecret)

