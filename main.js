import { CompactEncrypt } from 'jose/jwe/compact/encrypt'
import { createSecretKey } from 'crypto'

import { compactDecrypt } from 'jose/jwe/compact/decrypt'

const secret = await createSecretKey(Buffer.from('difn1$3h#ftefwta'))
console.log(secret)

const encoder = new TextEncoder()

const payload = {
  "CI":"eifnwifnwi",
  "PID":"eiwnfiwnfwiwnfi"
}


const jwe = await new CompactEncrypt(encoder.encode(JSON.stringify(payload)))
  .setProtectedHeader({ alg: 'A128KW', enc: 'A128CBC-HS256' })
  .encrypt(secret)

console.log('---- encrypted jwe token ----- ')
console.log(jwe)

// decrypt
try {
  const anotherSecret = await createSecretKey(Buffer.from('abcdabcdabcdabcd'))
  const { plaintext, protectedHeader }  = await compactDecrypt(jwe, secret)
  const decoder = new TextDecoder()

  console.log('---- decrypted jwe token ---- ')
  console.log(protectedHeader)
  console.log(decoder.decode(plaintext))
} catch (err) {
  console.log('error!')
}


