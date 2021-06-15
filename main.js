// ===================================================
// 아래의 코드는 "jose" 모듈 사용예제로서
// JWE 해독, JWE 검증
// 그리고 반대로 
// JWS 서명 후 JWE 암호화 과정을 설명하고 있다.
// 
// 본 코드는아래의 모듈을 바탕으로 작성되었다.
// jose by panva
// link - https://github.com/panva/jose
// ===================================================
import { CompactEncrypt } from 'jose/jwe/compact/encrypt'
import { compactDecrypt } from 'jose/jwe/compact/decrypt'
import { compactVerify } from 'jose/jws/compact/verify' 
import { CompactSign } from 'jose/jws/compact/sign'
import { parseJwk } from 'jose/jwk/parse'
import { createSecretKey } from 'crypto'




// ========== Decryption  ============
// decrypt jwe with jwk 
// ===================================
const decryptJwe = async (jwe, key) => {
  const { plaintext, protectedHeader }  = await compactDecrypt(jwe, key)
  return decoder.decode(plaintext)
}

// =========== Verification ================
// verify Jws with secretKey
// =========================================
const verifyJws = async (jws, secretKey) => {
  const { payload, protectedHeader } = await compactVerify(jws, secretKey)
  return decoder.decode(payload);
}


// ========== Signing ================
// sign JWS with JWK
// ====================================
const signJws = async (payload, secretKey) => {
  const encoder = new TextEncoder()
  const jws = await new CompactSign(encoder.encode('Test'))
    .setProtectedHeader({
      alg:'HS256',
    })
    .sign(secretKey)
  return jws
}

// ======== Encryption =================
// encrypt jws with jwk
// ====================================
const encryptJwe = async (jws, secretkey) => { 
  const encoder = new TextEncoder()

  const payload = {
    "CI":"eifnwifnwi",
    "PID":"eiwnfiwnfwiwnfi"
  }

  const jwe = await new CompactEncrypt(encoder.encode(JSON.stringify(payload)))
    .setProtectedHeader({ alg: 'dir', enc: 'A128CBC-HS256' })
    .encrypt(secretKey)

  return jwe; 
}

const showYourResult = (result) => {
  console.log("====== your token =====");
  console.log("<33333 ");
  console.log(result);
}

// ====================== 
// 여기부터시작... 젠장...
// ======================
const decoder = new TextDecoder()

const jwe =
  'eyJhbGciOiJkaXIiLCJlbmMiOiJBMTI4Q0JDLUhTMjU2In0..SwrNNLx3v-6GhiLj3kSYVg.HHrODCN0SvLgkiuXbkCK8Y5iKQ9t_BcVnErXwT4J6dsqJjW7HSjdtiARYN4ryr4DuO7iLdwOtMqle1bR5D-bne4toehPYUPiGDrMz2xqMTTH3Wv9Oc1TQP0BzK8bx712_9zbid0YrxtBoyA7wt7Vmuqp06rAQ-RLIjf7k_8souzw5vJRwbUKgw4SDcwYOrnO.b6oEiHTQxN_-kBm6rMZAQQ'

const secretKey = await parseJwk({
  'kty':'oct',
  // k는 base64로 인코딩 되어있어야 한다. 
  'k': Buffer.from('776086fe1dc445c2a7807cd26d497f3b').toString('base64')
}, 'dir')

decryptJwe(jwe, secretKey)  // 1.해독
  .then((jws) => {
    return verifyJws(jws, secretKey)  // 2.검증
  }).then((payload) => {
    let newPayload = JSON.parse(payload)
    newPayload.CI = "Modified by NodeJS"
    // 3. 사용
    return newPayload 
  }).then((newPayload) => {
    return signJws(newPayload, secretKey)  // 4. 서명
  }).then((newJws)=> {
    return encryptJwe(newJws, secretKey)  // 5. 암호
  }).then((newJwe) => {
    showYourResult(newJwe) 
  }).catch((e) => {
    console.log(e)
  })


