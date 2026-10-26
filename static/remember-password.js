// Keep the password encrypted; the browser stores a non-exportable AES key separately.
const rememberStorageKey='cpa_codex_remembered_password_v1';
async function rememberDatabase(){return new Promise((resolve,reject)=>{const request=indexedDB.open('cpa_codex_login',1);request.onupgradeneeded=()=>request.result.createObjectStore('keys');request.onsuccess=()=>resolve(request.result);request.onerror=()=>reject(request.error);});}
async function passwordKey(create=false){
  const db=await rememberDatabase();
  try{
    let key=await new Promise((resolve,reject)=>{const request=db.transaction('keys').objectStore('keys').get('password');request.onsuccess=()=>resolve(request.result);request.onerror=()=>reject(request.error);});
    if(!key&&create){key=await crypto.subtle.generateKey({name:'AES-GCM',length:256},false,['encrypt','decrypt']);await new Promise((resolve,reject)=>{const transaction=db.transaction('keys','readwrite');transaction.objectStore('keys').put(key,'password');transaction.oncomplete=resolve;transaction.onerror=()=>reject(transaction.error);});}
    return key;
  }finally{db.close();}
}
async function loadRememberedPassword(){
  if(!window.crypto?.subtle)return null;
  const saved=localStorage.getItem(rememberStorageKey);if(!saved)return null;
  const key=await passwordKey();if(!key)return null;
  const payload=JSON.parse(saved),bytes=Uint8Array.from(atob(payload.data),character=>character.charCodeAt(0));
  const plaintext=await crypto.subtle.decrypt({name:'AES-GCM',iv:new Uint8Array(payload.iv)},key,bytes);
  return new TextDecoder().decode(plaintext);
}
async function saveRememberedPassword(value){
  if(!window.crypto?.subtle)throw new Error('当前连接不支持安全保存密码，请通过 HTTPS 或 localhost 访问');
  const key=await passwordKey(true),iv=crypto.getRandomValues(new Uint8Array(12));
  const ciphertext=await crypto.subtle.encrypt({name:'AES-GCM',iv},key,new TextEncoder().encode(value));
  const data=btoa(Array.from(new Uint8Array(ciphertext),byte=>String.fromCharCode(byte)).join(''));
  localStorage.setItem(rememberStorageKey,JSON.stringify({iv:Array.from(iv),data}));
}
function forgetRememberedPassword(){localStorage.removeItem(rememberStorageKey);}
