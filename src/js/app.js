/* global atob, Buffer, TextDecoder, BUILD_VERSION */

import 'bootstrap';
import CodeMirror from 'codemirror/lib/codemirror.js';
import $ from "jquery";
import jose from "node-jose";

require('codemirror/mode/javascript/javascript');
require('codemirror/addon/mode/simple');

const tenMinutes = 10 * 60;
const ITERATION_DEFAULT = 8192,
      ITERATION_MAX = 100001,
      ITERATION_MIN = 50;
const re = {
        signed : {
          jwt : new RegExp('^([^\\.]+)\\.([^\\.]+)\\.([^\\.]+)$'),
          cm : new RegExp('^([^\\.]+)(\\.)([^\\.]+)(\\.)([^\\.]+)$')
        },
        encrypted: {
          jwt : new RegExp('^([^\\.]+)\\.([^\\.]+)\\.([^\\.]+)\\.([^\\.]+)\\.([^\\.]+)$'),
          cm : new RegExp('^([^\\.]+)(\\.)([^\\.]+)(\\.)([^\\.]+)(\\.)([^\\.]+)(\\.)([^\\.]+)$')
        }
      };
const sampledata = {
        names : ['audrey', 'olaf', 'vinit', 'antonio', 'alma', 'ming', 'naimish', 'anna', 'sheniqua', 'tamara', 'kina', 'maxine' ],
        props : ['propX', 'propY', 'aaa', 'version', 'entitlement', 'alpha', 'classid'],
        types : ['number', 'string', 'object', 'array', 'boolean']
      };

function algPermutations(prefixes) {
  return prefixes.reduce( (a, v) =>
    [...a, ...[256,384,512].map(x=>v+x)], []);
}

const rsaSigningAlgs = algPermutations(['RS','PS']),
      ecdsaSigningAlgs = algPermutations(['ES']),
      hmacSigningAlgs = algPermutations(['HS']),
      signingAlgs = [...rsaSigningAlgs, ...ecdsaSigningAlgs, ...hmacSigningAlgs],
      rsaKeyEncryptionAlgs = ['RSA-OAEP','RSA-OAEP-256'],
      pbes2KeyEncryptionAlgs = [  "PBES2-HS256+A128KW", "PBES2-HS384+A192KW", "PBES2-HS512+A256KW" ],
      keyEncryptionAlgs = [...rsaKeyEncryptionAlgs, ...pbes2KeyEncryptionAlgs, '??'],
      contentEncryptionAlgs = [
        'A128CBC-HS256',
        'A256CBC-HS512',
        'A128GCM',
        'A256GCM'
      ];

let editors = {}; // codemirror editors

CodeMirror.defineSimpleMode("encodedjwt", {
  start : [
    {
      regex: re.signed.cm,
      sol: true,
      token: ["jwt-header", "", "jwt-payload", "", "jwt-signature"]
    },
    {
      regex: re.encrypted.cm,
      sol: true,
      token: ["jwt-header", "", "jwt-key", "", "jwt-iv", "", "jwt-payload", "", "jwt-authtag"]
    }
  ]
});

function reformIndents(s) {
  let s2 = s.split(new RegExp('\n', 'g'))
    .map(s => s.trim())
    .join("\n");
  return s2.trim();
}

function randomString(){
  return Math.random().toString(36).substring(2, 15) + Math.random().toString(36).substring(2, 15);
}

function randomNumber() {
  let min = (randomBoolean())? 10: 100,
      max = (randomBoolean())? 10000: 1000;
  return Math.floor(Math.random() * (max - min)) + min;
}

function randomBoolean() {
  return Math.floor(Math.random() * 2) == 1;
}

function randomArray() {
  let n = Math.floor(Math.random() * 4) + 1, // at least 1 element
      a = [], type;
  for(var i = 0; i < n; i++){
    type = selectRandomValueExcept(sampledata.types, ['array', 'object']);
    a[i] = generateRandomValue(type);
  }
  return a;
}

function randomObject(depth, exclusion) {
  let n = Math.floor(Math.random() * 4) + 1,
      obj = {}, propname, type;
  for(var i = 0; i < n; i++) {
    propname = selectRandomValueExcept(sampledata.props, exclusion);
    // limit complexity
    type = (depth >1) ?
      selectRandomValueExcept(sampledata.types, ['array', 'object']) :
      selectRandomValue(sampledata.types);
    obj[propname] = generateRandomValue(type, depth, propname);
  }
  return obj;
}

function generateRandomValue (type, depth, parentName) {
  type = type || selectRandomValue(sampledata.types);
  depth = (typeof depth == 'number')? depth + 1 : 1;
  switch(type) {
  case 'number' :
    return randomNumber();
  case 'string' :
    return randomString();
  case 'array' :
    return randomArray();
  case 'object' :
    return randomObject(depth, parentName);
  case 'boolean' :
    return randomBoolean();
  }
  return null;
}

function selectRandomValueExcept (a, exclusion) {
  let v = null;
  if ( ! exclusion) { exclusion = []; }
  if ( ! Array.isArray(exclusion)) {
    exclusion = [exclusion];
  }
  do {
    v = selectRandomValue (a);
  } while(exclusion.indexOf(v) >= 0);
  return v;
}

function selectRandomValue (a) {
  let L = a.length,
      n = Math.floor(Math.random() * L);
  return a[n];
}

function hmacToKeyBits(alg) {
  switch(alg) {
  case 'HS256' : return 256;
  case 'HS384' : return 384;
  case 'HS512' : return 512;
  }
  return 9999999;
}

function algToKeyBits(alg) {
  if (alg.startsWith('PBES2')) {
    let hmac = alg.substring(6, 11);
    return hmacToKeyBits(hmac);
  }
  return hmacToKeyBits(alg);
}

function getPbkdf2IterationCount() {
  let icountvalue = $('#ta_pbkdf2_iterations').val(),
      icount = ITERATION_DEFAULT;
  try {
    icount = Number.parseInt(icountvalue, 10);
  }
  catch (exc1) {
    setAlert("not a number? defaulting to iteration count: "+ icount);
  }
  if (icount > ITERATION_MAX || icount < ITERATION_MIN) {
    icount = ITERATION_DEFAULT;
    setAlert("iteration count out of range. defaulting to: "+ icount);
  }
  return icount;
}

function getPbkdf2SaltBuffer() {
  let keyvalue = $('#ta_pbkdf2_salt').val();
  let coding = $('.sel-symkey-pbkdf2-salt-coding').find(':selected').text().toLowerCase();
  let knownCodecs = ['utf-8', 'base64', 'hex'];

  if (knownCodecs.indexOf(coding)>=0) {
    return Buffer.from(keyvalue, coding);
  }
  throw new Error('unsupported salt encoding'); // will not happen
}

async function getSymmetricKeyBuffer(alg) {
  let keyvalue = $('#ta_symmetrickey').val();
  let coding = $('.sel-symkey-coding').find(':selected').text().toLowerCase();
  let knownCodecs = ['utf-8', 'base64', 'hex'];

  if (knownCodecs.indexOf(coding)>=0) {
    return Promise.resolve(Buffer.from(keyvalue, coding));
  }

  if (coding == 'pbkdf2') {
    let kdfParams = {
          salt: getPbkdf2SaltBuffer(),
          iterations: getPbkdf2IterationCount(),
          length: algToKeyBits(alg) / 8
        };
    return jose.JWA.derive("PBKDF2-SHA-256", Buffer.from(keyvalue, 'utf-8'), kdfParams);
  }

  throw new Error('unknown key encoding: ' + coding);  // will not happen
}

function getPrivateKey() {
  editors.privatekey.save();
  let keyvalue = $('#ta_privatekey').val();
  return keyvalue;
}

function getPublicKey() {
  editors.publickey.save();
  let keyvalue = $('#ta_publickey').val();
  return keyvalue;
}

function currentKid() {
  let s = (new Date()).toISOString(); // ex: 2019-09-04T21:29:23.428Z
  let re = new RegExp('[-:TZ\\.]', 'g');
  return s.replace(re, '');
}

function capitalize(string) {
    return string.charAt(0).toUpperCase() + string.slice(1);
}

function copyToClipboard(event) {
  let $elt = $(this),
      sourceElement = $elt.data('target'),
      // grab the element to copy
      $source = $('#' + sourceElement),
      // Create a temporary hidden textarea.
      $temp = $("<textarea>");

  if (editors[sourceElement]) {
    editors[sourceElement].save();
  }

  //let textToCopy = $source.val();
  // in which case do I need text() ?
  let textToCopy = ($source[0].tagName == 'TEXTAREA' || $source[0].tagName == 'INPUT') ? $source.val() : $source.text();

  $("body").append($temp);
  $temp.val(textToCopy).select();
  let success;
  try {
    success = document.execCommand("copy");
    if (success) {
      // Animation to indicate copy.
      // CodeMirror obscures the original textarea, and appends a div as the next sibling.
      // We want to flash THAT.
      let $cmdiv = $source.next();
      if ($cmdiv.prop('tagName').toLowerCase() == 'div' && $cmdiv.hasClass('CodeMirror')) {
        $cmdiv.addClass('copy-to-clipboard-flash-bg')
          .delay('1000')
          .queue( _ => $cmdiv.removeClass('copy-to-clipboard-flash-bg').dequeue() );
      }
      else {
        // no codemirror (probably the secretkey field, which is just an input)
        $source.addClass('copy-to-clipboard-flash-bg')
          .delay('1000')
          .queue( _ => $source.removeClass('copy-to-clipboard-flash-bg').dequeue() );
      }
    }
  }
  catch (e) {
    success = false;
  }
  $temp.remove();
  return success;
}

function getAcceptableSigningAlgs(key) {
  let keytype = key.kty;
  if (keytype == 'oct') return hmacSigningAlgs;
  if (keytype == 'RSA') return rsaSigningAlgs;
  if (keytype == 'EC') {
    if (key.length == 256)
      return ['ES256'];
    if (key.length == 384)
      return ['ES384'];
    if (key.length == 521)
      return ['ES512'];
  }
  return ["NONE"];
}

function isAppropriateAlg(alg, key) {
  return getAcceptableSigningAlgs(key).indexOf(alg)>=0;
}

function getAcceptableEncryptionAlgs(key) {
  let keytype = key.kty;
  if (keytype == 'RSA') return rsaKeyEncryptionAlgs;
  if (keytype == 'oct') return pbes2KeyEncryptionAlgs; // eventually extend this to dir, A128KW, etc
  return ["NONE"];
}

function pickSigningAlg(key) {
  return selectRandomValue(getAcceptableSigningAlgs(key));
}

function pickKeyEncryptionAlg(key) {
  return selectRandomValue(getAcceptableEncryptionAlgs(key));
}

function pickContentEncryptionAlg() {
  return selectRandomValue(contentEncryptionAlgs);
}

function isSymmetric(alg) {
  return alg.startsWith('HS');
}

function checkKeyLength(alg, keybuffer) {
  let length = keybuffer.byteLength;
  let requiredLength = algToKeyBits(alg) / 8;
  if (length >= requiredLength) return Promise.resolve(keybuffer);
  return Promise.reject(new Error('insufficient key length. You need at least ' + requiredLength + ' chars for ' + alg));
}

function encodeJwt(event) {
  let values = {}, parseError;
  ['header', 'payload'].forEach( segment => {
    let elementId = 'token-decoded-' + segment;
    if (editors[elementId]) {
      editors[elementId].save();
      let text = $('#' + elementId).val();
      try {
        values[segment] = JSON.parse(text);
      }
      catch(e) {
        parseError = segment;
      }
    }
  });
  if (parseError) {
    setAlert("cannot parse JSON ("+parseError+")", 'warning');
    return;
  }

  let {header, payload} = values;
  if (!header.typ) { header.typ = "JWT"; }

  // optionally set expiry in payload
  let desiredExpiryOverride = $('.sel-expiry').find(':selected').text().toLowerCase();
  if (desiredExpiryOverride == "no expiry") {
    delete payload.exp;
  }
  else {
    let matches = (new RegExp('^([1-9][0-9]*)mins$')).exec(desiredExpiryOverride);
    if (matches && matches.length == 2) {
      // forcibly set payload
      payload.exp = Math.floor((new Date()).valueOf() / 1000) +
        parseInt(matches[1], 10) * 60;
    }
  }

  let wantIssuedTime = $('#chk-iat').prop('checked');
  if (wantIssuedTime) {
    payload.iat = Math.floor((new Date()).valueOf() / 1000);
  }

  let p = null;
  if (header.enc && header.alg) {
    // create encrypted JWT
    if (pbes2KeyEncryptionAlgs.indexOf(header.alg) >= 0) {
      // overwrite the header values with values from the inputs
      header.p2c = getPbkdf2IterationCount();
      header.p2s = getPbkdf2SaltBuffer().toString('base64');

      let keyBuffer = Buffer.from($('#ta_symmetrickey').val(), 'utf-8');
      p = jose.JWK.asKey({ kty:'oct', k: keyBuffer, use: 'enc' });

    }
    else {
      p = jose.JWK.asKey(getPublicKey(), "pem");
    }

    p = p
      .then( encryptingKey => {
        let encryptOptions = {alg: header.alg, fields: header, format: 'compact'},
            // createEncrypt will automatically inject the kid, unless I pass reference:false
            cipher = jose.JWE.createEncrypt(encryptOptions, [{key:encryptingKey, reference:false}]);
        cipher.update(JSON.stringify(payload), "utf8");
        return cipher.final();
      });
  }
  else {
    // create signed JWT
    if (isSymmetric(header.alg)) {
      p = getSymmetricKeyBuffer(header.alg)
        .then( keyBuffer => checkKeyLength(header.alg, keyBuffer))
        .then( keyBuffer => jose.JWK.asKey({ kty:'oct', k: keyBuffer, use: "sig" }));
    }
    else {
      p = jose.JWK.asKey(getPrivateKey(), "pem");
    }
    p = p
    .then( signingKey => {
      if (!header.alg) { header.alg = pickSigningAlg(signingKey); }
      if ( ! isAppropriateAlg(header.alg, signingKey)) {
        throw new Error('the alg specified in the header is not compatible with the key');
      }
      let signOptions = {
            alg: header.alg,
            fields: header,
            format: 'compact'
          };
      // use reference:false to omit the kid from the header
      let signer = jose.JWS.createSign(signOptions, [{key:signingKey, reference:false}]);
      signer.update(JSON.stringify(payload), "utf8");
      return signer.final();
    });
  }

  return p
    .then( jwt => {
      //editors.encodedjwt.setValue(jwt);
      $('#panel_encoded > p > span.length').text('(' + jwt.length + ' bytes)');
      editors.encodedjwt.setValue(jwt);
      editors.encodedjwt.save();
      if ( header.enc ) {
        // re-format the decoded JSON, incl added or modified properties like kid, alg
        showDecoded();
        setAlert("encrypted JWT", 'info');
      }
      else {
        showDecoded();
        setAlert("signed JWT", 'info');
      }
    })
    .then(() => {
      $('#privatekey .CodeMirror-code').removeClass('outdated');
      $('#publickey .CodeMirror-code').removeClass('outdated');
    })
    .catch( e => {
      console.log(e.stack);
      setAlert(e);
    });
}

function decodeJwt(event) {
  showDecoded();
}

function checkValidityReasons(pHeader, pPayload, acceptableAlgorithms) {
  let now = Math.floor((new Date()).valueOf() / 1000),
      gracePeriod = 0,
      wantCheckIat = true,
      reasons = [];

  // 4. algorithm ('alg' in header) check
  if (pHeader.alg === undefined) {
    reasons.push('the header lacks the required alg property');
  }

  if (acceptableAlgorithms.indexOf(pHeader.alg) < 0) {
    reasons.push('the algorithm is not acceptable');
  }

  // 8.1 expired time 'exp' check
  if (pPayload.exp !== undefined && typeof pPayload.exp == "number") {
    if (pPayload.exp + gracePeriod < now) {
      reasons.push('the token is expired');
    }
  }

  // 8.2 not before time 'nbf' check
  if (pPayload.nbf !== undefined && typeof pPayload.nbf == "number") {
    if (now < pPayload.nbf - gracePeriod) {
      reasons.push('the not-before time is in the future');
    }
  }

  // 8.3 issued at time 'iat' check
  if (wantCheckIat) {
    if (pPayload.iat !== undefined && typeof pPayload.iat == "number") {
      if (now < pPayload.iat - gracePeriod) {
        reasons.push('the issued-at time is in the future');
      }
    }
  }
  return reasons;
}


function verifyJwt(event) {
  editors.encodedjwt.save();
  editors.publickey.save();
  let tokenString = editors.encodedjwt.getValue(),
      matches = re.signed.jwt.exec(tokenString);
  // verify a signed JWT
  if (matches && matches.length == 4) {
    $("#mainalert").addClass('fade').removeClass('show');
    let json = atob(matches[1]);  // base64-decode
    let header = JSON.parse(json);
    let p = null;

    if (isSymmetric(header.alg)) {
      p = getSymmetricKeyBuffer(header.alg)
        .then( keyBuffer => checkKeyLength(header.alg, keyBuffer))
        .then( keyBuffer => jose.JWK.asKey({kty:'oct', k: keyBuffer, use:'sig'}));
    }
    else {
      p = jose.JWK.asKey(getPublicKey(), "pem");
    }

    return p
      .then( key =>
             jose.JWS.createVerify(key)
             .verify(tokenString)
             .then( result => {
               // {result} is a Object with:
               // *  header: the combined 'protected' and 'unprotected' header members
               // *  payload: Buffer of the signed content
               // *  signature: Buffer of the verified signature
               // *  key: The key used to verify the signature

               let parsedPayload = JSON.parse(result.payload),
                   reasons = checkValidityReasons(result.header, parsedPayload, getAcceptableSigningAlgs(key));
               if (reasons.length == 0) {
                 let message = 'The JWT signature has been verified and the times are valid. Algorithm: ' + result.header.alg;
                 showDecoded();
                 setAlert(message, 'success');
                 selectAlgorithm(result.header.alg);
               }
               else {
                 let label = (reasons.length == 1)? 'Reason' : 'Reasons';
                 setAlert('The JWT is not valid. ' + label+': ' + reasons.join(', and ') + '.', 'warning');
               }
             })
             .catch( e => {
               setAlert('Verification failed. Bad key?');
               console.log('During verify: ' + e);
               console.log(e.stack);
             }));
  }

  // verification/decrypt of encrypted JWT
  matches = re.encrypted.jwt.exec(tokenString);
  if (matches && matches.length == 6) {
    let p = null;
    let json = atob(matches[1]);  // base64-decode
    let header = JSON.parse(json);

    if (pbes2KeyEncryptionAlgs.indexOf(header.alg) >= 0) {
      let password = $('#ta_symmetrickey').val();
      let keyBuffer = Buffer.from(password, 'utf-8');
      p = jose.JWK.asKey({ kty:'oct', k: keyBuffer, use: 'enc' });
    }
    else {
      p = jose.JWK.asKey(getPrivateKey(), "pem");
    }

    return p
      .then( decryptionKey =>
             jose.JWE.createDecrypt(decryptionKey)
             .decrypt(tokenString)
             .then( result => {
               // {result} is a Object with:
               // *  header: the combined 'protected' and 'unprotected' header members
               // *  protected: an array of the member names from the "protected" member
               // *  key: Key used to decrypt
               // *  payload: Buffer of the decrypted content
               // *  plaintext: Buffer of the decrypted content (alternate)
               let td = new TextDecoder('utf-8'),
                   stringPayload = td.decode(result.payload),
                   parsedPayload = JSON.parse(stringPayload),
                   prettyPrintedJson = JSON.stringify(parsedPayload,null,2),
                   reasons = checkValidityReasons(result.header, parsedPayload, getAcceptableEncryptionAlgs(decryptionKey)),
                   elementId = 'token-decoded-payload',
                   flavor = 'payload';
               editors[elementId].setValue(prettyPrintedJson);
               $('#' + flavor + ' > p > .length').text('( ' + stringPayload.length + ' bytes)');
               if (reasons.length == 0) {
                 let message = "The JWT has been decrypted successfully, and the times are valid.";
                 setAlert(message, 'success');
               }
               else {
                 let label = (reasons.length == 1)? 'Reason' : 'Reasons';
                 setAlert('The JWT is not valid. ' + label+': ' + reasons.join(', and ') + '.', 'warning');
               }
               return {};
             }))
      .catch( e => {
        setAlert('Decryption failed. Bad key?');
        console.log('During decryption: ' + e);
        console.log(e.stack);
      });
  }
}


function setAlert(html, alertClass) {
  let buttonHtml = '<button type="button" class="close" data-dismiss="alert" aria-label="Close">\n' +
    ' <span aria-hidden="true">&times;</span>\n' +
    '</button>',
      $mainalert = $("#mainalert");
  $mainalert.html(html + buttonHtml);
  if (alertClass) {
    $mainalert.removeClass('alert-warning'); // this is the default
    $mainalert.addClass('alert-' + alertClass); // success, primary, warning, etc
  }
  else {
    $mainalert.addClass('alert-warning');
  }
  // show()
  $mainalert.removeClass('fade').addClass('show');
  setTimeout(() => $("#mainalert").addClass('fade').removeClass('show'), 5650);
}

function closeAlert(event){
  //$("#mainalert").toggle();
  $('#mainalert').removeClass('show').addClass('fade');
  return false; // Keep close.bs.alert event from removing from DOM
}

function updateKeyValue(flavor /* public || private */, keyvalue) {
  let editor = editors[flavor+'key'];
  if (editor) {
    editor.setValue(keyvalue);
    editor.save();
  }
}

function key2pem(flavor, keydata) {
  let body = window.btoa(String.fromCharCode(...new Uint8Array(keydata)));
  body = body.match(/.{1,64}/g).join('\n');
  return `-----BEGIN ${flavor} KEY-----\n${body}\n-----END ${flavor} KEY-----`;
}

function getGenKeyParams(alg) {
  if (alg.startsWith('RS') || alg.startsWith('PS')) return {
    name: "RSASSA-PKCS1-v1_5", // this name also works for RSA-PSS !
    modulusLength: 2048, //can be 1024, 2048, or 4096
    publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
    hash: {name: "SHA-256"}
  };
  if (alg == 'ES256') return {
    name: "ECDSA",
    namedCurve: 'P-256'
  };
  if (alg == 'ES384') return {
    name: "ECDSA",
    namedCurve: 'P-384'
  };
  if (alg == 'ES512') return {
    name: "ECDSA",
    namedCurve: 'P-521'
  };
  throw new Error('invalid key flavor');
}

function newKeyPair(event) {
  let alg = $('.sel-alg').find(':selected').text();
  if (alg.startsWith('HS')) {
    setAlert("can't do that for HS algorithms");
  }
  else {
    //flavor = (alg.startsWith('ES')) ? 'EC' : 'RSA',
    let keyUse = ["sign", "verify"],
      isExtractable = true,
      genKeyParams = getGenKeyParams(alg);
  return window.crypto.subtle.generateKey(genKeyParams, isExtractable, keyUse)
    .then(key => window.crypto.subtle.exportKey( "spki", key.publicKey )
          .then(keydata => updateKeyValue('public', key2pem('PUBLIC', keydata)) )
          .then( () => window.crypto.subtle.exportKey( "pkcs8", key.privateKey ))
          .then(keydata => updateKeyValue('private', key2pem('PRIVATE', keydata)) ))
    .then( () => {
      $('#mainalert').removeClass('show').addClass('fade');
      $('#privatekey .CodeMirror-code').removeClass('outdated');
      $('#publickey .CodeMirror-code').removeClass('outdated');
    });
  }
}

function selectAlgorithm(algName) {
  let currentlySelectedAlg = $('.sel-alg').find(':selected').text().toLowerCase();
  if (algName.toLowerCase() != currentlySelectedAlg) {
    let $option = $('.sel-alg option[value="'+ algName +'"]');
    if ( ! $option.length) {
      $option = $('.sel-alg option[value="??"]');
    }
    $option
      .prop('selected', true)
      .trigger("change");
  }
}

function showDecoded() {
  editors.encodedjwt.save();
  let tokenString = editors.encodedjwt.getValue(), //$('#encodedjwt').val(),
      matches = re.signed.jwt.exec(tokenString);
  if (matches && matches.length == 4) {
    setAlert("looks like a signed JWT", 'info');
    let currentlySelectedVariant = $('.sel-variant').find(':selected').text().toLowerCase();
    if (currentlySelectedVariant != "signed") {
      $('.sel-variant option[value=Signed]')
        .prop('selected', true)
        .trigger("change");
    }

    let flavors = ['header','payload']; // cannot decode signature
    matches.slice(1,-1).forEach(function(item,index) {
      let json = atob(item),  // base64-decode
          flavor = flavors[index],
          elementId = 'token-decoded-' + flavor;
      try {
        let obj = JSON.parse(json), // may throw
            prettyPrintedJson = JSON.stringify(obj,null,2),
            flatJson = JSON.stringify(obj);
        editors[elementId].setValue(prettyPrintedJson);
        $('#' + flavor + ' > p > .length').text('(' + flatJson.length + ' bytes)');
        if (flavor == 'header' && obj.alg) {
          selectAlgorithm(obj.alg);
        }
      }
      catch (e) {
        // probably not json
        setAlert("the "+ flavor +" may not be valid JSON", 'info');
        editors[elementId].setValue(json);
      }
    });
    return;
  }

  matches = re.encrypted.jwt.exec(tokenString);
  if (matches && matches.length == 6) {
    // can decode the header. Need to decrypt to 'decode' the payload.
    setAlert("an encrypted JWT", 'info');
    let currentlySelectedVariant = $('.sel-variant').find(':selected').text().toLowerCase();
    if (currentlySelectedVariant != "encrypted") {
      $('.sel-variant option[value=Encrypted]')
        .prop('selected', true)
        .trigger("change");
    }
    // header
    let item = matches[1],
        json = atob(item),  // base64-decode
        elementId = 'token-decoded-header',
        flavor = 'header';
    try {
      let obj = JSON.parse(json),
          prettyPrintedJson = JSON.stringify(obj,null,2),
          flatJson = JSON.stringify(obj);
      editors[elementId].setValue(prettyPrintedJson);
      $('#' + flavor + ' > p > .length').text('(' + flatJson.length + ' bytes)');
      // must decrypt the ciphertext payload to display claims
      elementId = 'token-decoded-payload';
      flavor = 'payload';
      editors[elementId].setValue('?ciphertext?');
      $('#' + flavor + ' > p > .length').text('( ' + matches[2].length + ' bytes)');
      if (obj.alg) {
        selectAlgorithm(obj.alg);
      }
    }
    catch (e) {
      // probably not json
      setAlert("the "+ flavor +" may not be valid JSON", 'info');
      //editors[elementId].setValue(json);
    }

    // do not attempt decrypt here
    return;
  }

  setAlert("That does not appear to be a JWT");
}

function populateAlgorithmSelectOptions() {
  let variant = $('.sel-variant').find(':selected').text().toLowerCase();
  $('.sel-alg').find('option').remove();
  let a = (variant == 'signed') ? signingAlgs : keyEncryptionAlgs;
  $.each(a, (val, text) =>
         $('.sel-alg').append( $('<option></option>').val(text).html(text) ));
  // store currently selected alg:
  //$( '.sel-alg').data("prev", $( '.sel-alg').find(':selected').text());
  $( '.sel-alg').data("prev", 'NONE');
  // $('.sel-alg').trigger('change'); // not sure why this does not work

  //onChangeAlg.call(document.getElementsByClassName('sel-alg')[0], null);
  onChangeAlg.call(document.querySelector('.sel-alg'), null);
}

function keysAreCompatible(alg1, alg2) {
  let prefix1 = alg1.substring(0, 2),
      prefix2 = alg2.substring(0, 2);
  if (['RS', 'PS'].indexOf(prefix1)>=0 &&
      ['RS', 'PS'].indexOf(prefix2)>=0 ) return true;
  if (prefix1 == 'ES') return alg1 == alg2;
  return false;
}


function changeSymmetricKeyCoding(event) {
  let $this = $(this),
      newSelection = $this.find(':selected').text().toLowerCase(),
      previousSelection = $this.data('prev');
  if (newSelection != previousSelection) {
    if (newSelection == 'pbkdf2') {
      // display the salt and iteration count
      $('#pbkdf2_params').show();
    }
    else {
      $('#pbkdf2_params').hide();
    }
  }
  $this.data('prev', newSelection);
}

function checkSymmetryChange(newalg, oldalg) {
  let newPrefix = newalg.substring(0, 2),
      oldPrefix = oldalg && oldalg.substring(0, 2);
  if (newPrefix == 'HS' || newPrefix == 'PB') {
    $('.btn-newkeypair').hide();
    if (oldPrefix != 'HS' & oldPrefix != 'PB') {
      $('#privatekey').hide();
      $('#publickey').hide();
      $('#symmetrickey').show();

      if (newPrefix == 'PB') {
        //$('.sel-symkey-coding').disable(); // always PBKDF2!
        let currentlySelectedCoding = $('.sel-symkey-coding').find(':selected').text().toLowerCase();
        if (currentlySelectedCoding != "pbkdf2") {
          $('.sel-symkey-coding option[value=PBKDF2]')
            .prop('selected', true)
            .trigger("change");
        }
        $('.sel-symkey-coding').prop("disabled", true);
      }
      else {
        // $('.sel-symkey-coding').enable();
        $('.sel-symkey-coding').prop("disabled", false);
      }
      return true;
    }
  }
  else {
    $('.btn-newkeypair').show();
    if (newPrefix == 'RS' || newPrefix == 'PS' || newPrefix == 'ES') {
      $('#privatekey').show();
      $('#publickey').show();
      $('#symmetrickey').hide();
      return true;
    }
  }
}

function initialized() {
  return !!editors['token-decoded-header'];
}

function onChangeAlg(event) {
  let $this = $(this),
      newSelection = $this.find(':selected').text(),
      previousSelection = $this.data('prev'),
      headerObj = null;

  if ( ! initialized()) { return ; }

  if (newSelection != previousSelection) {

    checkSymmetryChange(newSelection, previousSelection);

    // apply newly selected alg to the displayed header
    editors['token-decoded-header'].save();
    let headerText = $('#token-decoded-header').val();
    try {
      headerObj = JSON.parse(headerText);
      headerObj.alg = newSelection;
      editors['token-decoded-header'].setValue(JSON.stringify(headerObj, null, 2));
    }
    catch(e) {
      /* gulp */
    }

    if ( ! keysAreCompatible(newSelection, previousSelection)) {
      $('#privatekey .CodeMirror-code').addClass('outdated');
      $('#publickey .CodeMirror-code').addClass('outdated');
    }
    $this.data('prev', newSelection);
  }
  if (newSelection.startsWith('PB')) {
    if (headerObj){
      $('#ta_pbkdf2_iterations').val(headerObj.p2c);
      $('#ta_pbkdf2_salt').val(headerObj.p2s);
      // always base64
      $('.sel-symkey-pbkdf2-salt-coding option[value="Base64"]')
        .prop('selected', true)
        .trigger("change");
      // user can change these but it probably won't work
    }
  }
  else {
    // nop
  }
}

function onChangeVariant(event) {
  // change signed to encrypted or vice versa
  let $this = $(this),
      newSelection = $this.find(':selected').text().toLowerCase(),
      previousSelection = $this.data('prev'),
      priorAlgSelection = $('.sel-alg').data('prev');

  editors['token-decoded-header'].save();
  let headerText = $('#token-decoded-header').val();
  if (newSelection != previousSelection) {
    try {
      let headerObj = JSON.parse(headerText);
      if (newSelection == 'encrypted') {
        // swap in alg and enc
        headerObj.alg = pickKeyEncryptionAlg({kty:'RSA'}); // not always !
        headerObj.enc = pickContentEncryptionAlg();
        $('#privatekey').show();
        $('#publickey').show();
        $('#symmetrickey').hide();
      }
      else {
        // select an appropriate alg and remove enc
        headerObj.alg = pickSigningAlg({kty:'RSA'});
        // these fields can never be used with signed JWT
        delete headerObj.enc;
        delete headerObj.p2s;
        delete headerObj.p2c;
        // populateAlgorithmSelectOptions() - called below - will trigger the
        // onChangeAlg fn which will do the right thing for symmetry change, etc.
      }
      editors['token-decoded-header'].setValue(JSON.stringify(headerObj, null, 2));
    }
    catch(e) {
      /* gulp */
    }
    $this.data('prev', newSelection);
  }
  populateAlgorithmSelectOptions();

  // This used to be appropriate logic, but since adding PBES2, at
  // least the comment is no longer accurate.  In any case things seem to be working.

  // There are two possibilities:
  // 1. change from signed to encrypted, in which case we always need RSA keys.
  // 2. change from encrypted to signed, in which case RS256 gets selected and again we need RSA keys.
  // So just check if the prior alg was RSA.
  if ( !priorAlgSelection.startsWith('PS') && !priorAlgSelection.startsWith('RS')) {
    $('#privatekey .CodeMirror-code').addClass('outdated');
    $('#publickey .CodeMirror-code').addClass('outdated');
  }
}

function contriveJwt(event) {
    let now = Math.floor((new Date()).valueOf() / 1000),
        sub = selectRandomValue(sampledata.names),
        aud = selectRandomValueExcept(sampledata.names, sub),
        payload = {
          iss:"DinoChiesa.github.io",
          sub,
          aud,
          iat: now,
          exp: now + tenMinutes // always
        },
        header = { alg : $('.sel-alg').find(':selected').text() };

  if (randomBoolean()) {
    let propname = selectRandomValue(sampledata.props);
    payload[propname] = generateRandomValue(null, null, propname);
  }
  editors['token-decoded-header'].setValue(JSON.stringify(header));
  editors['token-decoded-payload'].setValue(JSON.stringify(payload));
  encodeJwt(event);
}

function decoratePayloadLine(instance, handle, lineElement) {
  let lastComma = new RegExp(',\s*$');
  $(lineElement).find('span.cm-property').each( (ix, element) => {
    let $this = $(element), text = $this.text();
    if (['"exp"', '"iat"', '"nbf"'].indexOf(text) >= 0) {
      let $valueSpan = $this.nextAll('span').first(),
          text = $valueSpan.text().replace(lastComma, ''),
          time = new Date(Number(text) * 1000),
          stringRep = time.toISOString();
      $valueSpan.attr('title', stringRep);
    }
  });
}

// function decorateEncodedToken(instance, handle, lineElement) {
//   $(lineElement).find('span.cm-jwt-header').each( (ix, element) => {
//     let $this = $(element);
//     $this.hover(
//       () => {
//         $this.after($('<div>encoded JWT header</div>'));
//       },
//       () => {
//         $this.next('div').remove();
//       }
//     );
//   });
//  $(lineElement).find('span.cm-jwt-payload').each( (ix, element) => {
//     let $this = $(element);
//     $this.hover(
//       () => {
//         $this.after($('<div>encoded JWT payload</div>'));
//       },
//       () => {
//         $this.next('div').remove();
//       }
//     );
//   });
//  $(lineElement).find('span.cm-jwt-signature').each( (ix, element) => {
//     let $this = $(element);
//     $this.hover(
//       () => {
//         $this.after($('<div>encoded JWT signature</div>'));
//       },
//       () => {
//         $this.next('div').remove();
//       }
//     );
//   });
// }

function looksLikeJwt(possibleJwt) {
  if ( ! possibleJwt) return false;
  if (possibleJwt == '') return false;
  let matches = re.signed.jwt.exec(possibleJwt);
  if (matches && matches.length == 4) { return true; }
  matches = re.encrypted.jwt.exec(possibleJwt);
  if (matches && matches.length == 6) { return true; }
  return false;
}

$(document).ready(function() {
  $( '#version_id').text(BUILD_VERSION);
  $( '.btn-copy' ).on('click', copyToClipboard);
  $( '.btn-encode' ).on('click', encodeJwt);
  $( '.btn-decode' ).on('click', decodeJwt);
  $( '.btn-verify' ).on('click', verifyJwt);
  $( '.btn-newkeypair' ).on('click', newKeyPair);

  $( '.btn-regen' ).on('click', contriveJwt);
  $( '.sel-variant').on('change', onChangeVariant);
  $( '.sel-alg').on('change', onChangeAlg);

  populateAlgorithmSelectOptions();

  $( '.sel-symkey-coding').on('change', changeSymmetricKeyCoding);

  $('#mainalert').addClass('fade');
  $('#mainalert').on('close.bs.alert', closeAlert);

  // editor for the encoded JWT (left hand column)
  editors.encodedjwt = CodeMirror.fromTextArea(document.getElementById('encodedjwt'), {
    mode: 'encodedjwt',
    lineWrapping: true
  });
  editors.encodedjwt.on('inputRead', function(cm, event) {
    /* event -> object{
       origin: string, can be '+input', '+move' or 'paste'
       doc for origins >> http://codemirror.net/doc/manual.html#selection_origin
       from: object {line, ch},
       to: object {line, ch},
       removed: array of removed strings
       text: array of pasted strings
       } */
    if (event.origin == 'paste') {
      setTimeout(decodeJwt, 220);
    }
  });
  //editors.encodedjwt.on('renderLine', decorateEncodedToken);

  // create editors for the public and private keys
  ['private', 'public'].forEach( flavor => {
    let keytype = flavor+'key', // private || public
        elementId = 'ta_'+ keytype;
    editors[keytype] = CodeMirror.fromTextArea(document.getElementById(elementId), {
      mode: 'encodedjwt', // not really
      lineWrapping: true
    });
    editors[keytype].on('inputRead', function(cm, event) {
      if (event.origin == 'paste') {
        setTimeout(function() {
          editors[keytype].save();
          let keyvalue = $('#ta_' + keytype).val();
          updateKeyValue(flavor, reformIndents(keyvalue));
        }, 220);
      }
    });

  });

  // create CM editors for decoded (JSON) payload and header
  ['header', 'payload'].forEach( portion => {
    let elementId = 'token-decoded-' + portion;
    editors[elementId] = CodeMirror.fromTextArea(document.getElementById(elementId), {
      mode: {
        name: 'javascript',
        json: true,
        indentWithTabs: false,
        statementIndent : 2,
        indentUnit : 2,
        tabSize: 2
      }
    });
  });

  // to label fields in the decoded payload. We don't do the same in the header.
  editors['token-decoded-payload'].on('renderLine', decoratePayloadLine);
  $('#symmetrickey').hide();
  $('#pbkdf2_params').hide();

  // handle inbound query or hash
  let inboundJwt = window.location.hash,
      hash = {},
      fnStartsWith = function(s, searchString, position) {
        position = position || 0;
        return s.lastIndexOf(searchString, position) === position;
      };

  if ( ! inboundJwt || inboundJwt === '') {
    inboundJwt = window.location.search.replace('?', '');
  }

  if (looksLikeJwt(inboundJwt)) {
    newKeyPair()
      .then( _ => {
        editors.encodedjwt.setValue(inboundJwt);
        editors.encodedjwt.save();
        showDecoded();
        $('#privatekey .CodeMirror-code').addClass('outdated');
        $('#publickey .CodeMirror-code').addClass('outdated');
      });
  }
  else {
    newKeyPair()
      .then( _ => contriveJwt() );
  }

});
