/* global atob, Buffer, TextDecoder */

import 'bootstrap';
import CodeMirror from 'codemirror/lib/codemirror.js';
import $ from "jquery";
import jose from "node-jose";

/* this is horrendous */

require('codemirror/mode/javascript/javascript');
require('codemirror/addon/mode/simple');

const tenMinutes = 10 * 60;
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

const rsaSigningAlgs = ['RS','PS'].reduce( (a, v) =>
    [...a, ...[256,384,512].map(x=>v+x)], []);

const ecdsaSigningAlgs = ['ES'].reduce( (a, v) =>
    [...a, ...[256,384,512].map(x=>v+x)], []);

const hmacSigningAlgs = ['HS'].reduce( (a, v) =>
    [...a, ...[256,384,512].map(x=>v+x)], []);

const signingAlgs = [...rsaSigningAlgs, ...ecdsaSigningAlgs, ...hmacSigningAlgs];

const rsaKeyEncryptionAlgs = ['RSA-OAEP','RSA-OAEP-256'];

const contentEncryptionAlgs = [
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

function algToKeyBits(alg) {
  return (alg == 'HS256') ? 256 :
    (alg == 'HS384') ? 384 :
    (alg == 'HS512') ? 512 : 999999;
}

function getPbkdf2IterationCount() {
  let icountvalue = $('#ta_pbkdf2_iterations').val(),
      icount = 8192;
  try {
    icount = Number.parseInt(icountvalue, 10);
  }
  catch (exc1) {
    setAlert("defaulting to iteration count: "+ icount);
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
  let s = (new Date()).toISOString(); // 2019-09-04T21:29:23.428Z
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

  let textToCopy = ($source[0].tagName == 'TEXTAREA') ? $source.val() : $source.text();

  $("body").append($temp);
  $temp.val(textToCopy).select();
  let success;
  try {
    success = document.execCommand("copy");
    if (success) {
      // Animation to indicate copy.
      // CodeMirror obscures the original textarea, and appends a div as next sibling.
      // We want to flash THAT.
      let $cmdiv = $source.next();
      if ($cmdiv.prop('tagName').toLowerCase() == 'div' && $cmdiv.hasClass('CodeMirror')) {
        $cmdiv.addClass('copy-to-clipboard-flash-bg')
          .delay('1000')
          .queue( _ => $cmdiv.removeClass('copy-to-clipboard-flash-bg').dequeue() );
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

  var p = null;
  if (header.enc && header.alg) {
    p = jose.JWK.asKey(getPublicKey(), "pem")
      .then( encryptingKey => {
        let encryptOptions = {alg: header.alg, fields: header, format: 'compact'},
            // createEncrypt will automatically inject the kid, unless I pass reference:false
            cipher = jose.JWE.createEncrypt(encryptOptions, [{key:encryptingKey, reference:false}]);
        cipher.update(JSON.stringify(payload), "utf8");
        return cipher.final();
      });
  }
  else {
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
      editors.encodedjwt.setValue(jwt);
      $('#panel_encoded > p > span.length').text('(' + jwt.length + ' bytes)');
      editors.encodedjwt.setValue(jwt);
      editors.encodedjwt.save();
      if ( header.enc ) {
        // re-format the decoded JSON, incl added or modified properties like kid, alg
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
             .then(function(result) {
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
              // programmatically select the alg
              $('.sel-alg option[value='+ result.header.alg +']').prop('selected', true);
            }
            else {
              let label = (reasons.length == 1)? 'Reason' : 'Reasons';
              setAlert('The JWT is not valid. ' + label+': ' + reasons.join(', and ') + '.', 'warning');
            }
          })
          .catch (e => {
            setAlert('Verification failed. Bad key?');
            console.log('During verify: ' + e);
            console.log(e.stack);
          }));
  }

  // verification/decrypt of encrypted JWT
  matches = re.encrypted.jwt.exec(tokenString);
  if (matches && matches.length == 6) {

    return jose.JWK.asKey(getPrivateKey(), "pem")
      .then( privateKey =>
             jose.JWE.createDecrypt(privateKey)
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
                   reasons = checkValidityReasons(result.header, parsedPayload, getAcceptableEncryptionAlgs(privateKey)),
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
    name: "RSASSA-PKCS1-v1_5",
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

function showDecoded() {
  editors.encodedjwt.save();
  let tokenString = editors.encodedjwt.getValue(), //$('#encodedjwt').val(),
      matches = re.signed.jwt.exec(tokenString);
  if (matches && matches.length == 4) {
    setAlert("a signed JWT", 'info');
    //$('#mainalert').hide();
    //$('#mainalert').removeClass('show').addClass('fade');
    let flavors = ['header','payload']; // cannot decode signature
    matches.slice(1,-1).forEach(function(item,index) {
      let json = atob(item),  // base64-decode
          obj = JSON.parse(json),
          flavor = flavors[index],
          prettyPrintedJson = JSON.stringify(obj,null,2),
          flatJson = JSON.stringify(obj),
          elementId = 'token-decoded-' + flavor;
      editors[elementId].setValue(prettyPrintedJson);
      $('#' + flavor + ' > p > .length').text('(' + flatJson.length + ' bytes)');
    });
    return;
  }
  matches = re.encrypted.jwt.exec(tokenString);
  if (matches && matches.length == 6) {
    setAlert("an encrypted JWT", 'info');
    //$('#mainalert').removeClass('show').addClass('fade');
    // header
    let item = matches[1],
        json = atob(item),  // base64-decode
        obj = JSON.parse(json),
        flavor = 'header',
        prettyPrintedJson = JSON.stringify(obj,null,2),
        flatJson = JSON.stringify(obj),
        elementId = 'token-decoded-header';
      editors[elementId].setValue(prettyPrintedJson);
    $('#' + flavor + ' > p > .length').text('(' + flatJson.length + ' bytes)');
    // must decrypt the ciphertext payload to display claims
    elementId = 'token-decoded-payload';
    flavor = 'payload';
    editors[elementId].setValue('?ciphertext?');
    $('#' + flavor + ' > p > .length').text('( ' + matches[2].length + ' bytes)');
    // do not attempt decrypt here
    return;
  }
  setAlert("That does not appear to be a signed JWT");
}

function populateAlgorithmSelectOptions() {
  let variant = $('.sel-variant').find(':selected').text().toLowerCase();
  $('.sel-alg').find('option') .remove();
  let a = (variant == 'signed') ? signingAlgs : rsaKeyEncryptionAlgs;
  $.each(a, (val, text) =>
         $('.sel-alg').append( $('<option></option>').val(text).html(text) ));
  // store currently selected alg:
  $( '.sel-alg').data("prev", $( '.sel-alg').find(':selected').text());
}

function keysAreCompatible(alg1, alg2) {
  let prefix1 = alg1.substring(0, 2),
      prefix2 = alg2.substring(0, 2);
  if (['RS', 'PS'].indexOf(prefix1)>=0 &&
      ['RS', 'PS'].indexOf(prefix2)>=0 ) return true;
  if (prefix1 == 'ES') return alg1 == alg2;
  return false;
}

function checkSymmetryChange(newalg, oldalg) {
  let prefix1 = newalg.substring(0, 2),
      prefix2 = oldalg.substring(0, 2);
  if (prefix1 == 'HS' && prefix2 != 'HS') {
    $('#privatekey').hide();
    $('#publickey').hide();
    $('#symmetrickey').show();
    $('.sel-symkey-coding option[value=PBKDF2]')
      .prop('selected', true)
      .trigger("change");
    return true;
  }
  if (prefix2 == 'HS' && prefix1 != 'HS') {
    $('#privatekey').show();
    $('#publickey').show();
    $('#symmetrickey').hide();
    return true;
  }
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

function changeAlg(event) {
  let $this = $(this),
      newSelection = $this.find(':selected').text(),
      previousSelection = $this.data('prev');
  editors['token-decoded-header'].save();
  let headerText = $('#token-decoded-header').val();
  try {
    let headerObj = JSON.parse(headerText);
    headerObj.alg = newSelection;
    editors['token-decoded-header'].setValue(JSON.stringify(headerObj, null, 2));
  }
  catch(e) {
    /* gulp */
  }

  if (newSelection != previousSelection) {
    if (newSelection.startsWith('HS')) {
      $('.btn-newkeypair').hide();
    }
    else {
      $('.btn-newkeypair').show();
    }
  }

  checkSymmetryChange(newSelection, previousSelection);

  if ( ! keysAreCompatible(newSelection, previousSelection)) {
    $('#privatekey .CodeMirror-code').addClass('outdated');
    $('#publickey .CodeMirror-code').addClass('outdated');
  }
  $this.data('prev', newSelection);
}

function changeVariant(event) {
  let selection = this.value.toLowerCase(),
      priorAlgSelection = $('.sel-alg').data('prev');

  editors['token-decoded-header'].save();
  let text = $('#token-decoded-header').val();
  try {
    let headerObj = JSON.parse(text);
    if (selection == 'encrypted') {
      // swap in alg and enc
      headerObj.alg = pickKeyEncryptionAlg({kty:'RSA'});
      headerObj.enc = pickContentEncryptionAlg();
      $('#privatekey').show();
      $('#publickey').show();
      $('#symmetrickey').hide();
    }
    else {
      // select an appropriate alg and remove enc
      headerObj.alg = pickSigningAlg({kty:'RSA'});
      delete headerObj.enc;
    }
    editors['token-decoded-header'].setValue(JSON.stringify(headerObj, null, 2));
  }
  catch(e) {
    /* gulp */
  }
  populateAlgorithmSelectOptions();

  ///xxx

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

$(document).ready(function() {
  $( '.btn-copy' ).on('click', copyToClipboard);
  $( '.btn-encode' ).on('click', encodeJwt);
  $( '.btn-decode' ).on('click', decodeJwt);
  $( '.btn-verify' ).on('click', verifyJwt);
  $( '.btn-newkeypair' ).on('click', newKeyPair);

  $( '.btn-regen' ).on('click', contriveJwt);
  $( '.sel-variant').on('change', changeVariant);
  $( '.sel-alg').on('change', changeAlg);

  populateAlgorithmSelectOptions();

  $( '.sel-symkey-coding').on('change', changeSymmetricKeyCoding);

  $('#mainalert').addClass('fade');
  $('#mainalert').on('close.bs.alert', closeAlert);

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

  ['private', 'public'].forEach( flavor => {
    let keytype = flavor+'key', // private || public
        elementId = 'ta_'+ keytype;
    editors[keytype] = CodeMirror.fromTextArea(document.getElementById(elementId), {
      mode: 'encodedjwt',
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

  editors['token-decoded-payload'].on('renderLine', decoratePayloadLine);

  $('#symmetrickey').hide();

  // let $ta = $('#symmetrickey > textarea');
  // $ta.data('val', '');
  // $ta.on("change keyup paste", function() {
  //   var currentVal = $ta.val();
  //   var priorVal = $ta.data('val');
  //   // suppress multiple triggers
  //   if(currentVal == priorVal) {
  //       return;
  //   }
  //
  //   $ta.data('val', currentVal);
  //   $('#symmetrickey > p > .length').text('(' + currentVal.length + ' characters)');
  // });
  $('#pbkdf2_params').hide();

  newKeyPair()
    .then( _ => contriveJwt() );

});
