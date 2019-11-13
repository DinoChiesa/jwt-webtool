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

function isAppropriateAlg(alg, key) {
  let keytype = key.kty;
  if (keytype == 'RSA') return rsaSigningAlgs.indexOf(alg)>=0;
  if (keytype == 'EC') {
    if (key.length == 256)
      return alg =='ES256';
    if (key.length == 384)
      return alg =='ES384';
    if (key.length == 521)
      return alg =='ES512';
  }
}

function getAcceptableSigningAlgs(key) {
  let keytype = key.kty;
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

function getAcceptableEncryptionAlgs(key) {
  let keytype = key.kty;
  if (keytype == 'RSA') return ['RSA-OAEP-256'];
  return ["NONE"];
}

function selectAppropriateAlg(key) {
  return selectRandomValue(getAcceptableSigningAlgs(key));
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
  // TODO: make this dependent upon UI switch, not inferred from the header contents
  if (header.enc && header.alg == 'RSA-OAEP-256') {
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
    p = jose.JWK.asKey(getPrivateKey(), "pem")
    .then( signingKey => {
      if (!header.alg) { header.alg = selectAppropriateAlg(signingKey); }
      if ( ! isAppropriateAlg(header.alg, signingKey)) {
        // forcibly overwrite the alg
        header.alg = selectAppropriateAlg(signingKey);
      }
      let signOptions = {alg: header.alg, fields: header, format: 'compact'},
          // createSign will automatically inject the kid, unless I pass reference:false
          signer = jose.JWS.createSign(signOptions, [{key:signingKey, reference:false}]);
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
  if (matches && matches.length == 4) {
    //$("#mainalert").hide();
    $("#mainalert").addClass('fade').removeClass('show');

    return jose.JWK.asKey(getPublicKey(), "pem")
      .then( publicKey =>
             jose.JWS.createVerify(publicKey)
             .verify(tokenString)
             .then(function(result) {
               // {result} is a Object with:
               // *  header: the combined 'protected' and 'unprotected' header members
               // *  payload: Buffer of the signed content
               // *  signature: Buffer of the verified signature
               // *  key: The key used to verify the signature

               let parsedPayload = JSON.parse(result.payload),
                   reasons = checkValidityReasons(result.header, parsedPayload, getAcceptableSigningAlgs(publicKey));
            if (reasons.length == 0) {
              let message = 'The JWT signature has been verified and the times are valid. Algorithm: ' + result.header.alg;
              showDecoded();
              setAlert(message, 'success');
            }
            else {
              let label = (reasons.length == 1)? 'Reason' : 'Reasons';
              setAlert('The JWT is not valid. ' + label+': ' + reasons.join(', and ') + '.', 'warning');
            }
          })
          .catch (e => {
            setAlert('Cannot verify: ' + e);
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

function getGenKeyParams(flavor) {
  if (flavor == 'RSA') return {
    name: "RSASSA-PKCS1-v1_5",
    modulusLength: 2048, //can be 1024, 2048, or 4096
    publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
    hash: {name: "SHA-256"}
  };
  if (flavor == 'EC') return {
    name: "ECDSA",
    namedCurve: selectRandomValue(['P-256', 'P-384', 'P-521'])
  };
  throw new Error('invalid key flavor');
}

function newKeyPair(flavor) {
  return function (event) {
    let keyUse = ["sign", "verify"],
        isExtractable = true,
        genKeyParams = getGenKeyParams(flavor);
    return window.crypto.subtle.generateKey(genKeyParams, isExtractable, keyUse)
      .then(key => window.crypto.subtle.exportKey( "spki", key.publicKey )
            .then(keydata => updateKeyValue('public', key2pem('PUBLIC', keydata)) )
            .then( () => window.crypto.subtle.exportKey( "pkcs8", key.privateKey ))
            .then(keydata => updateKeyValue('private', key2pem('PRIVATE', keydata)) ))
      .then( () => $('#mainalert').removeClass('show').addClass('fade')) ;
  };
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
        header = { /* will be filled in later */ };

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
  let newRsaKeyPair = newKeyPair('RSA'),
      newEcKeyPair = newKeyPair('EC');

  $( '.btn-copy' ).on('click', copyToClipboard);
  $( '.btn-encode' ).on('click', encodeJwt);
  $( '.btn-decode' ).on('click', decodeJwt);
  $( '.btn-verify' ).on('click', verifyJwt);
  $( '.btn-newkeypair_rsa' ).on('click', newRsaKeyPair);
  $( '.btn-newkeypair_ec' ).on('click', newEcKeyPair);
  $( '.btn-regen' ).on('click', contriveJwt);

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

  newRsaKeyPair()
    .then( _ => contriveJwt() );


// // Popover の処理を追加してみた
// $(function () {
//   $("button[data-toggle='popover']").popover({
//     container: 'body'
//   })
// })


});
