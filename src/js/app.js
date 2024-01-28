/* global Buffer, TextDecoder, BUILD_VERSION, gtag */
// gtag('event', <action>, {
//   'event_category': <category>,
//   'event_label': <label>,
//   'value': <value>
// });

import { _Tooltip, Popover } from "bootstrap";
import CodeMirror from "codemirror/lib/codemirror.js";
import "codemirror/mode/javascript/javascript";
import "codemirror/addon/mode/simple";
import jose from "node-jose";
import LocalStorage from "./LocalStorage.js";
import rdg from "./random-data-generator";
import TimeAgo from "javascript-time-ago";
import en from "javascript-time-ago/locale/en";

TimeAgo.addDefaultLocale(en);

const html5AppId = "2084664E-BF2B-4C76-BD5F-1087502F580B";

const storage = LocalStorage.init(html5AppId);
const datamodel = {
  "sel-variant": "",
  "sel-enc": "",
  "sel-alg-encrypted": "",
  "sel-alg-signed": "",
  encodedjwt: "",
  ta_publickey: "",
  ta_privatekey: "",
  ta_symmetrickey: "",
  ta_directkey: "",
  "sel-symkey-coding-pb": "",
  "sel-symkey-coding": "",
  "sel-dirkey-coding": "",
  "sel-symkey-pbkdf2-salt-coding": "",
  "sel-expiry": 10,
  "chk-iat": true,
  "chk-typ": true
};

const tenMinutesInSeconds = 10 * 60;

const PBKDF2_SALT_DEFAULT = "abcdefghijkl",
  ITERATION_DEFAULT = 8192,
  ITERATION_MAX = 100001,
  ITERATION_MIN = 50;

const re = {
  signed: {
    jwt: new RegExp("^([^\\.]+)\\.([^\\.]+)\\.([^\\.]+)$"),
    cm: new RegExp("^([^\\.]+)(\\.)([^\\.]+)(\\.)([^\\.]+)$")
  },
  encrypted: {
    jwt: new RegExp(
      "^([^\\.]+)\\.([^\\.]*)\\.([^\\.]+)\\.([^\\.]+)\\.([^\\.]+)$"
    ),
    cm: new RegExp(
      "^([^\\.]+)(\\.)([^\\.]*)(\\.)([^\\.]+)(\\.)([^\\.]+)(\\.)([^\\.]+)$"
    )
  }
};

const $sel = (query) => document.querySelector(query),
  $all = (query) => document.querySelectorAll(query),
  hide = (el) => {
    el.classList.add("hidden");
    el.classList.remove("show");
  },
  show = (el) => {
    el.classList.remove("hidden");
    el.classList.add("show");
  };

function algPermutations(prefixes) {
  return prefixes.reduce(
    (a, v) => [...a, ...[256, 384, 512].map((x) => v + x)],
    []
  );
}

const rsaSigningAlgs = algPermutations(["RS", "PS"]),
  ecdsaSigningAlgs = algPermutations(["ES"]),
  hmacSigningAlgs = algPermutations(["HS"]),
  signingAlgs = [...rsaSigningAlgs, ...ecdsaSigningAlgs, ...hmacSigningAlgs],
  rsaKeyEncryptionAlgs = ["RSA-OAEP", "RSA-OAEP-256"],
  ecdhKeyEncryptionAlgs = ["ECDH-ES", "ECDH-ES+A128KW", "ECDH-ES+A256KW"], // 'ECDH-ES+A192KW' not supported
  pbes2KeyEncryptionAlgs = [
    "PBES2-HS256+A128KW",
    "PBES2-HS384+A192KW",
    "PBES2-HS512+A256KW"
  ],
  kwKeyEncryptionAlgs = ["A128KW", "A256KW"],
  keyEncryptionAlgs = [
    ...rsaKeyEncryptionAlgs,
    ...pbes2KeyEncryptionAlgs,
    ...kwKeyEncryptionAlgs,
    ...ecdhKeyEncryptionAlgs,
    "dir"
  ],
  contentEncryptionAlgs = [
    "A128CBC-HS256",
    "A256CBC-HS512",
    "A128GCM",
    "A256GCM"
  ];

const editors = {}; // codemirror editors

CodeMirror.defineSimpleMode("encodedjwt", {
  start: [
    {
      regex: re.signed.cm,
      sol: true,
      token: ["jwt-header", "", "jwt-payload", "", "jwt-signature"]
    },
    {
      regex: re.encrypted.cm,
      sol: true,
      token: [
        "jwt-header",
        "",
        "jwt-key",
        "",
        "jwt-iv",
        "",
        "jwt-payload",
        "",
        "jwt-authtag"
      ]
    }
  ]
});

const curry =
  (fn, arg1) =>
  (...args) =>
    fn.apply(this, [arg1].concat(args));

const quantify = (quantity, term) => {
  const termIsPlural = term.endsWith("s"),
    quantityIsPlural = quantity != 1 && quantity != -1;
  if (termIsPlural && !quantityIsPlural) return term.slice(0, -1);
  return !termIsPlural && quantityIsPlural ? term + "s" : term;
};

function reformIndents(s) {
  const s2 = s
    .split(new RegExp("\n", "g"))
    .map((s) => s.trim())
    .join("\n");
  return s2.trim();
}

function timeAgo(time) {
  return new TimeAgo("en-US").format(time);
}

function formatTimeString(time) {
  return time.toISOString().replace(".000Z", "Z");
}

function hmacToKeyBits(alg) {
  switch (alg) {
    case "HS256":
      return 256;
    case "HS384":
      return 384;
    case "HS512":
      return 512;
  }
  return 9999999;
}

function requiredKeyBitsForAlg(alg) {
  if (alg.startsWith("PBES2")) {
    const hmac = alg.substring(6, 11);
    return hmacToKeyBits(hmac);
  }
  if (alg.startsWith("HS")) {
    return hmacToKeyBits(alg);
  }
  switch (alg) {
    case "A128CBC-HS256":
      return 256;
    case "A192CBC-HS384":
      return 384;
    case "A256CBC-HS512":
      return 512;
    case "A128GCM":
      return 128;
    case "A192GCM":
      return 192;
    case "A256GCM":
      return 256;
    case "A128KW":
      return 128;
    case "A192KW":
      return 192;
    case "A256KW":
      return 256;
  }
  return 99999;
}

function getPbkdf2IterationCount() {
  const icountvalue = $sel("#ta_pbkdf2_iterations").value.trim();
  let icount = ITERATION_DEFAULT;
  if (icountvalue == "") {
    setAlert("not a number? defaulting to iteration count: " + icount);
  } else {
    try {
      icount = Number.parseInt(icountvalue, 10);
    } catch (_exc1) {
      setAlert("not a number? defaulting to iteration count: " + icount);
    }
  }
  if (icount > ITERATION_MAX || icount < ITERATION_MIN) {
    icount = ITERATION_DEFAULT;
    setAlert("iteration count out of range. defaulting to: " + icount);
  }
  return icount;
}

function getPbkdf2SaltBuffer() {
  const saltText = $sel("#ta_pbkdf2_salt").value.trim(),
    coding = $sel(
      ".sel-symkey-pbkdf2-salt-coding"
    ).selectedOptions[0].text.toLowerCase(),
    knownCodecs = ["utf-8", "base64", "hex"];

  if (knownCodecs.indexOf(coding) >= 0) {
    return Buffer.from(saltText, coding);
  }
  throw new Error("unsupported salt encoding"); // will not happen
}

function getBufferForSymmetricKey(item, alg) {
  /* let $div; */
  let $ta;
  if (typeof item == "string") {
    const s = `#${item}`;
    //$div = $sel(s);
    $ta = $sel(`${s} .ta-key`);
  } else {
    $ta = item;
    // $div = $ta.parentElement;
  }

  const keyvalue = $ta.value.trim(),
    select = $sel(`#${$ta.getAttribute("data-coding")}`),
    coding = select.selectedOptions[0].text.toLowerCase(),
    knownCodecs = ["utf-8", "base64", "hex"];

  if (knownCodecs.indexOf(coding) >= 0) {
    let b = null;
    try {
      b = Buffer.from(keyvalue, coding);
    } catch (_e) {
      // bad coding: either bad length, invalid chars for the given coding, etc.
      b = Buffer.from([]);
    }
    return Promise.resolve(b);
  }

  if (coding == "pbkdf2") {
    const kdfParams = {
      salt: getPbkdf2SaltBuffer(),
      iterations: getPbkdf2IterationCount(),
      length: requiredKeyBitsForAlg(alg) / 8
    };
    return jose.JWA.derive(
      "PBKDF2-SHA-256",
      Buffer.from(keyvalue, "utf-8"),
      kdfParams
    );
  }

  throw new Error("unknown key encoding: " + coding); // will not happen
}

function looksLikePem(s) {
  s = s.trim();
  const looksLike =
    (s.startsWith("-----BEGIN PRIVATE KEY-----") &&
      s.endsWith("-----END PRIVATE KEY-----")) ||
    (s.startsWith("-----BEGIN PUBLIC KEY-----") &&
      s.endsWith("-----END PUBLIC KEY-----")) ||
    (s.startsWith("-----BEGIN RSA PUBLIC KEY-----") &&
      s.endsWith("-----END RSA PUBLIC KEY-----")) ||
    (s.startsWith("-----BEGIN RSA PRIVATE KEY-----") &&
      s.endsWith("-----END RSA PRIVATE KEY-----"));
  return looksLike;
}

function looksLikeJwks(s) {
  try {
    s = JSON.parse(s);
    return s.keys && s.keys.length > 0 && s.keys[0].kty ? s : null;
  } catch (_exc1) {
    return false;
  }
}

function getPrivateKey(header, options) {
  editors.privatekey.save();
  const keyvalue = $sel("#ta_privatekey")
    .value.trim()
    .replace(new RegExp("[^\x00-\x7F]", "g"), ""); // strip non - ASCII

  return jose.JWK.asKey(keyvalue, "pem", { ...options, ...header });
}

function getPublicKey(header, options) {
  options = options || {};
  editors.publickey.save();
  const fieldValue = $sel("#ta_publickey")
    .value.trim()
    .replace(new RegExp("[^\x00-\x7F]", "g"), ""); // strip non - ASCII

  if (looksLikePem(fieldValue)) {
    // if de-serializing from PEM, apply the kid, if any
    return jose.JWK.asKey(fieldValue, "pem", { ...options, ...header });
  }

  let parseable = false;
  try {
    JSON.parse(fieldValue);
    parseable = true;
  } catch (_e1) {
    setAlert("not parseable as JWKS?");
  }

  if (!parseable) {
    return Promise.resolve(null); // no key
  }

  return jose.JWK.asKeyStore(fieldValue).then((keystore) =>
    keystore.get(header)
  );
}

function clearJwt(_event) {
  editors.encodedjwt.setValue("");
  editors.encodedjwt.save();
}

function copyToClipboard(event) {
  const sourceElement = event.currentTarget.getAttribute("data-target"),
    $source = document.getElementById(sourceElement),
    $temp = document.createElement("textarea");

  if (editors[sourceElement]) {
    editors[sourceElement].save();
  }

  gtag("event", "copyToClipboard", {
    event_category: "click",
    event_label: sourceElement
  });

  const sourceType = $source.tagName;
  const textToCopy =
    sourceType == "TEXTAREA" || sourceType == "INPUT"
      ? $source.value
      : $source.text;

  $sel("body").appendChild($temp);
  $temp.value = textToCopy;
  $temp.select();
  let success;
  try {
    success = document.execCommand("copy");

    /*
     * Animation to indicate copy.
     * CodeMirror obscures the original textarea, and appends some DOM content
     * as the next sibling. We want to flash THAT.
     **/
    const $putativeCmdiv = $source.nextElementSibling;
    if (
      $putativeCmdiv.tagName.toLowerCase() == "div" &&
      $putativeCmdiv.classList.contains("CodeMirror")
    ) {
      const $divToFlash = $putativeCmdiv.querySelector(".CodeMirror-code");
      // At one point there seemed to be a bug in Chrome which recomputes the
      // font size, seemingly incorrectly, after removing the
      // copy-to-clipboard-flash-bg class.

      // Not sure if that is still happening.  If so, this logic should be
      // changed to just leave the class there, and then remove it _prior_ to
      // adding it the next time.

      $divToFlash.classList.remove("copy-to-clipboard-flash-bg");
      setTimeout(
        (_) => $divToFlash.classList.add("copy-to-clipboard-flash-bg"),
        6
      );
    } else {
      // no codemirror (probably the secretkey field, which is just an input)
      $source.classList.add("copy-to-clipboard-flash-bg");
      setTimeout(
        (_) => $source.classList.remove("copy-to-clipboard-flash-bg"),
        1800
      );
    }
  } catch (_e) {
    success = false;
  }
  $temp.parentNode.removeChild($temp);
  return success;
}

function getAcceptableSigningAlgs(key) {
  const keytype = key.kty;
  if (keytype == "oct") return hmacSigningAlgs;
  if (keytype == "RSA") return rsaSigningAlgs;
  if (keytype == "EC") {
    if (key.length == 256) return ["ES256"];
    if (key.length == 384) return ["ES384"];
    if (key.length == 521) return ["ES512"];
  }
  return ["NONE"];
}

function getAcceptableEncryptionAlgs(key) {
  const keytype = key.kty;
  if (keytype == "RSA") return rsaKeyEncryptionAlgs;
  if (keytype == "oct")
    return [...pbes2KeyEncryptionAlgs, ...kwKeyEncryptionAlgs, "dir"];
  if (keytype == "EC") return ecdhKeyEncryptionAlgs;
  return ["NONE"];
}

const isAppropriateSigningAlg = (alg, key) =>
  getAcceptableSigningAlgs(key).indexOf(alg) >= 0;

const isAppropriateEncryptingAlg = (alg, key) =>
  getAcceptableEncryptionAlgs(key).indexOf(alg) >= 0;

const pickSigningAlg = (key) => rdg.arrayItem(getAcceptableSigningAlgs(key));

const pickKeyEncryptionAlg = (key) =>
  rdg.arrayItem(getAcceptableEncryptionAlgs(key));

const pickContentEncryptionAlg = () =>
  datamodel["sel-enc"] || rdg.arrayItem(contentEncryptionAlgs);

const isSymmetric = (alg) => alg.startsWith("HS");

function checkKeyLength(alg, exact, keybuffer) {
  const length = keybuffer.byteLength,
    requiredLength = requiredKeyBitsForAlg(alg) / 8,
    okResult = exact ? length == requiredLength : length >= requiredLength;
  if (okResult) return Promise.resolve(keybuffer);
  const errorMsg = exact
    ? `inappropriate key length, provided=${length}, required=${requiredLength}`
    : `insufficient key length. You need at least ${requiredLength} bytes to use ${alg}`;
  return Promise.reject(new Error(errorMsg));
}

function retrieveCryptoKey(header, options) {
  // options = {direction:'encrypt'} or {direction:'decrypt'}
  // When using symmetric keys and algorithms, it does not matter.
  if (pbes2KeyEncryptionAlgs.indexOf(header.alg) >= 0) {
    // overwrite the header values with values from the inputs
    header.p2c = getPbkdf2IterationCount();
    header.p2s = getPbkdf2SaltBuffer().toString("base64");

    return getBufferForSymmetricKey("symmetrickey", header.alg).then(
      (keyBuffer) => jose.JWK.asKey({ kty: "oct", k: keyBuffer, use: "enc" })
    );
  }
  if (kwKeyEncryptionAlgs.indexOf(header.alg) >= 0) {
    return getBufferForSymmetricKey("symmetrickey", header.alg)
      .then((keyBuffer) => checkKeyLength(header.alg, true, keyBuffer))
      .then((keyBuffer) =>
        jose.JWK.asKey({ kty: "oct", k: keyBuffer, use: "enc" })
      );
  }

  if (header.alg === "dir") {
    return getBufferForSymmetricKey("directkey", header.alg)
      .then((keyBuffer) => checkKeyLength(header.enc, true, keyBuffer))
      .then((keyBuffer) =>
        jose.JWK.asKey({
          kty: "oct",
          k: keyBuffer,
          use: "enc",
          alg: header.enc
        })
      );
  }

  // When using asymmetric keys and algorithms, direction matters.
  if (options.direction === "encrypt")
    return getPublicKey(header, { use: "enc" });

  return getPrivateKey(header, { use: "enc" });
}

function encodeJwt(_event) {
  const values = {};
  let parseError;
  ["header", "payload"].forEach((segment) => {
    const elementId = "token-decoded-" + segment;
    if (editors[elementId]) {
      editors[elementId].save();
      const text = $sel("#" + elementId).value;
      try {
        values[segment] = JSON.parse(text);
      } catch (_e) {
        parseError = segment;
      }
    }
  });
  gtag("event", "encodeJwt");

  if (parseError) {
    setAlert("cannot parse JSON (" + parseError + ")", "warning");
    return;
  }

  const { header, payload } = values;
  if (!header.typ && $sel("#chk-typ").checked) {
    header.typ = "JWT";
  }

  // optionally set expiry in payload
  const desiredExpiryOverride =
    $sel(".sel-expiry").selectedOptions[0].text.toLowerCase();
  if (desiredExpiryOverride == "no expiry") {
    delete payload.exp;
  } else {
    const matches = new RegExp("^([1-9][0-9]*) (minutes|seconds)$").exec(
      desiredExpiryOverride
    );
    if (matches && matches.length == 3) {
      const now = Math.floor(new Date().valueOf() / 1000),
        factor = matches[2] == "minutes" ? 60 : 1;
      // the following may override an explicitly-provided value
      payload.exp = now + parseInt(matches[1], 10) * factor;
    }
  }

  const wantIssuedTime = $sel("#chk-iat").checked;
  if (wantIssuedTime) {
    payload.iat = Math.floor(new Date().valueOf() / 1000);
  }

  let p = null;
  if (header.enc && header.alg) {
    // create encrypted JWT
    p = retrieveCryptoKey(header, { direction: "encrypt" }).then(
      (encryptingKey) => {
        if (!isAppropriateEncryptingAlg(header.alg, encryptingKey)) {
          throw new Error(
            "the alg specified in the header is not compatible with the provided key. Maybe generate a fresh one?"
          );
        }
        const encryptOptions = {
            alg: header.alg,
            fields: header,
            format: "compact"
          },
          // createEncrypt will automatically inject the kid, unless I pass reference:false
          cipher = jose.JWE.createEncrypt(encryptOptions, [
            { key: encryptingKey, reference: false }
          ]);
        cipher.update(JSON.stringify(payload), "utf8");
        return cipher.final();
      }
    );
  } else {
    // create signed JWT
    if (isSymmetric(header.alg)) {
      p = getBufferForSymmetricKey("symmetrickey", header.alg)
        .then((keyBuffer) => checkKeyLength(header.alg, false, keyBuffer))
        .then((keyBuffer) =>
          jose.JWK.asKey({ kty: "oct", k: keyBuffer, use: "sig" })
        );
    } else {
      p = getPrivateKey();
    }
    p = p.then((signingKey) => {
      if (!header.alg) {
        header.alg = pickSigningAlg(signingKey);
      }
      if (!isAppropriateSigningAlg(header.alg, signingKey)) {
        throw new Error(
          "the alg specified in the header is not compatible with the provided key. Maybe generate a fresh one?"
        );
      }
      const signOptions = {
        alg: header.alg,
        fields: header,
        format: "compact"
      };
      // use reference:false to omit the kid from the header
      const signer = jose.JWS.createSign(signOptions, [
        { key: signingKey, reference: false }
      ]);
      signer.update(JSON.stringify(payload), "utf8");
      return signer.final();
    });
  }

  return p
    .then((jwt) => {
      //editors.encodedjwt.setValue(jwt);
      $sel(
        "#panel_encoded > p > span.length"
      ).textContent = `(${jwt.length} bytes)`;
      editors.encodedjwt.setValue(jwt);
      editors.encodedjwt.save();
      if (header.enc) {
        // re-format the decoded JSON, incl added or modified properties like kid, alg
        showDecoded(true);
        editors["token-decoded-payload"].setValue(
          JSON.stringify(payload, null, 2)
        );
        setAlert("an encrypted JWT", "info");
      } else {
        showDecoded();
        setAlert("a signed JWT", "info");
      }
    })
    .then(() => {
      $sel("#privatekey .CodeMirror-code").classList.remove("outdated");
      $sel("#publickey .CodeMirror-code").classList.remove("outdated");
    })
    .catch((e) => {
      //console.log(e.stack);
      setAlert(e);
    });
}

function checkValidityReasons(pHeader, pPayload, acceptableAlgorithms) {
  const nowSeconds = Math.floor(new Date().valueOf() / 1000),
    wantCheckIat = true,
    reasons = [];

  // 4. algorithm ('alg' in header) check
  if (pHeader.alg === undefined) {
    reasons.push("the header lacks the required alg property");
  }

  if (acceptableAlgorithms.indexOf(pHeader.alg) < 0) {
    reasons.push(`the algorithm is (${pHeader.alg}) not acceptable`);
  }

  // 8.1 expired time 'exp' check
  if (pPayload.exp !== undefined && typeof pPayload.exp == "number") {
    const expiry = new Date(pPayload.exp * 1000),
      expiresString = formatTimeString(expiry),
      delta = nowSeconds - pPayload.exp,
      timeUnit = quantify(delta, "seconds");
    if (delta > 0) {
      reasons.push(
        `the expiry time (${expiresString}) is in the past, ${delta} ${timeUnit} ago`
      );
    }
  }

  // 8.2 not before time 'nbf' check
  if (pPayload.nbf !== undefined && typeof pPayload.nbf == "number") {
    const notBefore = new Date(pPayload.nbf * 1000),
      notBeforeString = formatTimeString(notBefore),
      delta = pPayload.nbf - nowSeconds,
      timeUnit = quantify(delta, "seconds");
    if (delta > 0) {
      reasons.push(
        `the not-before time (${notBeforeString}) is in the future, in ${delta} ${timeUnit}`
      );
    }
  }

  // 8.3 issued at time 'iat' check
  if (wantCheckIat) {
    if (pPayload.iat !== undefined && typeof pPayload.iat == "number") {
      const issuedAt = new Date(pPayload.iat * 1000),
        issuedAtString = formatTimeString(issuedAt),
        delta = pPayload.iat - nowSeconds,
        timeUnit = quantify(delta, "seconds");
      if (delta > 0) {
        reasons.push(
          `the issued-at time (${issuedAtString}) is in the future, in ${delta} ${timeUnit}`
        );
      }
    }
  }
  return reasons;
}

function verifyJwt(event) {
  editors.encodedjwt.save();
  editors.publickey.save();
  const tokenString = editors.encodedjwt.getValue();
  let matches = re.signed.jwt.exec(tokenString);
  // verify a signed JWT
  if (matches && matches.length == 4) {
    $sel("#mainalert").classList.add("fade");
    $sel("#mainalert").classList.remove("show");
    const json = Buffer.from(matches[1], "base64").toString("utf8"),
      header = JSON.parse(json);
    let p = null;

    gtag("event", "verifyJwt", {
      event_category: "click",
      event_label: `signed ${header.alg}`
    });

    if (isSymmetric(header.alg)) {
      p = getBufferForSymmetricKey("symmetrickey", header.alg)
        .then((keyBuffer) => checkKeyLength(header.alg, false, keyBuffer))
        .then((keyBuffer) =>
          jose.JWK.asKey({ kty: "oct", k: keyBuffer, use: "sig" })
        );
    } else {
      p = getPublicKey(header);
    }

    p = p
      .then((key) =>
        jose.JWS.createVerify(key)
          .verify(tokenString)
          .then((result) => {
            // {result} is a Object with:
            // *  header: the combined 'protected' and 'unprotected' header members
            // *  payload: Buffer of the signed content
            // *  signature: Buffer of the verified signature
            // *  key: The key used to verify the signature

            const parsedPayload = JSON.parse(result.payload),
              reasons = checkValidityReasons(
                result.header,
                parsedPayload,
                getAcceptableSigningAlgs(key)
              );
            if (reasons.length == 0) {
              const message =
                "The JWT signature has been verified and the times are valid. Algorithm: " +
                result.header.alg;
              showDecoded();
              if (event) {
                setAlert(message, "success");
              }
              selectAlgorithm(result.header.alg);
              $sel("#privatekey .CodeMirror-code").classList.remove("outdated");
              $sel("#publickey .CodeMirror-code").classList.remove("outdated");
            } else {
              const label = reasons.length == 1 ? "Reason" : "Reasons";
              setAlert(
                "The signature verifies, but the JWT is not valid. " +
                  label +
                  ": " +
                  reasons.join(", and ") +
                  ".",
                "warning"
              );
            }
          })
          .catch((e) => {
            if (e.message == "no key found") {
              setAlert("could not verify. key mismatch?");
            } else {
              setAlert("could not verify. " + e.message);
            }
          })
      )
      .catch((e) => {
        setAlert(e);
      });

    return p;
  }

  // verification/decrypt of encrypted JWT
  matches = re.encrypted.jwt.exec(tokenString);
  if (matches && matches.length == 6) {
    const json = Buffer.from(matches[1], "base64").toString("utf8");
    const header = JSON.parse(json);
    gtag("event", "verifyJwt", {
      event_category: "click",
      event_label: `encrypted ${header.alg}`
    });

    return retrieveCryptoKey(header, { direction: "decrypt" })
      .then(async (decryptionKey) => {
        const decrypter = await jose.JWE.createDecrypt(decryptionKey);
        const result = await decrypter.decrypt(tokenString);
        // {result} is a Object with:
        // *  header: the combined 'protected' and 'unprotected' header members
        // *  protected: an array of the member names from the "protected" member
        // *  key: Key used to decrypt
        // *  payload: Buffer of the decrypted content
        // *  plaintext: Buffer of the decrypted content (alternate)
        const td = new TextDecoder("utf-8"),
          stringPayload = td.decode(result.payload);
        let parsedPayload = null;
        try {
          parsedPayload = JSON.parse(stringPayload);
        } catch (e) {
          // not JSON. It's a JWE, not JWT. Which is ok.
        }

        if (parsedPayload) {
          const prettyPrintedJson = JSON.stringify(parsedPayload, null, 2),
            reasons = checkValidityReasons(
              result.header,
              parsedPayload,
              getAcceptableEncryptionAlgs(decryptionKey)
            ),
            elementId = "token-decoded-payload",
            flavor = "payload";
          editors[elementId].setValue(prettyPrintedJson);
          $sel(
            `#${flavor} > p > .length`
          ).textContent = `( ${stringPayload.length} bytes)`;

          if (reasons.length == 0) {
            const message =
              "The JWT has been decrypted successfully, and the times are valid.";
            if (event) {
              setAlert(message, "success");
            }
            $sel("#privatekey .CodeMirror-code").classList.remove("outdated");
            $sel("#publickey .CodeMirror-code").classList.remove("outdated");
          } else {
            const label = reasons.length == 1 ? "Reason" : "Reasons";
            setAlert(
              "The JWT is not valid. " +
                label +
                ": " +
                reasons.join(", and ") +
                ".",
              "warning"
            );
          }
          return {};
        }

        // it's a JWE
        const elementId = "token-decoded-payload",
          flavor = "payload";
        editors[elementId].setValue(stringPayload);
        $sel(
          `#${flavor} > p > .length`
        ).textContent = `( ${stringPayload.length} bytes)`;

        return null;
      })
      .catch((e) => {
        setAlert("Decryption failed. Bad key?");
        console.log("During decryption: " + e);
        console.log(e.stack);
      });
  }
}

function setAlert(html, alertClass) {
  const buttonHtml =
      '<button type="button" class="close dismiss" data-dismiss="alert" aria-label="Close">\n' +
      ' <span aria-hidden="true">&times;</span>\n' +
      "</button>",
    $mainalert = $sel("#mainalert");
  $mainalert.innerHTML = `<div>${html}\n${buttonHtml}</div>`;
  if (alertClass) {
    $mainalert.classList.remove("alert-warning"); // this is the default
    $mainalert.classList.add("alert-" + alertClass); // success, primary, warning, etc
  } else {
    $mainalert.classList.add("alert-warning");
  }

  const dismiss = () => {
    $mainalert.classList.add("fade");
    $mainalert.classList.remove("show");
    setTimeout(() => $mainalert.setAttribute("style", `z-index: -1`), 800);
  };

  // show()
  $mainalert.classList.remove("fade");
  $mainalert.classList.add("show");
  $mainalert.setAttribute("style", `z-index: 99`);
  const t = setTimeout(dismiss, 5650);
  $sel("button.dismiss").addEventListener("click", () => {
    dismiss();
    clearTimeout(t);
  });
}

function closeAlert(_event) {
  const $mainalert = $sel("#mainalert");
  $mainalert.classList.add("fade");
  $mainalert.classList.remove("show");
  setTimeout(() => $mainalert.setAttribute("style", "z-index: -1"), 800);
  return false; // Keep close.bs.alert event from removing from DOM
}

function updateAsymmetricKeyValue(flavor /* public || private */, keyvalue) {
  const editor = editors[flavor + "key"];
  if (editor) {
    editor.setValue(keyvalue);
    editor.save();
    saveSetting("ta_" + flavor + "key", keyvalue);
  }
}

function key2pem(flavor, keydata) {
  let body = window.btoa(String.fromCharCode(...new Uint8Array(keydata)));
  body = body.match(/.{1,64}/g).join("\n");
  return `-----BEGIN ${flavor} KEY-----\n${body}\n-----END ${flavor} KEY-----`;
}

function getGenKeyParams(alg) {
  if (alg.startsWith("RS") || alg.startsWith("PS"))
    return {
      name: "RSASSA-PKCS1-v1_5", // this name also works for RSA-PSS !
      modulusLength: 2048, //can be 1024, 2048, or 4096
      publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
      hash: { name: "SHA-256" }
    };
  // signing with EC keys
  if (alg == "ES256") return { name: "ECDSA", namedCurve: "P-256" };
  if (alg == "ES384") return { name: "ECDSA", namedCurve: "P-384" };
  if (alg == "ES512") return { name: "ECDSA", namedCurve: "P-521" };
  // encrypting with EC keys (ECDH)
  // TODO: determine if we want to support other curves. can be "P-256", "P-384", or "P-521"
  if (alg.startsWith("ECDH")) return { name: "ECDH", namedCurve: "P-256" };
  throw new Error("invalid key flavor");
}

function maybeNewKey() {
  const alg = $sel(".sel-alg").selectedOptions[0].text;
  if (alg === "dir") {
    if (!$sel("#ta_directkey").value) {
      return newKey(null);
    }
  } else if (
    alg.startsWith("HS") ||
    alg.startsWith("PB") ||
    alg.startsWith("A")
  ) {
    if (!$sel("#ta_symmetrickey").value) {
      return newKey(null);
    }
  } else {
    editors.privatekey.save();
    editors.publickey.save();
    const privatekey = $sel("#ta_privatekey").value.trim(),
      publickey = $sel("#ta_publickey").value.trim();
    if (!privatekey || !publickey) {
      return newKey(null);
    }
  }
  return Promise.resolve({});
}

const getKeyUse = (alg) =>
  alg.startsWith("ECDH") ? ["deriveKey", "deriveBits"] : ["sign", "verify"];

function newKey(event) {
  const alg = $sel(".sel-alg").selectedOptions[0].text;

  gtag("event", "newKey", {
    event_category: event ? "click" : "implicit",
    event_label: alg
  });

  if (
    alg.startsWith("HS") ||
    alg.startsWith("PB") ||
    alg === "dir" ||
    alg.startsWith("A")
  ) {
    const domid = alg === "dir" ? "directkey" : "symmetrickey",
      $ta = $sel(`#${domid} .ta-key`),
      coding = $sel(
        `#${$ta.getAttribute("data-coding")}`
      ).selectedOptions[0].text.toLowerCase();
    let keyString = null;
    if (coding == "pbkdf2") {
      // password can be of arbitrary length
      keyString = rdg.passphrase();
    } else {
      // want key of specific length. Not REQUIRED for HS* signing, but it's ok.
      const cls = alg === "dir" ? ".sel-enc" : ".sel-alg",
        cipherAlg = $sel(cls).selectedOptions[0].text,
        benchmark = requiredKeyBitsForAlg(cipherAlg) / 8;
      if (coding == "utf-8") {
        keyString = rdg.password(benchmark);
      } else if (coding == "base64" || coding == "hex") {
        keyString = Buffer.from(rdg.octetKey(benchmark)).toString(coding);
      }
    }
    if (keyString) {
      $ta.value = keyString;
      $ta.dispatchEvent(new Event("change"));
      saveSetting("ta_" + domid, keyString);
    }
    return Promise.resolve({});
  }

  // this works with either EC or RSA key types
  const keyUse = getKeyUse(alg),
    isExtractable = true,
    genKeyParams = getGenKeyParams(alg);
  return window.crypto.subtle
    .generateKey(genKeyParams, isExtractable, keyUse)
    .then((key) =>
      window.crypto.subtle
        .exportKey("spki", key.publicKey)
        .then((keydata) =>
          updateAsymmetricKeyValue("public", key2pem("PUBLIC", keydata))
        )
        .then(() => window.crypto.subtle.exportKey("pkcs8", key.privateKey))
        .then((keydata) =>
          updateAsymmetricKeyValue("private", key2pem("PRIVATE", keydata))
        )
    )
    .then(() => {
      $sel("#mainalert").classList.remove("show");
      $sel("#mainalert").classList.add("fade");
      $sel("#privatekey .CodeMirror-code").classList.remove("outdated");
      $sel("#publickey .CodeMirror-code").classList.remove("outdated");
      // why only publickey, not also privatekey?
      editors.publickey.setOption("mode", "encodedjwt");
      return {};
    })
    .catch((e) => console.log(e));
}

function selectAlgorithm(algName) {
  const currentlySelectedAlg =
    $sel(".sel-alg").selectedOptions[0].text.toLowerCase();
  if (algName.toLowerCase() != currentlySelectedAlg) {
    let $option = $sel(`.sel-alg option[value="${algName}"]`);
    if (!$option) {
      $option = $sel('.sel-alg option[value="??"]');
    }
    $option.selected = true;
    //$option.prop("selected", true).trigger("change");
    $sel(".sel-alg").dispatchEvent(new Event("change"));
  }
}

function selectEnc(encName) {
  const currentlySelectedEnc =
    $sel(".sel-enc").selectedOptions[0].text.toLowerCase();
  if (encName.toLowerCase() != currentlySelectedEnc) {
    let $option = $sel(`.sel-enc option[value="${encName}"]`);
    if (!$option) {
      $option = $sel('.sel-enc option[value="??"]');
    }
    $option.selected = true;
    //$option.prop("selected", true).trigger("change");
    $sel(".sel-enc").dispatchEvent(new Event("change"));
  }
}

function showDecoded(skipEncryptedPayload) {
  editors.encodedjwt.save();

  const tokenString = editors.encodedjwt.getValue();
  let matches = re.signed.jwt.exec(tokenString);

  gtag("event", "decode", {
    event_category: "click"
  });

  saveSetting("encodedjwt", tokenString); // for reload
  $sel(
    "#panel_encoded > p > span.length"
  ).textContent = `(${tokenString.length} bytes)`;

  if (matches && matches.length == 4) {
    setAlert("looks like a signed JWT", "info");
    const currentlySelectedVariant =
      $sel(".sel-variant").selectedOptions[0].text.toLowerCase();
    if (currentlySelectedVariant != "signed") {
      $sel(".sel-variant option[value=Signed]").selected = true;
      setTimeout(() => $sel(".sel-variant").dispatchEvent(new Event("change")));
    }

    const flavors = ["header", "payload"]; // cannot decode signature
    matches.slice(1, -1).forEach(function (item, index) {
      const json = Buffer.from(item, "base64").toString("utf8"),
        flavor = flavors[index],
        elementId = "token-decoded-" + flavor;
      try {
        const obj = JSON.parse(json), // may throw
          prettyPrintedJson = JSON.stringify(obj, null, 2),
          flatJson = JSON.stringify(obj);
        editors[elementId].setValue(prettyPrintedJson);
        $sel(
          `#${flavor} > p > .length`
        ).textContent = `(${flatJson.length} bytes)`;

        if (flavor == "header" && obj.alg) {
          selectAlgorithm(obj.alg);
        }
      } catch (e) {
        // probably not json
        setAlert(`the ${flavor} may not be valid JSON`, "info");
        editors[elementId].setValue(json);
      }
    });
    return;
  }

  matches = re.encrypted.jwt.exec(tokenString);
  if (matches && matches.length == 6) {
    setAlert("an encrypted JWT", "info");
    const currentlySelectedVariant =
      $sel(".sel-variant").selectedOptions[0].text.toLowerCase();
    if (currentlySelectedVariant != "encrypted") {
      $sel(".sel-variant option[value=Encrypted]").selected = true;
      setTimeout(() => $sel(".sel-variant").dispatchEvent(new Event("change")));
    }
    // Display the decoded header.
    // It is not possible to 'decode' the payload; it requires decryption.
    try {
      const item = matches[1],
        json = Buffer.from(item, "base64").toString("utf8"),
        obj = JSON.parse(json),
        prettyPrintedJson = JSON.stringify(obj, null, 2),
        flatJson = JSON.stringify(obj);
      editors["token-decoded-header"].setValue(prettyPrintedJson);
      $sel("#header > p > .length").textContent = `(${flatJson.length} bytes)`;
      if (!skipEncryptedPayload) {
        // Just display a fixed value.
        // Must decrypt the ciphertext payload to display claims,
        // and it's not possible to decrypt just now.
        editors["token-decoded-payload"].setValue("?ciphertext?");
        $sel(
          "#payload > p > .length"
        ).textcontent = `(${matches[2].length} bytes)`;
      }
      if (obj.alg) {
        selectAlgorithm(obj.alg);
      }
      if (obj.enc) {
        selectEnc(obj.enc);
      }
    } catch (_e) {
      // probably not json
      setAlert("the header may not be valid JSON", "info");
      editors["token-decoded-header"].setValue("??");
    }

    // do not attempt decrypt here
    return;
  }

  setAlert("That does not appear to be a JWT");
}

function populateEncSelectOptions() {
  const select = $sel(".sel-enc");
  contentEncryptionAlgs.forEach((text) =>
    select.options.add(new Option(text, text))
  );
}

function populateAlgorithmSelectOptions() {
  const variant = $sel(".sel-variant").selectedOptions[0].text.toLowerCase(),
    $selAlg = $sel(".sel-alg");

  // remove all options
  while ($selAlg.options.length) {
    $selAlg.remove(0);
  }

  const a = variant == "signed" ? signingAlgs : keyEncryptionAlgs;
  a.forEach((text) => $selAlg.options.add(new Option(text, text)));

  const headerObj = getHeaderFromForm();
  let $option = null;
  if (headerObj && headerObj.alg) {
    // select that one
    $option = $sel(`.sel-alg option[value='${headerObj.alg}']`);
    if ($option) {
      saveSetting("sel-alg-" + variant, headerObj.alg);
    }
  }
  if (!$option) {
    // pull from data model and select that
    const value = datamodel["sel-alg-" + variant];
    $option = $sel(`.sel-alg option[value='${value}']`);
  }
  if ($option) {
    $option.selected = true;
  }

  $selAlg.setAttribute("data-prev", "NONE"); // do we always want this?
  setTimeout(() => $selAlg.dispatchEvent(new Event("change")), 1);
}

function keysAreCompatible(alg1, alg2) {
  const prefix1 = alg1.substring(0, 2),
    prefix2 = alg2.substring(0, 2);
  if (["RS", "PS"].indexOf(prefix1) >= 0 && ["RS", "PS"].indexOf(prefix2) >= 0)
    return true;
  if (prefix1 == "ES") return alg1 == alg2;
  return false;
}

function changeKeyCoding(event) {
  // fires for changes in coding for either key (dir, symmetric) or salt  (for PBKDF2)
  const sourceElement = event.currentTarget;
  if (sourceElement.tagName != "SELECT") {
    throw new Error("misconfiguration with event handler");
  }

  const newCodingCased = sourceElement.selectedOptions[0].text,
    id = sourceElement.getAttribute("id"),
    newCoding = newCodingCased.toLowerCase(),
    previousCoding = sourceElement.getAttribute("data-prev");

  const effectivePrevCoding = () => {
    if (previousCoding == "PBKDF2" || previousCoding == "pbkdf2")
      return "utf-8";
    return previousCoding || "utf-8";
  };
  if (newCoding != previousCoding) {
    // When the coding changes, try to re-encode the existing key.
    // This will not always work nicely when switching to UTF-8.
    // You will get a utf-8 string with unicode escape sequences, eg \u000b.
    const targetElement = sourceElement.getAttribute("data-target"),
      $ta = $sel(`#${targetElement}`),
      textVal = $ta.value,
      keybuf = Buffer.from(textVal, effectivePrevCoding());

    if (newCoding == "pbkdf2") {
      $ta.value = keybuf.toString("utf-8");
      // display the salt and iteration count
      show($sel("#pbkdf2_params"));
    } else {
      $ta.value = keybuf.toString(newCoding);
      if (id.indexOf("salt") < 0) {
        hide($sel("#pbkdf2_params"));
      }
    }
  }

  sourceElement.setAttribute("data-prev", newCoding);
  const suffix = newCoding == "pbkdf2" ? "-pb" : "";
  saveSetting(id + suffix, newCodingCased);
}

function checkSymmetryChange(newalg, oldalg) {
  const newPrefix = newalg.substring(0, 2);
  //oldPrefix = oldalg && oldalg.substring(0, 2);
  if (newalg == "dir") {
    if (oldalg != "dir") {
      hide($sel("#privatekey"));
      hide($sel("#publickey"));
      hide($sel("#symmetrickey"));
      show($sel("#directkey"));
    }
    return;
  }

  if (["HS", "PB", "A1", "A2"].includes(newPrefix)) {
    hide($sel("#privatekey"));
    hide($sel("#publickey"));
    show($sel("#symmetrickey"));
    hide($sel("#directkey"));

    const $keycoding = $sel("#sel-symkey-coding");
    if (newPrefix == "PB") {
      const currentlySelectedCoding =
        $keycoding.selectedOptions[0].text.toLowerCase();
      //$keycoding.find("option[value=PBKDF2]").show();
      if (currentlySelectedCoding != "pbkdf2") {
        const $option = $sel('#sel-symkey-coding option[value="PBKDF2"]');
        if ($option) {
          show($option);
          $option.selected = true;
        }
        $keycoding.dispatchEvent(new Event("change"));
      }
      // when it's a PBES2 alg, there's no option to switch key coding.
      $keycoding.setAttribute("disabled", "disabled");
    } else {
      let value = datamodel["sel-symkey-coding"];
      if (value == "PBKDF2") {
        // alg is not PBES2, but stored key coding is PBKDF2. Must force switch.
        value = "UTF-8";
        saveSetting("sel-symkey-coding", value);
      }
      const $item = $sel(`#sel-symkey-coding option[value='${value}']`);
      if ($item) {
        $item.selected = true;
      }
      const $option = $sel('#sel-symkey-coding option[value="PBKDF2"]');
      hide($option);
      $keycoding.removeAttribute("disabled");
    }

    if (newPrefix.startsWith("A")) {
      // TODO ? not sure
      // key wrapping, do not need PBKDF2
    }
    return true;
  }

  if (["RS", "PS", "ES", "EC"].includes(newPrefix)) {
    show($sel("#privatekey"));
    show($sel("#publickey"));
    hide($sel("#symmetrickey"));
    hide($sel("#directkey"));
    return true;
  }
}

function initialized() {
  return !!editors["token-decoded-header"];
}

function onChangeCheckbox(event) {
  const target = event.target,
    id = target.getAttribute("id"),
    booleanValue = target.checked;
  saveSetting(id, String(booleanValue));
}

function onChangeExpiry(event) {
  const target = event.target,
    selectedExpiry = target.selectedOptions[0].text;
  saveSetting("sel-expiry", selectedExpiry);
}

function getHeaderFromForm() {
  const headerText = $sel("#token-decoded-header").value;
  if (headerText) {
    try {
      return JSON.parse(headerText);
    } catch (_e) {
      console.log("invalid header");
    }
  }
  return {}; // hack in case of no header
}

async function onKeyTextChange(_event) {
  const target = _event.target,
    id = target.id,
    alg = $sel(".sel-alg").selectedOptions[0].text,
    variant = $sel(".sel-variant").selectedOptions[0].text.toLowerCase();

  saveSetting(id, target.value);

  // If the key will be used in a symmetric alg (signing or encrypting), show
  // some helpful text on the actual size of the key, and the required size of
  // the key.
  if (
    (variant == "encrypted" && (alg == "dir" || alg.startsWith("PB"))) ||
    (variant == "signed" && alg.startsWith("HS"))
  ) {
    if (!alg.startsWith("PB")) {
      const buf = await getBufferForSymmetricKey(target, alg),
        cls = id.indexOf("direct") >= 0 ? ".sel-enc" : ".sel-alg",
        realAlg = $sel(cls).selectedOptions[0].text,
        benchmark = requiredKeyBitsForAlg(realAlg) / 8,
        requirement = variant == "encrypted" ? "required" : "minimum";
      target.parentElement.querySelector(
        "p > span.length"
      ).textContent = `(${buf.byteLength} bytes, ${requirement}: ${benchmark})`;
    } else {
      // there is no minimum with PBKDF2...
    }
  }
}

function onChangeEnc(event) {
  const target = event.target,
    newSelection = target.selectedOptions[0].text,
    previousSelection = target.getAttribute("data-prev"),
    alg = $sel(".sel-alg").selectedOptions[0].text;
  let headerObj = null;

  if (!initialized()) {
    return;
  }
  gtag("event", "changeEnc", {
    event_category: "click",
    event_label: `${previousSelection} -> ${newSelection}`
  });
  if (alg == "dir" || alg.startsWith("PB")) {
    $all(".ta-key").forEach(($ta) => $ta.dispatchEvent(new Event("change")));
  }

  if (newSelection != previousSelection) {
    // apply newly selected enc to the displayed header
    editors["token-decoded-header"].save();
    try {
      headerObj = getHeaderFromForm();
      headerObj.enc = newSelection;
      editors["token-decoded-header"].setValue(
        JSON.stringify(headerObj, null, 2)
      );
      saveSetting("sel-enc", newSelection);
    } catch (e) {
      /* gulp */
      console.log("while updating header enc", e);
    }
  }
}

function onChangeAlg(event) {
  const target = event.target,
    newSelection = target.selectedOptions[0].text,
    previousSelection = target.getAttribute("data-prev");
  let headerObj = null;
  const updateHeader = () => {
    try {
      editors["token-decoded-header"].setValue(
        JSON.stringify(headerObj, null, 2)
      );
    } catch (e) {
      /* gulp */
      console.log("while updating header alg", e);
    }
  };

  if (!initialized()) {
    return;
  }
  gtag("event", "changeAlg", {
    event_category: "click",
    event_label: `${previousSelection} -> ${newSelection}`
  });

  editors["token-decoded-header"].save();
  headerObj = getHeaderFromForm();

  maybeNewKey().then((_) => {
    if (newSelection != previousSelection) {
      checkSymmetryChange(newSelection, previousSelection);

      // apply newly selected alg to the displayed header
      headerObj.alg = newSelection;

      if (!keysAreCompatible(newSelection, previousSelection)) {
        $sel("#privatekey .CodeMirror-code").classList.add("outdated");
        $sel("#publickey .CodeMirror-code").classList.add("outdated");
      }
      target.setAttribute("data-prev", newSelection);
    }
    if (!newSelection.startsWith("ECDH")) {
      if (headerObj.epk) {
        delete headerObj.epk;
      }
    }
    if (!newSelection.startsWith("PB")) {
      if (headerObj.p2c) {
        delete headerObj.p2c;
      }
      if (headerObj.p2s) {
        delete headerObj.p2s;
      }
      hide($sel("#pbkdf2_params"));
      $all(".ta-key").forEach(($ta) => $ta.dispatchEvent(new Event("change")));
    }

    if (newSelection.startsWith("PB")) {
      show($sel("#pbkdf2_params"));
      if (!headerObj.p2c) {
        headerObj.p2c = ITERATION_DEFAULT;
      }
      $sel("#ta_pbkdf2_iterations").value = headerObj.p2c;
      if (!headerObj.p2s) {
        headerObj.p2s = PBKDF2_SALT_DEFAULT;
      }
      $sel("#ta_pbkdf2_salt").value = headerObj.p2s;
    }
    updateHeader();
    const variant = $sel("#sel-variant").selectedOptions[0].text.toLowerCase();
    saveSetting("sel-alg-" + variant, newSelection);
  });
}

function onChangeVariant(event) {
  // change signed to encrypted or vice versa
  const target = event.target,
    newSelection = target.selectedOptions[0].text,
    previousSelection = target.getAttribute("data-prev"),
    priorAlgSelection = $sel(".sel-alg").getAttribute("data-prev");

  editors["token-decoded-header"].save();

  gtag("event", "changeVariant", {
    event_category: "click",
    event_label: `${previousSelection} -> ${newSelection}`
  });
  if (newSelection != previousSelection) {
    try {
      const headerObj = getHeaderFromForm();
      if (newSelection == "Encrypted") {
        // swap in alg and enc
        if (!headerObj.alg) {
          headerObj.alg = pickKeyEncryptionAlg({ kty: "RSA" }); // not always !
        }
        if (!headerObj.enc) {
          headerObj.enc = pickContentEncryptionAlg();
        }
        show($sel("#sel-enc"));
      } else {
        hide($sel("#sel-enc")); // not used for signing
        // these fields are defined for use only with signed JWT
        delete headerObj.enc;
        delete headerObj.p2s;
        delete headerObj.p2c;
        delete headerObj.epk;
        // alg will get set later
      }
      editors["token-decoded-header"].setValue(
        JSON.stringify(headerObj, null, 2)
      );
    } catch (_e) {
      /* gulp */
    }
    target.setAttribute("data-prev", newSelection);
  }

  populateAlgorithmSelectOptions();

  // still need this?
  if (
    !priorAlgSelection.startsWith("PS") &&
    !priorAlgSelection.startsWith("RS")
  ) {
    $sel("#privatekey .CodeMirror-code").classList.add("outdated");
    $sel("#publickey .CodeMirror-code").classList.add("outdated");
  }
  saveSetting("sel-variant", newSelection);
}

function contriveJson(segment) {
  if (segment == "payload") {
    const nowSeconds = Math.floor(new Date().valueOf() / 1000),
      sub = rdg.name(),
      aud = rdg.nameExcept(sub),
      payload = {
        iss: "DinoChiesa.github.io",
        sub,
        aud,
        iat: nowSeconds,
        exp: nowSeconds + tenMinutesInSeconds
      };
    if (rdg.boolean()) {
      const propname = rdg.propertyName();
      payload[propname] = rdg.value(null, null, propname);
    }
    return payload;
  }

  const header = { alg: $sel(".sel-alg").selectedOptions[0].text };
  if (keyEncryptionAlgs.indexOf(header.alg) >= 0) {
    if (!header.enc) {
      header.enc = rdg.arrayItem(contentEncryptionAlgs);
    }
  }
  if (rdg.boolean()) {
    header.typ = "JWT";
  }
  if (rdg.boolean()) {
    const propname = rdg.propertyName(),
      type = rdg.typeExcept(["array", "object"]);
    header[propname] = rdg.value(type, 0, propname);
  }
  return header;
}

function newJson(event) {
  const target = event.currentTarget,
    segment = target.getAttribute("data-jsontype"),
    jsonBlob = contriveJson(segment),
    elementId = `token-decoded-${segment}`;
  gtag("event", "newJson", { segment });
  editors[elementId].setValue(JSON.stringify(jsonBlob, null, 2));
}

function contriveJwt(event) {
  const payload = contriveJson("payload"),
    header = contriveJson("header");
  gtag("event", "contriveJwt");
  editors["token-decoded-header"].setValue(JSON.stringify(header));
  editors["token-decoded-payload"].setValue(JSON.stringify(payload));
  encodeJwt(event);
}

function decoratePayload(_instance) {
  const lastComma = new RegExp(",s*$");

  // inspect each property and look for time values
  $all("span.cm-property").forEach((element, _ix) => {
    const label = element.textContent;
    if (['"exp"', '"iat"', '"nbf"'].includes(label)) {
      const valueSpan = element.nextElementSibling;
      if (valueSpan && valueSpan.tagName == "SPAN") {
        const value = valueSpan.textContent.replace(lastComma, ""); // just in case
        // Set attributes for use with bootstrap popover.
        // Cannot use .data() here; it does not update the DOM.
        valueSpan.setAttribute("data-toggle", "popover");
        valueSpan.setAttribute("data-time", value);
      }
    }
  });

  /*
   * For each time value, on hover, show a tooltip with dynamic content,
   * displaying an ISO8601 time string, and a relative time. "5 minutes ago",
   * etc.  The popover element is styled with .bs-popover-right, and it is
   * appended near the end of the DOM. It shows and hides automatically on
   * hover. This is basically a better, more nicely styled title attribute.
   **/

  $all('#payload span[data-toggle="popover"]').forEach((span) => {
    const pop = new Popover(span, {
      placement: "right",
      trigger: "manual", // could not get 'hover' to work properly
      html: true,
      content: function () {
        const value = Number(span.getAttribute("data-time"));
        try {
          const time = new Date(Number(value) * 1000);
          return formatTimeString(time) + " - " + timeAgo(time);
        } catch (_e) {
          // possibly an invalid time
          console.log(`found invalid time value while decoding ${value}`);
          return "looks like an invalid time value";
        }
      }
    });

    const maybeDismiss = () =>
      setTimeout(() => {
        const hoveringOnSpanOrPopover =
          $sel(".popover:hover") || span.querySelector(":hover");
        if (!hoveringOnSpanOrPopover) {
          pop.hide();
        } else {
          maybeDismiss();
        }
      }, 450);

    span.addEventListener("mouseenter", () => {
      pop.show();
      $sel(".popover").addEventListener("mouseleave", maybeDismiss);
    });

    span.addEventListener("mouseleave", maybeDismiss);
  });
}

function looksLikeJwt(possibleJwt) {
  if (!possibleJwt) return false;
  if (possibleJwt == "") return false;
  let matches = re.signed.jwt.exec(possibleJwt);
  if (matches && matches.length == 4) {
    return true;
  }
  matches = re.encrypted.jwt.exec(possibleJwt);
  if (matches && matches.length == 6) {
    return true;
  }
  return false;
}

function retrieveLocalState() {
  Object.keys(datamodel).forEach((key) => {
    const value = storage.get(key);
    if (key.startsWith("chk-")) {
      datamodel[key] = String(value) == "true";
    } else {
      datamodel[key] = value;
    }
  });
}

function saveSetting(key, value) {
  if (key == "sel-alg") {
    key = key + "-" + datamodel["sel-variant"].toLowerCase();
  }
  datamodel[key] = value;
  storage.store(key, value);
}

function applyState() {
  // ordering is important. We must apply variant before alg.
  const keys = Object.keys(datamodel);

  // need the variant to be applied first
  keys.sort((a, b) =>
    a == "sel-variant" ? -1 : b == "sel-variant" ? 1 : a.localeCompare(b)
  );
  keys.forEach((key) => {
    const value = datamodel[key];
    if (value) {
      let $item = $sel("#" + key);
      if (key.startsWith("sel-alg-")) {
        // selection of alg, stored separately for signing and encrypting
        const currentlySelectedVariant = datamodel["sel-variant"];
        if (currentlySelectedVariant) {
          const storedVariant = key.substr(8);
          if (storedVariant == currentlySelectedVariant.toLowerCase()) {
            $item = $sel(`#sel-alg option[value='${value}']`);
            if ($item) {
              $item.selected = true;
            }
          }
        }
      } else if (key.startsWith("sel-symkey-coding")) {
        $item = $sel("#sel-symkey-coding");
        if (key == "sel-symkey-coding-pb") {
          const currentlySelectedAlg = datamodel["sel-alg-encrypted"];
          $item =
            currentlySelectedAlg.startsWith("PB") &&
            $sel(`#sel-symkey-coding option[value='PBKDF2']`);
        } else {
          $item = $sel(`#sel-symkey-coding option[value='${value}']`);
        }
        if ($item) {
          $item.selected = true;
        }
      } else if (key.startsWith("sel-")) {
        // selection
        $item = $sel(`#${key} option[value='${value}']`);
        if ($item) {
          $item.selected = true;
        }
        if (key == "sel-variant") {
          //onChangeVariant.call(document.querySelector("#sel-variant"), null);
          populateAlgorithmSelectOptions();
          $sel("#sel-variant").dispatchEvent(new Event("change"));
        }
      } else if (key.startsWith("chk-")) {
        $item.checked = String(value) == "true";
      } else if (key == "encodedjwt") {
        if (value) {
          parseAndDisplayToken(value);
        }
      } else if (key == "ta_publickey" || key == "ta_privatekey") {
        const keytype = key.substr(3);
        editors[keytype].setValue(value); // will update the visible text area
      } else {
        $item.value = value;
      }
    }
  });

  const currentlySelectedVariant =
    $sel(".sel-variant").selectedOptions[0].text.toLowerCase();
  if (currentlySelectedVariant == "signed") {
    hide($sel("#sel-enc")); // not used for signing
  }
}

function fixupTextInEditor(replacer, editor) {
  editor.save();
  const fieldvalue = replacer(editor.getValue()).trim();
  editor.setValue(fieldvalue);
  editor.save();
  return fieldvalue;
}

const reformNewlines = curry(fixupTextInEditor, (s) => s.replace(/\\n/g, "\n"));
const removeNewlines = curry(fixupTextInEditor, (s) => s.replace(/\s/g, ""));

function parseAndDisplayToken(token) {
  editors.encodedjwt.setValue(token);
  editors.encodedjwt.save();
  showDecoded();
  $sel("#privatekey .CodeMirror-code").classList.add("outdated");
  $sel("#publickey .CodeMirror-code").classList.add("outdated");
}

document.addEventListener("DOMContentLoaded", function () {
  $sel("#version_id").textContent = BUILD_VERSION;

  $all(".btn-copy").forEach((btn) =>
    btn.addEventListener("click", copyToClipboard)
  );
  $sel(".btn-clear").addEventListener("click", clearJwt);
  $sel(".btn-encode").addEventListener("click", encodeJwt);
  $sel(".btn-decode").addEventListener("click", showDecoded);
  $sel(".btn-verify").addEventListener("click", verifyJwt);
  $all(".btn-newkey").forEach((btn) => btn.addEventListener("click", newKey));
  $sel("#btn-new-payload").addEventListener("click", newJson);
  $sel("#btn-new-header").addEventListener("click", newJson);

  populateEncSelectOptions();

  $all(".sel-key-coding").forEach((sel) =>
    sel.addEventListener("change", changeKeyCoding)
  );
  $sel("#mainalert").classList.add("fade");
  $sel("#mainalert").addEventListener("close.bs.alert", closeAlert);

  // editor for the encoded JWT (left hand column)
  editors.encodedjwt = CodeMirror.fromTextArea(
    document.getElementById("encodedjwt"),
    {
      mode: "encodedjwt",
      lineWrapping: true,
      singleCursorHeightPerLine: false
    }
  );
  editors.encodedjwt.on("inputRead", function (_cm, event) {
    /* event -> object{
       origin: string, can be '+input', '+move' or 'paste'
       doc for origins >> http://codemirror.net/doc/manual.html#selection_origin
       from: object {line, ch},
       to: object {line, ch},
       removed: array of removed strings
       text: array of pasted strings
       } */
    if (event.origin == "paste") {
      gtag("event", "paste", {
        event_category: "encodedJwt"
      });

      setTimeout(() => {
        removeNewlines(editors.encodedjwt);
        showDecoded();
      }, 220);
    }
  });
  //editors.encodedjwt.on('renderLine', decorateEncodedToken);

  // create editors for the public and private keys
  ["private", "public"].forEach((flavor) => {
    const keytype = flavor + "key", // private || public
      elementId = "ta_" + keytype;
    editors[keytype] = CodeMirror.fromTextArea(
      document.getElementById(elementId),
      {
        mode: "encodedjwt", // not really, its just plaintext
        lineWrapping: true,
        singleCursorHeightPerLine: false
      }
    );
    editors[keytype].on("inputRead", function (_cm, event) {
      gtag("event", "paste", {
        event_category: keytype
      });
      if (event.origin == "paste") {
        setTimeout(function () {
          const fieldvalue = reformNewlines(editors[keytype]);
          if (looksLikePem(fieldvalue)) {
            editors[keytype].setOption("mode", "encodedjwt");
            updateAsymmetricKeyValue(flavor, reformIndents(fieldvalue));
          } else {
            const possiblyJwks = looksLikeJwks(fieldvalue);
            if (possiblyJwks) {
              editors[keytype].setOption("mode", "javascript");
              const prettyPrintedJson = JSON.stringify(possiblyJwks, null, 2);
              editors[keytype].setValue(prettyPrintedJson);
            } else {
              // meh, not sure what to do here
              // $('#publickey-label').text('Public Key');
              //debugger;
            }
          }
        }, 220);
      }
    });
  });

  // create CM editors for decoded (JSON) payload and header
  ["header", "payload"].forEach((portion) => {
    const elementId = "token-decoded-" + portion;
    editors[elementId] = CodeMirror.fromTextArea(
      document.getElementById(elementId),
      {
        mode: {
          name: "javascript",
          json: true,
          indentWithTabs: false,
          statementIndent: 2,
          indentUnit: 2,
          tabSize: 2
        },
        singleCursorHeightPerLine: false
      }
    );
  });

  // to label fields in the decoded payload. We don't do the same in the header.
  editors["token-decoded-payload"].on("update", decoratePayload);
  hide($sel("#symmetrickey"));
  hide($sel("#pbkdf2_params"));

  // handle inbound query or hash
  let inboundJwt = window.location.hash;
  if (inboundJwt) {
    inboundJwt = inboundJwt.slice(1);
  } else {
    inboundJwt = window.location.search.replace("?", "");
  }

  retrieveLocalState();
  applyState();

  $all(".ta-key").forEach(($ta) => {
    ["change", "keyup", "input"].forEach((eventname) =>
      $ta.addEventListener(eventname, onKeyTextChange)
    );
    $ta.dispatchEvent(new Event("change"));
  });

  $sel("#sel-variant").addEventListener("change", onChangeVariant);
  $sel("#sel-alg").addEventListener("change", onChangeAlg);
  $sel("#sel-enc").addEventListener("change", onChangeEnc);
  $sel("#sel-expiry").addEventListener("change", onChangeExpiry);
  $sel("#chk-iat").addEventListener("change", onChangeCheckbox);
  $sel("#chk-typ").addEventListener("change", onChangeCheckbox);

  if (looksLikeJwt(inboundJwt)) {
    maybeNewKey().then((_) => parseAndDisplayToken(inboundJwt));
  } else if (datamodel.encodedjwt) {
    maybeNewKey();
  } else {
    maybeNewKey().then((_) => contriveJwt());
  }
});
