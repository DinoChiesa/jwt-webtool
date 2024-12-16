# JWT Web tool

This is the source code for a web tool that can decode JWT, verify signed JWT,
decrypt encrypted JWT, and create signed or encrypted JWT. It works nicely for
lots of cases.  It also has a few limitations; details below.

![screengrab](images/screenshot-20191115-083624.png)

## License

This code is Copyright (c) 2019-2024 Google LLC, and is released under the Apache
Source License v2.0. For information see the [LICENSE](LICENSE) file.

## Purpose

I built this as a tool that might be helpful to developers learning JWT, or
experimenting with ways to use JWT.  The output of this repo is currently
running [here](https://dinochiesa.github.io/jwt/).

## Disclaimer

This tool is not an official Google product, nor is it part of an official
Google product.

## Limitations

This tool has some limitations:
 - For signed JWT, the tool handles JWT that use ECDSA (ES256, ES384, ES512),
   RSA (RS256, RS384, RS512, PS256, PS384, PS512) or HMAC algorithms (HS256,
   HS384, HS512).

 - For encrypted JWT, specifically for key encryption, it handles JWT that use
   RSA keys and RSA algorithms (RSA-OAEP, RSA-OAEP-256), JWT that use EC keys
   and various ECDH algorithms (ECDH-ES, ECDH-ES+A128KW, ECDH-ES+A256KW) as well
   as JWT that use the PBES2 algorithms. It does not currently support the "dir"
   alg type. It supports all types of enc algorithms.

 - With either signed or encrypted JWT, this tool explicitly ignores crit headers.

 - This tool will not extract the certificate from an x5c header. Nor will it check
   thumbprints of an x5t header.

 - This tool uses EcmaScript v9, and webcrypto, which means it will run only on
   modern, current browsers.

## Design

This is a single-page web app. It has no "backend" supporting it. All JWT
signing and verifying, or encrypting or decrypting, happens within the browser.
Anything a user pastes into the UI never leaves the browser. It just needs a few
static files.

There's a shortcut: if you open the url with <baseurl>?JWT_HERE, it will decode *that* JWT.   It
saves you a step, pasting in your own JWT. If you're paranoid you can also use
the # as a separator.

You may want to fork this and bundle it into an intranet, to allow developers
within a company to experiment with JWT. You can also run it from a file:// URL.

From my perspective, there's no security issue with using the [publicly hosted
tool](https://dinochiesa.github.io/jwt/), but your company's security auditors
may not agree..

## Dependencies

The web app depends on
* [Bootstrap 5.0](https://getbootstrap.com/docs/5.0) - for UI and styling
* [node-jose](https://github.com/cisco/node-jose) - for JWT
* [CodeMirror](https://codemirror.net/) - for the in-browser editors
* [webcrypto](https://developer.mozilla.org/en-US/docs/Web/API/Web_Crypto_API) - for generating RSA and ECDSA keys


## Build Dependencies

This tool uses [webpack v5](https://webpack.js.org/) for bundling the assets.


## Please send pull requests

Constructive feedback is always appreciated.
PR's will be appreciated.


## Developing

If you fork this repo to mess with the code, here's what I advise.

Before you do anything you need to install the dependencies.

```
npm install
```

To build a "development" distribution:

```
npm run devbuild
```

This build will allow you to run the page and debug with the browser dev tools,
and see the original source lines in your in-browser debugger. You can load the
page via a file:/// url, and it will work just fine. For that, open a Chrome
browser tab (or whatever browser you use) to
file:///path/to/dist/index.html .

During development, I prefer to use the webpack "watch" capability, which
rebuilds as I modify the source code. To do that, execute this in a terminal:

```
npm run watch
```

The above command will run "forever", and will rebundle when any source file
changes. When you save a file, wait a few seconds for the build, maybe 5
seconds, and then just click the reload button in the browser tab, to see the
updates.


To build a production distribution:

```
npm run build
```

## Bugs / Feature Gaps

* For verification of signed JWT, or creation of encrypted JWT, it is not
  possible to use an x509v3 certificate for the source of the public key. You
  need to extract the public key yourself.
