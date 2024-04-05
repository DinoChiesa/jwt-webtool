// Copyright © 2023-2024 Google LLC.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//

/* jshint esversion:9, node:true, strict:implied */
/* global process, console, Buffer */

const pwStrings = [
  [
    "Vaguely",
    "Undoubtedly",
    "Indisputably",
    "Understandably",
    "Definitely",
    "Possibly"
  ],
  [
    "Salty",
    "Fresh",
    "Ursine",
    "Excessive",
    "Daring",
    "Delightful",
    "Stable",
    "Evolving",
    "Instructive",
    "Engaging"
  ],
  [
    "Mirror",
    "Caliper",
    "Postage",
    "Return",
    "Roadway",
    "Passage",
    "Statement",
    "Toolbox",
    "Paradox",
    "Orbit",
    "Bridge",
    "Artifact",
    "Puzzle"
  ]
];

const sampledata = {
  names: [
    "audrey",
    "olaf",
    "antonio",
    "alma",
    "ming",
    "naimish",
    "anna",
    "sheniqua",
    "tamara",
    "kina",
    "maxine",
    "arya",
    "asa",
    "idris",
    "evander",
    "natalia"
  ],
  props: [
    "propX",
    "propY",
    "aaa",
    "version",
    "entitlement",
    "alpha",
    "classid"
  ],
  types: ["number", "string", "object", "array", "boolean"]
};

function selectRandomValue(a) {
  const L = a.length,
    n = Math.floor(Math.random() * L);
  return a[n];
}

function selectRandomValueExcept(a, exclusion) {
  let v = null;
  if (!exclusion) {
    exclusion = [];
  }
  if (!Array.isArray(exclusion)) {
    exclusion = [exclusion];
  }
  do {
    v = selectRandomValue(a);
  } while (exclusion.indexOf(v) >= 0);
  return v;
}

const string = () =>
  Math.random().toString(36).substring(2, 15) +
  Math.random().toString(36).substring(2, 15);

const boolean = () => Math.floor(Math.random() * 2) == 1;

const number = () => {
  const min = boolean() ? 10 : 100,
    max = boolean() ? 100000 : 1000;
  return Math.floor(Math.random() * (max - min)) + min;
};

const password = (L, noTruncate) => {
  L = L || 23;
  let r = "";
  const totalLength = (items) => items.reduce((a, c) => (a += c.length), 0);
  do {
    const items = pwStrings.map(selectRandomValue);
    while (totalLength(items) < L) {
      items.push(number().toFixed(0).padStart(4, "0").substr(-4));
    }
    r = items.join("-");
    if (!noTruncate) {
      r = r.substring(0, L);
    }
  } while (r.endsWith("-"));
  return r;
};

const array = () => {
  const n = Math.floor(Math.random() * 4) + 1, // at least 1 element
    a = [];
  for (let i = 0; i < n; i++) {
    const vtype = selectRandomValueExcept(sampledata.types, [
      "array",
      "object"
    ]);
    a[i] = value(vtype);
  }
  return a;
};

const typeExcept = (exclusions) =>
  selectRandomValueExcept(sampledata.types, exclusions);
const type = () => typeExcept([]);

const object = (depth, exclusion) => {
  const n = Math.floor(Math.random() * 4) + 1,
    obj = {};
  for (let i = 0; i < n; i++) {
    const propname = selectRandomValueExcept(sampledata.props, exclusion);
    // limit complexity
    const dtype = depth > 1 ? typeExcept(["array", "object"]) : type();
    obj[propname] = value(dtype, depth, propname);
  }
  return obj;
};

const value = (vtype, depth, parentName) => {
  vtype = vtype || type();
  depth = typeof depth == "number" ? depth + 1 : 1;
  switch (vtype) {
    case "number":
      return number();
    case "string":
      return string();
    case "array":
      return array();
    case "object":
      return object(depth, parentName);
    case "boolean":
      return boolean();
  }
  return null;
};

function octetKey(L) {
  L = L || 48;
  const array = new Uint8Array(L);
  window.crypto.getRandomValues(array);
  return array;
}

const passphrase = () => password(0, true);
const name = () => selectRandomValue(sampledata.names);
const nameExcept = (v) => selectRandomValueExcept(sampledata.names, v);
const propertyName = () => selectRandomValue(sampledata.props);
const arrayItem = (a) => selectRandomValue(a);

export default {
  string,
  boolean,
  number,
  password,
  array,
  object,
  value,
  octetKey,
  passphrase,
  name,
  nameExcept,
  propertyName,
  type,
  typeExcept,
  arrayItem
};
