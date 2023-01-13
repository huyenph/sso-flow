"use strict";
const fs = require("fs");
const p = require("path");
const privateKeyFilePath = p.resolve(__dirname, "./jwtRS256.key");
const privateCert = fs.readFileSync(privateKeyFilePath);
console.log(privateCert);
module.exports = privateCert;
