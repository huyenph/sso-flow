"use strict";
const CryptoJS = require("crypto-js");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const cert = require("./key/index");
const sessionUser = {};
const sessionApp = {};
const intermediateTokenCache = {};
const originName = {
    "http://localhost:3000": "client_1",
    "http://localhost:3002": "client_2",
};
const alloweOrigin = {
    "http://localhost:3000": true,
    "http://localhost:3002": false,
};
const appTokenDB = {
    client_1: "l1Q7zkOL59cRqWBkQ12ZiGVW2DBL",
    client_2: "1g0jJwGmRQhJwvwNOrY4i90kD0m",
};
const SECRET_KEY = "secretKey";
const generateAuthorizationCode = (clientId, redirectUrl) => {
    return CryptoJS.AES.encrypt(JSON.stringify({
        client_id: clientId,
        redirect_url: redirectUrl,
        exp: Date.now() + 600,
    }), SECRET_KEY).toString();
};
const authenticateClient = (clientId, clientSecret) => {
    // check credential here
    return true;
};
const verifyAuthorizationCode = (bearerCode, authCode, clientId, redirectUrl) => {
    const ssoCode = authCode.replace(/\s/g, "+");
    const clientName = intermediateTokenCache[ssoCode][1];
    const globalSessionToken = intermediateTokenCache[ssoCode][0];
    if (bearerCode.replace("Bearer ", "") !== appTokenDB[clientName]) {
        return false;
    }
    if (authCode === undefined) {
        return false;
    }
    if (sessionApp[globalSessionToken][clientName] !== true) {
        return false;
    }
    const authData = JSON.parse(CryptoJS.AES.decrypt(ssoCode, SECRET_KEY).toString(CryptoJS.enc.Utf8));
    if (authData) {
        const { client_id, redirect_url, exp } = authData;
        if (clientId !== client_id || redirect_url !== redirectUrl) {
            return false;
        }
        if (exp < Date.now()) {
            return false;
        }
        return true;
    }
    return false;
};
const generateAccessToken = (authCode, clientId, clientSecret) => {
    const ssoCode = authCode.replace(/\s/g, "+");
    const globalSessionToken = intermediateTokenCache[ssoCode][0];
    const userInfo = sessionUser[globalSessionToken];
    return jwt.sign({
        client_id: clientId,
        client_secret: clientSecret,
        user: userInfo,
    }, cert, {
        algorithm: "RS256",
        expiresIn: "1h",
        issuer: "sso-auth-server",
    });
};
const storeAppInCache = (redirectUrl, userId, token) => {
    const originUrl = new URL(redirectUrl).origin;
    if (sessionApp[userId] === undefined) {
        sessionApp[userId] = {
            [originName[originUrl]]: true,
        };
    }
    else {
        sessionApp[userId][originName[originUrl]] = true;
    }
    intermediateTokenCache[token] = [
        userId,
        originName[originUrl],
    ];
};
var UserRole;
(function (UserRole) {
    UserRole[UserRole["Admin"] = 0] = "Admin";
    UserRole[UserRole["Tier1"] = 1] = "Tier1";
    UserRole[UserRole["Tier2"] = 2] = "Tier2";
    UserRole[UserRole["Tier3"] = 3] = "Tier3";
})(UserRole || (UserRole = {}));
const insertUser = (userID, username, password, email, role) => {
    bcrypt.genSalt(10, (err, salt) => {
        bcrypt.hash(password, salt, (err, hash) => {
            connection.execute("INSERT INTO Users (userID, username, password, email, role) VALUES (?,?,?,?,?)", [userID, username, hash, email, role], (err, results, fields) => { });
        });
    });
};
const checkCredential = (connection, username, password, callback) => {
    connection.execute(`SELECT * FROM Users WHERE username = "${username}"`, (err, results, fields) => {
        if (results.length > 0) {
            bcrypt.compare(password, results[0]["password"], (err, result) => {
                if (result) {
                    const user = {
                        userId: results[0]["userID"],
                        username: results[0]["username"],
                        email: results[0]["email"],
                        role: results[0]["role"],
                    };
                    callback(user);
                }
            });
        }
    });
};
module.exports = {
    sessionUser,
    sessionApp,
    intermediateTokenCache,
    originName,
    alloweOrigin,
    generateAuthorizationCode,
    checkCredential,
    authenticateClient,
    verifyAuthorizationCode,
    storeAppInCache,
    generateAccessToken,
    insertUser,
};
