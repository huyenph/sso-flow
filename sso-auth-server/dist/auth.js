"use strict";
const CryptoJS = require("crypto-js");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const sessionUser = {};
const sessionApp = {};
const intrmTokenCache = {};
const appName = {
    "http://localhost:3000": "client_1",
    "http://localhost:3003": "client_2",
};
const allowUrl = {
    "http://localhost:3000": true,
    "http://localhost:3003": false,
};
const generateAuthorizationCode = (clientId, redirectUrl) => {
    return CryptoJS.AES.encrypt(JSON.stringify({
        client_id: clientId,
        redirect_url: redirectUrl,
        exp: Date.now() + 600,
    }), "secretKey").toString();
};
const authenticateClient = (clientId, clientSecret) => {
    // check credential here
    return true;
};
const verifyAuthorizationCode = (authCode, clientId, redirectUrl) => {
    if (!authCode) {
        return false;
    }
    const authData = JSON.parse(CryptoJS.AES.decrypt(authCode.replace(/\s/g, "+"), "secretKey").toString(CryptoJS.enc.Utf8));
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
const generateAccessToken = (clientId, clientSecret) => {
    return jwt.sign({
        client_id: clientId,
        client_secret: clientSecret,
        issuer: "auth-server",
        exp: Date.now() + 1800,
    }, "secretKey");
};
const storeAppInCache = (redirectUrl, userId, token) => {
    const originUrl = new URL(redirectUrl).origin;
    if (sessionApp[userId] === undefined) {
        sessionApp[userId] = {
            [appName[originUrl]]: true,
        };
    }
    else {
        sessionApp[userId][appName[originUrl]] = true;
    }
    intrmTokenCache[token] = [userId, appName[originUrl]];
    console.log(sessionApp);
    console.log(intrmTokenCache);
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
    intrmTokenCache,
    appName,
    allowUrl,
    generateAuthorizationCode,
    checkCredential,
    authenticateClient,
    verifyAuthorizationCode,
    storeAppInCache,
    generateAccessToken,
    insertUser,
};
