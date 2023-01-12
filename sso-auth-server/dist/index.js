"use strict";
const express = require("express");
const { NextFunction, Request, Response } = require("express");
const session = require("express-session");
const mysql = require("mysql2");
const bcrypt = require("bcrypt");
const path = require("path");
const CryptoJS = require("crypto-js");
const bodyParser = require("body-parser");
const app = express();
const router = express.Router();
app.use(bodyParser.json());
app.use(express.urlencoded());
app.use((_, res, next) => {
    res.setHeader("Access-Control-Allow-Origin", "*");
    res.setHeader("Access-Control-Allow-Methods", "GET,POST,PUT,DELETE,PATCH");
    res.setHeader("Access-Control-Allow-Headers", "Content-Type");
    next();
});
app.use(session({
    resave: true,
    saveUninitialized: true,
    secret: "secretkey",
    cookie: { maxAge: 60000, secure: true },
}));
app.use("/", router);
const connection = mysql.createConnection({
    host: "localhost",
    user: "root",
    password: "rootpass",
    database: "sso_flow",
});
router.get("/", (req, res) => {
    // req.session.accessToken = "accessToken key";
    console.log(req.session);
    if (req.session.accessToken) {
    }
    else {
        res.redirect("/auth");
    }
});
router.get("/auth", (req, res) => {
    // req.session.accessToken = "accessToken key";
    console.log(req.session);
    if (req.session.accessToken) {
        res.redirect("/");
    }
    else {
        res.sendFile(path.join(__dirname + "/auth.html"));
    }
});
router.post("/signin", (req, res) => {
    const username = req.body.username;
    const password = req.body.password;
    const clientId = req.body.client_id;
    const redirectUrl = req.body.redirect_url;
    connection.execute(`SELECT password FROM Users WHERE username = "${username}"`, (err, results, fields) => {
        if (results.length > 0) {
            bcrypt.compare(password, results[0]["password"], (err, result) => {
                checkCredential(result, clientId, redirectUrl, res);
            });
        }
    });
});
router.post("/token", (req, res) => {
    console.log(req.body);
});
const checkCredential = (result, clientId, redirectUrl, res) => {
    if (result) {
        const code = generateAuthorizationCode(clientId, redirectUrl);
        console.log(code);
        res.redirect(redirectUrl + `?authorization_code=${code}`);
    }
};
const generateAuthorizationCode = (clientId, redirectUrl) => {
    return CryptoJS.AES.encrypt(JSON.stringify({
        client_id: clientId,
        redirect_url: redirectUrl,
        exp: Date.now() + 600,
    }), "secretKey").toString();
};
app.listen(3001, () => {
    console.log("Server listening on PORT 3001");
});
// bcrypt.genSalt(10, (err: any, salt: any) => {
//   bcrypt.hash(password, salt, (err: any, hash: string) => {
//     connection.execute(
//       "INSERT INTO Users (userID, username, password, email, role) VALUES (?,?,?,?,?)",
//       [
//         "a5860b36-8573-4500-9d0a-d6ee6ff891a7",
//         "user 4",
//         hash,
//         "user4@gmail.com",
//         "Tier3",
//       ],
//       (err: any, results: any, fields: any) => {}
//     );
//   });
// });
