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

app.use(
  (_: typeof Request, res: typeof Response, next: typeof NextFunction) => {
    res.setHeader("Access-Control-Allow-Origin", "*");
    res.setHeader("Access-Control-Allow-Methods", "GET,POST,PUT,DELETE,PATCH");
    res.setHeader("Access-Control-Allow-Headers", "Content-Type");
    next();
  }
);

app.use(
  session({
    resave: true,
    saveUninitialized: true,
    secret: "secretkey",
    cookie: { maxAge: 60000, secure: true },
  })
);

app.use("/", router);

const connection = mysql.createConnection({
  host: "localhost",
  user: "root",
  password: "rootpass",
  database: "sso_flow",
});

router.get("/", (req: typeof Request, res: typeof Response) => {
  // req.session.accessToken = "accessToken key";
  console.log(req.session);
  if (req.session.accessToken) {
  } else {
    res.redirect("/auth");
  }
});

router.get("/authorize", (req: typeof Request, res: typeof Response) => {
  // req.session.accessToken = "accessToken key";
  console.log(req.session);
  if (req.session.accessToken) {
    res.redirect("/");
  } else {
    res.sendFile(path.join(__dirname + "/auth.html"));
  }
});

router.post("/signin", (req: typeof Request, res: typeof Response) => {
  const username = req.body.username;
  const password = req.body.password;
  const clientId = req.body.client_id;
  const redirectUrl = req.body.redirect_url;

  connection.execute(
    `SELECT password FROM Users WHERE username = "${username}"`,
    (err: any, results: any, fields: any) => {
      if (results.length > 0) {
        bcrypt.compare(
          password,
          results[0]["password"],
          (err: any, result: any) => {
            if (result) {
              const code = generateAuthorizationCode(clientId, redirectUrl);
              res.redirect(redirectUrl + `?authorization_code=${code}`, 302);
            }
          }
        );
      }
    }
  );
});

router.post("/token", (req: typeof Request, res: typeof Response) => {
  if (req.body) {
    const { authorization_code, client_id, client_secret, redirect_url } =
      req.body;
    // authenticate client
    // verify authentication code
  }
});

const generateAuthorizationCode = (clientId: string, redirectUrl: string) => {
  return CryptoJS.AES.encrypt(
    JSON.stringify({
      client_id: clientId,
      redirect_url: redirectUrl,
      exp: Date.now() + 600,
    }),
    "secretKey"
  ).toString();
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
