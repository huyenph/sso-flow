const CryptoJS = require("crypto-js");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");

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

const authenticateClient = (clientId: string, clientSecret: string) => {
  // check credential here
  return true;
};

const verifyAuthorizationCode = (
  authCode: string,
  clientId: string,
  redirectUrl: string
) => {
  if (!authCode) {
    return false;
  }
  const authData = JSON.parse(
    CryptoJS.AES.decrypt(authCode.replace(/\s/g, "+"), "secretKey").toString(
      CryptoJS.enc.Utf8
    )
  );
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

const generateAccessToken = (clientId: string, clientSecret: string) => {
  return jwt.sign(
    {
      client_id: clientId,
      client_secret: clientSecret,
      issuer: "auth-server",
      exp: Date.now() + 1800,
    },
    "secretKey"
  );
};

enum UserRole {
  "Admin",
  "Tier1",
  "Tier2",
  "Tier3",
}

const insertUser = (
  userID: string,
  username: string,
  password: string,
  email: string,
  role: UserRole
) => {
  bcrypt.genSalt(10, (err: any, salt: any) => {
    bcrypt.hash(password, salt, (err: any, hash: string) => {
      connection.execute(
        "INSERT INTO Users (userID, username, password, email, role) VALUES (?,?,?,?,?)",
        [userID, username, hash, email, role],
        (err: any, results: any, fields: any) => {}
      );
    });
  });
};

const checkCredential = (
  connection: any,
  username: string,
  password: string,
  callback: () => void
) => {
  connection.execute(
    `SELECT password FROM Users WHERE username = "${username}"`,
    (err: any, results: any, fields: any) => {
      if (results.length > 0) {
        bcrypt.compare(
          password,
          results[0]["password"],
          (err: any, result: any) => {
            if (result) {
              callback();
            }
          }
        );
      }
    }
  );
};

module.exports = {
  generateAuthorizationCode,
  checkCredential,
  authenticateClient,
  verifyAuthorizationCode,
  generateAccessToken,
  insertUser,
};
