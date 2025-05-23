const CryptoJS = require("crypto-js");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const cert = require("./key/index");

const sessionUser = <object>{};
const sessionClient = <object>{};
var intermediateTokenCache = <object>{};

const originName = {
  "http://localhost:3000": "client_1",
  "http://localhost:3002": "client_2",
};

const alloweOrigin = {
  "http://localhost:3000": true,
  "http://localhost:3002": true,
};

const appTokenDB = {
  client_1: "l1Q7zkOL59cRqWBkQ12ZiGVW2DBL",
  client_2: "1g0jJwGmRQhJwvwNOrY4i90kD0m",
};

const SECRET_KEY = "secretKey";

const generateAuthorizationCode = (clientId: string, redirectUrl: string) => {
  return CryptoJS.AES.encrypt(
    JSON.stringify({
      client_id: clientId,
      redirect_url: redirectUrl,
      exp: Date.now() + 600,
    }),
    SECRET_KEY
  ).toString();
};

const authenticateClient = (clientId: string, clientSecret: string) => {
  // check credential here
  return true;
};

const verifyAuthorizationCode = (
  bearerCode: string,
  authCode: string,
  clientId: string,
  redirectUrl: string
) => {
  console.log(authCode);
  const ssoCode = authCode.replace(/\s/g, "+");
  const clientName = (intermediateTokenCache as any)[ssoCode][1];
  const globalSessionToken = (intermediateTokenCache as any)[ssoCode][0];

  if (bearerCode.replace("Bearer ", "") !== (appTokenDB as any)[clientName]) {
    return false;
  }

  if (authCode === undefined) {
    return false;
  }

  if (!(sessionClient as any)[globalSessionToken].includes(clientName)) {
    return false;
  }

  const authData = JSON.parse(
    CryptoJS.AES.decrypt(ssoCode, SECRET_KEY).toString(CryptoJS.enc.Utf8)
  );
  console.log(authData);
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

const generateAccessToken = (
  authCode: string,
  clientId: string,
  clientSecret: string
) => {
  const ssoCode: string = authCode.replace(/\s/g, "+");
  const globalSessionToken: string = (intermediateTokenCache as any)[
    ssoCode
  ][0];
  const userInfo: UserType = (sessionUser as any)[globalSessionToken];
  return jwt.sign(
    {
      client_id: clientId,
      client_secret: clientSecret,
      user: userInfo,
    },
    cert,
    {
      algorithm: "RS256",
      expiresIn: "1h",
      issuer: "sso-auth-server",
    }
  );
};

const storeClientInCache = (
  redirectUrl: string,
  userId: string,
  token: string
) => {
  const originUrl: string = new URL(redirectUrl).origin;
  if ((sessionClient as any)[userId] === undefined) {
    (sessionClient as any)[userId] = [(originName as any)[originUrl]];
  } else {
    const clients: object[] = [...(sessionClient as any)[userId]];
    clients.push((originName as any)[originUrl]);
    (sessionClient as any)[userId] = clients;
  }
  console.log("sessionClient");
  console.log(sessionClient);
  intermediateTokenCache = {
    ...intermediateTokenCache,
    [token]: [userId, (originName as any)[originUrl]],
  };
  console.log("intermediateTokenCache");
  console.log(intermediateTokenCache);
};

enum UserRole {
  "Admin",
  "Tier1",
  "Tier2",
  "Tier3",
}

type UserType = {
  userId: string;
  username: string;
  email: string;
  role: UserRole;
};

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
  callback: (userType: UserType) => void
) => {
  connection.execute(
    `SELECT * FROM Users WHERE username = "${username}" AND password = "${password}"`,
    (err: any, results: any, fields: any) => {
      if (results.length > 0) {
        const user: UserType = {
          userId: results[0]["userID"],
          username: results[0]["username"],
          email: results[0]["email"],
          role: results[0]["role"],
        };
        callback(user);
        // bcrypt.compare(
        //   password,
        //   results[0]["password"],
        //   (err: any, result: any) => {
        //     if (result) {
        //       const user: UserType = {
        //         userId: results[0]["userID"],
        //         username: results[0]["username"],
        //         email: results[0]["email"],
        //         role: results[0]["role"],
        //       };
        //       callback(user);
        //     }
        //   }
        // );
      }
    }
  );
};

module.exports = {
  sessionUser,
  sessionClient,
  intermediateTokenCache,
  originName,
  alloweOrigin,
  generateAuthorizationCode,
  checkCredential,
  authenticateClient,
  verifyAuthorizationCode,
  storeClientInCache,
  generateAccessToken,
  insertUser,
};
