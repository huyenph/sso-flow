const express = require("express");
const { NextFunction, Request, Response } = require("express");
const session = require("express-session");
const mysql = require("mysql2");
const path = require("path");
const bodyParser = require("body-parser");
const authModule = require("./auth");

const app = express();
const router = express.Router();

app.use(bodyParser.json());
app.use(express.urlencoded());
app.use(
  (_: typeof Request, res: typeof Response, next: typeof NextFunction) => {
    res.setHeader("Access-Control-Allow-Origin", "*");
    res.setHeader("Access-Control-Allow-Methods", "GET,POST,PUT,DELETE,PATCH");
    res.setHeader("Access-Control-Allow-Headers", "*");
    next();
  }
);
app.use(
  session({
    resave: true,
    saveUninitialized: true,
    secret: "secretkey",
    // cookie: { secure: true },
  })
);
app.use("/", router);

const connection = mysql.createConnection({
  host: "localhost",
  user: "root",
  password: "rootpass",
  database: "sso_flow",
});

router.get("/oauth", (req: typeof Request, res: typeof Response) => {
  const originUrl = new URL(req.query["redirect_url"]).origin;
  if (originUrl) {
    if (!authModule.alloweOrigin[originUrl]) {
      return res
        .status(400)
        .send({ message: "You are not allow to access SSO server" });
    }
    if (req.session.user !== undefined) {
      const code = authModule.generateAuthorizationCode(
        req.session.user,
        req.query["redirect_url"]
      );
      authModule.storeClientInCache(
        req.query["redirect_url"],
        req.session.user,
        code
      );
      // redirect to client with an authorization token
      res.redirect(
        302,
        req.query["redirect_url"] + `?authorization_code=${code}`
      );
    } else {
      res.redirect("/oauth/authorize");
    }
  } else {
    return res.status(400).send({ message: "Invalid client" });
  }
});

router.get("/oauth/authorize", (req: typeof Request, res: typeof Response) => {
  res.sendFile(path.join(__dirname + "/auth.html"));
});

router.post("/oauth/signin", (req: typeof Request, res: typeof Response) => {
  const username = req.body.username;
  const password = req.body.password;
  const clientId = req.body.client_id;
  const redirectUrl = req.body.redirect_url;

  authModule.checkCredential(
    connection,
    username,
    password,
    (userType: UserType) => {
      // create global session here
      req.session.user = userType.userId;
      (authModule.sessionUser as any)[userType.userId] = userType;
      if (redirectUrl === null) {
        return res.redirect("/");
      }

      // create authorization token
      const code = authModule.generateAuthorizationCode(clientId, redirectUrl);
      authModule.storeClientInCache(redirectUrl, userType.userId, code);

      // redirect to client with an authorization token
      res.redirect(302, redirectUrl + `?authorization_code=${code}`);
    }
  );
});

router.post("/oauth/token", (req: typeof Request, res: typeof Response) => {
  if (req.body) {
    const { authorization_code, client_id, client_secret, redirect_url } =
      req.body;

    if (!authModule.authenticateClient(client_id, client_secret)) {
      return res.status(400).send({ message: "Invalid client" });
    }

    if (
      !authModule.verifyAuthorizationCode(
        req.get("Authorization"),
        authorization_code,
        client_id,
        redirect_url
      )
    ) {
      return res.status(400).send({ message: "Access denied" });
    }

    const token = authModule.generateAccessToken(
      authorization_code,
      client_id,
      client_secret
    );
    return res.status(200).send({
      access_token: token,
      token_type: "JWT",
    });
  } else {
    return res.status(400).send({ message: "Invalid request" });
  }
});

app.listen(8000, () => {
  console.log("Server listening on PORT 8000");
});
