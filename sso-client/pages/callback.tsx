import Head from "next/head";
import Image from "next/image";
import { useRouter } from "next/router";
import { Inter } from "@next/font/google";
import styles from "../styles/Home.module.css";
import { useEffect } from "react";

const inter = Inter({ subsets: ["latin"] });

const Callback = () => {
  const router = useRouter();

  useEffect(() => {
    console.log(router.query);
    const authCode = router.query["authorization_code"];
    if (authCode) {
      const requestOptions = {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: "Bearer l1Q7zkOL59cRqWBkQ12ZiGVW2DBL",
        },
        body: JSON.stringify({
          grantType: "authorization_code",
          authorizationCode: authCode,
          clientID: "client1234",
          clientSecret: "CLIENT_SECRET",
          redirectUrl: "http://localhost:3000/callback",
        }),
      };
      fetch("http://localhost:8000/oauth/token", requestOptions).then(
        (res: Response) => {
          if (res.status === 200) {
            // store access token in cookie
            // res.headers.append('Set-Cookie', res.)
            const data = res.json().then((j) => {
              console.log(j);
            });
          }
        }
      );
    }
  }, [router.query]);

  return (
    <>
      <Head>
        <title>Create Next App</title>
        <meta name="description" content="Generated by create next app" />
        <meta name="viewport" content="width=device-width, initial-scale=1" />
        <link rel="icon" href="/favicon.ico" />
      </Head>
      <main className={styles.main}>
        <h3>Redirecting...</h3>
      </main>
    </>
  );
};

export default Callback;
