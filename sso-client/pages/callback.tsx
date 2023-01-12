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
    const authCode = router.query;
    if (authCode) {
      const requestOptions = {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          grant_type: "authorization_code",
          authorization_code: authCode,
          client_id: "CLIENT_ID",
          client_secret: "CLIENT_SECRET",
          redirect_url: "http://localhost:3000/callback",
        }),
      };
      fetch("http://localhost:3001/token", requestOptions).then(
        (res: Response) => {
          console.log(res);
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