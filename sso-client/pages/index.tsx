import Head from "next/head";
import Image from "next/image";
import { Inter } from "@next/font/google";
import styles from "../styles/Home.module.css";

const inter = Inter({ subsets: ["latin"] });

export default function Home() {
  return (
    <>
      <Head>
        <title>Create Next App</title>
        <meta name="description" content="Generated by create next app" />
        <meta name="viewport" content="width=device-width, initial-scale=1" />
        <link rel="icon" href="/favicon.ico" />
      </Head>
      <main className={styles.main}>
        <h3>
          <a href="http://localhost:3001/oauth?response_type=code&client_id=client_id&redirect_url=http://localhost:3000/callback">
            Sign in with Authorization Server
          </a>
        </h3>
      </main>
    </>
  );
}
