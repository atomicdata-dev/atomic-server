import type { Metadata } from "next";
import "./globals.css";
import ProviderWrapper from "@/components/ProviderWrapper";
import VStack from "@/components/Layout/VStack";
import Navbar from "@/components/Navbar";
import styles from "./layout.module.css";
import Footer from "@/components/Footer";
import Container from "@/components/Layout/Container";

export const metadata: Metadata = {
  title: "Next.js Atomic",
  description: "Next.js Atomic template",
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en">
      <body>
        <ProviderWrapper>
          <VStack align="stretch" height="100vh">
            <header>
              <Navbar />
            </header>
            <main className={styles.main}>{children}</main>
            <Footer />
          </VStack>
        </ProviderWrapper>
      </body>
    </html>
  );
}
