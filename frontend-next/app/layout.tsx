import "./globals.css";
import type { Metadata } from "next";
import { ReactNode } from "react";
import { AuthSyncListener } from "@/components/providers/auth-sync-listener";
import { KeyStorageBootstrap } from "@/components/providers/key-storage-bootstrap";

export const metadata: Metadata = {
  title: "University Messenger",
  description: "Secure instant messaging dashboard scaffold",
};

export default function RootLayout({ children }: { children: ReactNode }) {
  return (
    <html lang="en">
      <body>
        <KeyStorageBootstrap />
        <AuthSyncListener />
        {children}
      </body>
    </html>
  );
}
