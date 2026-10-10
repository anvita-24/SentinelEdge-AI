import "./globals.css";
import type { ReactNode } from "react";

export const metadata = { title: "SentinelEdge AI", description: "Agentic IoT security and operations" };

export default function RootLayout({ children }: { children: ReactNode }) {
  return (<html lang="en"><body>{children}</body></html>);
}
