"use client";

import { useEffect, useState } from "react";

const API_URL = process.env.NEXT_PUBLIC_API_URL ?? "http://localhost:8000";

export default function Home() {
  const [status, setStatus] = useState("Checking backend...");

  useEffect(() => {
    fetch(`${API_URL}/api/health`)
      .then((r) => r.json())
      .then((d) => setStatus(`${d.status}: ${d.message}`))
      .catch(() => setStatus("Backend unreachable"));
  }, []);

  return (
    <main className="flex flex-1 flex-col items-center justify-center gap-4 p-8">
      <h1 className="text-3xl font-bold">Local AI Security Log Analyzer</h1>
      <p className="text-zinc-500">Backend status: {status}</p>
    </main>
  );
}
