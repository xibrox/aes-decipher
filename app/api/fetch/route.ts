import { NextRequest, NextResponse } from "next/server";
import crypto from "crypto";

export async function POST(req: NextRequest) {
  try {
    const { url, method = "GET", body = null } = await req.json();

    if (!url) {
      return NextResponse.json({ error: "Missing url" }, { status: 400 });
    }

    // --- 1. generate AES key + IV
    const aesKey = crypto.randomBytes(32).toString("hex"); // 256-bit
    const aesIv = crypto.randomBytes(16).toString("hex");  // 128-bit

    // --- 2. fetch from VidNest
    const response = await fetch(url, {
      method,
      headers: {
        "Referer": "https://vidnest.fun/",
        "Origin": "https://vidnest.fun",
        "x-aes-key": aesKey,
        "x-aes-iv": aesIv,
        "Content-Type": "application/json",
      },
      body: body ? JSON.stringify(body) : undefined,
    });

    const json = await response.json();

    // --- 3. auto-decrypt if cipher is present
    if (json?.cipher) {
      try {
        const decipher = crypto.createDecipheriv(
          "aes-256-cbc",
          Buffer.from(aesKey, "hex"),
          Buffer.from(aesIv, "hex")
        );

        let decrypted = decipher.update(json.cipher, "base64", "utf8");
        decrypted += decipher.final("utf8");

        return NextResponse.json({ result: JSON.parse(decrypted) });
      } catch (err) {
        return NextResponse.json({ error: "Failed to decrypt", details: (err as Error).message }, { status: 500 });
      }
    }

    // --- 4. plain response
    return NextResponse.json({ result: json });
  } catch (err) {
    const message = err instanceof Error ? err.message : "Unknown error";
    return NextResponse.json({ error: message }, { status: 500 });
  }
}
