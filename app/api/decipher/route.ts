import { NextRequest, NextResponse } from "next/server";

// --- Decryption Helpers ---
async function decipherFetchResponse(json: { cipher: string; aes: string; iv: string }) {
  const decryptedJson = await decrypt(json.cipher, json.aes, json.iv);
  try {
    return JSON.parse(decryptedJson);
  } catch {
    return decryptedJson;
  }
}

async function decrypt(cipher: string, AES_KEY: string, AES_IV: string) {
  if (!AES_KEY || !AES_IV) {
    throw new Error("Missing AES key or IV");
  }

  const UInt8_IV = new TextEncoder().encode(AES_IV);
  if (UInt8_IV.length !== 16) {
    throw new Error("AES_IV must be 16 bytes");
  }

  const cryptoKey = await getCryptoKey(AES_KEY);
  const parsedCipher = parseCipherText(cipher);

  const decrypted = await crypto.subtle.decrypt(
    {
      name: "AES-CBC",
      iv: UInt8_IV,
    },
    cryptoKey,
    parsedCipher
  );

  return new TextDecoder().decode(new Uint8Array(decrypted));
}

async function getCryptoKey(AES_KEY: string) {
  const UInt8_KEY = new TextEncoder().encode(AES_KEY);

  if (UInt8_KEY.length !== 16 && UInt8_KEY.length !== 32) {
    throw new Error("AES_KEY must be 16 or 32 bytes");
  }

  return crypto.subtle.importKey(
    "raw",
    UInt8_KEY,
    { name: "AES-CBC" },
    false,
    ["decrypt"]
  );
}

function parseCipherText(cipher_internal: string) {
  const cleanCipher = cipher_internal.replace(/[^0-9a-fA-F]/g, "");
  if (cleanCipher.length % 2 !== 0) {
    throw new Error("Invalid hex");
  }

  const cypherBytes = new Uint8Array(cleanCipher.length / 2);
  for (let i = 0; i < cypherBytes.length; i++) {
    cypherBytes[i] = parseInt(cleanCipher.substr(2 * i, 2), 16);
  }

  return cypherBytes;
}

// --- API Route ---
export async function POST(req: NextRequest) {
  try {
    const body = (await req.json()) as { cipher?: string; aes?: string; iv?: string };
    const { cipher, aes, iv } = body;

    if (!cipher || !aes || !iv) {
      return NextResponse.json(
        { error: "Missing required fields: cipher, aes, iv" },
        { status: 400 }
      );
    }

    const result = await decipherFetchResponse({ cipher, aes, iv });
    return NextResponse.json({ result });
  } catch (err) {
    const message = err instanceof Error ? err.message : "Unknown error";
    return NextResponse.json({ error: message }, { status: 500 });
  }
}
