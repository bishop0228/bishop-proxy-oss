/**
 * Web Crypto SigV4 signer for AWS Bedrock (§1.17.17).
 *
 * Implements HMAC-SHA256 signing-key chain:
 *   kDate = HMAC("AWS4" + secretAccessKey, dateShort)
 *   kRegion = HMAC(kDate, region)
 *   kService = HMAC(kRegion, service)
 *   kSigning = HMAC(kService, "aws4_request")
 * Signed headers (alphabetical): content-type;host;x-amz-date
 */

function toHex(buf: ArrayBuffer): string {
  return Array.from(new Uint8Array(buf))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

async function hmacSha256(key: CryptoKey, data: string): Promise<ArrayBuffer> {
  const encoded = new TextEncoder().encode(data);
  return crypto.subtle.sign("HMAC", key, encoded);
}

async function importHmacKey(material: BufferSource): Promise<CryptoKey> {
  return crypto.subtle.importKey(
    "raw",
    material,
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );
}

export interface SigV4Params {
  accessKeyId: string;
  secretAccessKey: string;
  region: string;
  service: string;
  method: string;
  path: string;
  host: string;
  contentType: string;
  amzDate: string;
  payload: string;
}

export interface SigV4Result {
  authorization: string;
  amzDate: string;
}

export async function sigv4Sign(params: SigV4Params): Promise<SigV4Result> {
  const { accessKeyId, secretAccessKey, region, service, method, path, host, contentType, amzDate, payload } = params;

  const dateShort = amzDate.slice(0, 8); // YYYYMMDD

  // Payload hash.
  const payloadHashBuf = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(payload));
  const payloadHash = toHex(payloadHashBuf);

  // Canonical headers (alphabetical: content-type, host, x-amz-date).
  const canonicalHeaders =
    `content-type:${contentType}\n` +
    `host:${host}\n` +
    `x-amz-date:${amzDate}\n`;
  const signedHeaders = "content-type;host;x-amz-date";

  // Canonical request.
  const canonicalRequest = [
    method.toUpperCase(),
    path,
    "",                   // canonical query string (empty)
    canonicalHeaders,
    signedHeaders,
    payloadHash,
  ].join("\n");

  const canonicalRequestHashBuf = await crypto.subtle.digest(
    "SHA-256",
    new TextEncoder().encode(canonicalRequest),
  );
  const canonicalRequestHash = toHex(canonicalRequestHashBuf);

  // String to sign.
  const credentialScope = `${dateShort}/${region}/${service}/aws4_request`;
  const stringToSign = [
    "AWS4-HMAC-SHA256",
    amzDate,
    credentialScope,
    canonicalRequestHash,
  ].join("\n");

  // Signing key chain.
  const kDateKey = await importHmacKey(new TextEncoder().encode("AWS4" + secretAccessKey));
  const kDateBuf = await hmacSha256(kDateKey, dateShort);

  const kRegionKey = await importHmacKey(kDateBuf);
  const kRegionBuf = await hmacSha256(kRegionKey, region);

  const kServiceKey = await importHmacKey(kRegionBuf);
  const kServiceBuf = await hmacSha256(kServiceKey, service);

  const kSigningKey = await importHmacKey(kServiceBuf);
  const kSigningBuf = await hmacSha256(kSigningKey, "aws4_request");

  const sigKey = await importHmacKey(kSigningBuf);
  const signatureBuf = await hmacSha256(sigKey, stringToSign);
  const signature = toHex(signatureBuf);

  const authorization =
    `AWS4-HMAC-SHA256 Credential=${accessKeyId}/${credentialScope}, ` +
    `SignedHeaders=${signedHeaders}, ` +
    `Signature=${signature}`;

  return { authorization, amzDate };
}

/** Generate ISO-8601 compact timestamp for x-amz-date: YYYYMMDDTHHmmssZ */
export function amzDateNow(): string {
  return new Date().toISOString().replace(/[-:]/g, "").replace(/\.\d{3}/, "");
}
