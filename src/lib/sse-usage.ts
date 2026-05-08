/**
 * Anthropic SSE usage extraction.
 *
 * The Anthropic streaming protocol emits a sequence of `event:` / `data:` lines.
 * The two events we care about for billing are:
 *
 *   event: message_start
 *   data: {"type":"message_start","message":{"usage":{"input_tokens":N, ...}}}
 *
 *   event: message_delta
 *   data: {"type":"message_delta","usage":{"output_tokens":M, ...}}
 *
 * `message_start` carries the (non-cumulative) input/cache token counts.
 * `message_delta` carries running output tokens; the LAST message_delta has
 * the total. We track the most recent values seen for each field across the
 * full stream. The brief's privacy posture forbids reading message bodies —
 * we only parse the JSON envelope's `usage` object, never `delta.text`.
 *
 * Used in waitUntil() — the response stream is tee()'d, the client gets
 * one branch immediately, and this function consumes the other branch out
 * of band to extract token counts for QuotaStoreDO /increment + ProxyLogEvent.
 */

import type { Usage } from "./pricing";

export async function extractUsageFromSSE(stream: ReadableStream<Uint8Array>): Promise<Usage> {
  const usage: Usage = { input_tokens: 0, output_tokens: 0, cached_tokens: 0, cache_creation_input_tokens: 0 };
  const reader = stream.getReader();
  const decoder = new TextDecoder();
  let buffer = "";

  try {
    while (true) {
      const { value, done } = await reader.read();
      if (done) break;
      buffer += decoder.decode(value, { stream: true });

      // SSE frames are separated by blank lines. Process complete frames.
      let sep = buffer.indexOf("\n\n");
      while (sep !== -1) {
        const frame = buffer.slice(0, sep);
        buffer = buffer.slice(sep + 2);
        applyFrame(frame, usage);
        sep = buffer.indexOf("\n\n");
      }
    }
    // Tail flush: handle a final frame without trailing blank line.
    if (buffer.length > 0) {
      applyFrame(buffer, usage);
    }
  } finally {
    reader.releaseLock();
  }

  return usage;
}

function applyFrame(frame: string, usage: Usage): void {
  // Find the `data:` line (frames may carry `event:` and `data:` lines).
  const lines = frame.split("\n");
  for (const line of lines) {
    if (!line.startsWith("data:")) continue;
    const payload = line.slice(5).trim();
    if (!payload || payload === "[DONE]") continue;
    let obj: unknown;
    try {
      obj = JSON.parse(payload);
    } catch {
      continue;
    }
    if (obj === null || typeof obj !== "object") continue;
    const o = obj as Record<string, unknown>;

    // message_start carries usage on the message object.
    if (o.type === "message_start" && typeof o.message === "object" && o.message !== null) {
      const msg = o.message as Record<string, unknown>;
      if (typeof msg.usage === "object" && msg.usage !== null) {
        readUsage(msg.usage as Record<string, unknown>, usage);
      }
    }
    // message_delta carries usage on the event itself.
    if (o.type === "message_delta" && typeof o.usage === "object" && o.usage !== null) {
      readUsage(o.usage as Record<string, unknown>, usage);
    }
  }
}

function readUsage(src: Record<string, unknown>, dst: Usage): void {
  if (typeof src.input_tokens === "number") dst.input_tokens = src.input_tokens;
  if (typeof src.output_tokens === "number") dst.output_tokens = src.output_tokens;
  // Anthropic exposes both `cache_creation_input_tokens` and
  // `cache_read_input_tokens`. For pricing-table purposes we sum the read-side
  // (already-cached) into `cached_tokens`. Cache-creation tokens are billed at
  // the input rate and stay in `input_tokens` per Anthropic's accounting.
  if (typeof src.cache_read_input_tokens === "number") {
    dst.cached_tokens = src.cache_read_input_tokens;
  }
  if (typeof src.cache_creation_input_tokens === "number") {
    dst.cache_creation_input_tokens = src.cache_creation_input_tokens;
  }
}
