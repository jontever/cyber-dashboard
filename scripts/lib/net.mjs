import { gunzipSync } from "node:zlib";

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

/** Fetch with timeout and simple retry/backoff. Returns a Response or throws. */
export async function fetchRetry(url, { headers = {}, timeoutMs = 60000, retries = 2 } = {}) {
  let lastErr;
  for (let i = 0; i <= retries; i++) {
    try {
      const res = await fetch(url, { headers, signal: AbortSignal.timeout(timeoutMs) });
      if (res.status === 429 || res.status >= 500) throw new Error(`HTTP ${res.status}`);
      if (!res.ok) {
        const err = new Error(`HTTP ${res.status}`);
        err.fatal = true; // 4xx: retrying will not help
        throw err;
      }
      return res;
    } catch (e) {
      lastErr = e;
      if (e.fatal) break;
      if (i < retries) await sleep(1500 * (i + 1));
    }
  }
  throw new Error(`${url}: ${lastErr?.message ?? lastErr}`);
}

/** Try each URL in turn; return { url, data } for the first that works. */
export async function firstWorking(urls, parse, opts) {
  const errors = [];
  for (const url of urls) {
    try {
      const res = await fetchRetry(url, opts);
      return { url, data: await parse(res) };
    } catch (e) {
      errors.push(e.message);
    }
  }
  throw new Error(errors.join(" | "));
}

export const asJson = (res) => res.json();
export const asText = (res) => res.text();
export const asGunzipText = async (res) => gunzipSync(Buffer.from(await res.arrayBuffer())).toString("utf8");

export { sleep };
