import { auth, CredentialsClient, GoogleAuth } from "./auth/mod.ts";

export { auth, GoogleAuth };
export type { CredentialsClient };

export interface RequestOpts {
  client: CredentialsClient | undefined;
  method: string;
  body?: Uint8Array | string;
}

export async function request(url: string, opts: RequestOpts) {
  const headers = await opts.client?.getRequestHeaders(url) ?? {};
  const resp = await fetch(url, {
    headers: {
      "accept": "application/json",
      "content-type": "application/json",
      ...headers,
    },
    body: opts.body,
    method: opts.method,
  });
  if (resp.status >= 400) {
    if (resp.headers.get("content-type")?.includes("application/json")) {
      const body = await resp.json();
      throw new GoogleApiError(
        body.error.code,
        body.error.message,
        body.error.details,
      );
    } else {
      const body = await resp.text();
      throw new GoogleApiError(
        resp.status,
        body,
        undefined,
      );
    }
  }
  return await resp.json();
}

export class GoogleApiError extends Error {
  code: number;
  details: unknown;

  constructor(code: number, message: string, details: unknown) {
    super(`${code}: ${message}`);
    this.name = "GoogleApiError";
    this.code = code;
    this.details = details;
  }
}
