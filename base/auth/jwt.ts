import * as jose from "https://deno.land/x/jose@v4.4.0/index.ts";
import { CredentialsClient } from "./authclient.ts";

export interface JWTInput {
  type?: string;
  client_email?: string;
  private_key?: string;
  private_key_id?: string;
  project_id?: string;
  client_id?: string;
  client_secret?: string;
  refresh_token?: string;
  quota_project_id?: string;
  scopes?: string[];
}

export class JWT implements CredentialsClient {
  #projectId: string | undefined;
  #clientEmail: string;
  #privateKeyId: string | undefined;
  #privateKeyString: string;
  #privateKey: Promise<jose.KeyLike> | undefined;
  #scopes: string[] | undefined;

  constructor(
    projectId: string | undefined,
    clientEmail: string,
    privateKeyId: string | undefined,
    privateKeyString: string,
    scopes: string[] | undefined,
  ) {
    this.#projectId = projectId;
    this.#clientEmail = clientEmail;
    this.#privateKeyId = privateKeyId;
    this.#privateKeyString = privateKeyString;
    this.#scopes = scopes;
  }

  static fromJSON(json: JWTInput) {
    if (!json) {
      throw new Error(
        "Must pass in a JSON object containing the service account auth settings.",
      );
    }
    if (!json.client_email) {
      throw new Error(
        "The incoming JSON object does not contain a client_email field",
      );
    }
    if (!json.private_key) {
      throw new Error(
        "The incoming JSON object does not contain a private_key field",
      );
    }

    return new JWT(
      json.project_id,
      json.client_email,
      json.private_key_id,
      json.private_key,
      json.scopes,
    );
  }

  get projectId() {
    return this.#projectId;
  }

  get scopes() {
    return this.#scopes;
  }

  set scopes(val: string[] | undefined) {
    this.#scopes = val;
  }

  async getRequestHeaders(url: string): Promise<Record<string, string>> {
    const aud = new URL(url).origin + "/";
    const scope = this.#scopes?.join(' ');
    const jwt = await this.#getJWT(aud, scope);
    return {
      "Authorization": `Bearer ${jwt}`,
    };
  }

  #getPrivateKey(): Promise<jose.KeyLike> {
    if (!this.#privateKey) {
      this.#privateKey = jose.importPKCS8(this.#privateKeyString, "RS256");
    }
    return this.#privateKey;
  }

  async #getJWT(aud: string, scope?: string) {
    const key = await this.#getPrivateKey();
    const payload = scope ? { aud, scope } : { aud };
    return new jose.SignJWT(payload)
      .setProtectedHeader({ alg: "RS256", kid: this.#privateKeyId })
      .setIssuer(this.#clientEmail)
      .setSubject(this.#clientEmail)
      .setIssuedAt()
      .setExpirationTime("1h")
      .sign(key);
  }
}
