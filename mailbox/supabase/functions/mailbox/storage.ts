// Signed Storage URLs (spec 4.8, 4.11), with the service key, for Storage
// only, never for the database. Names are exactly the object names the SQL
// functions return: the edge function never builds one.
import { createClient } from "@supabase/supabase-js";

export const BUCKET = "onepass-mailbox";
/** Lifetime of a signed download URL, seconds (spec 4.11). */
export const DOWNLOAD_URL_SECS = 60;

export interface Signer {
  /**
   * URL to upload one object. Its lifetime is Storage's, not ours: the
   * upload signing endpoint takes no expiry and uses
   * SIGNED_UPLOAD_URL_EXPIRATION_TIME (2 h by default), still far below the
   * 24 h after which an unreferenced blob is collected (spec 4.11).
   */
  upload(objectName: string): Promise<string>;
  /** URL to download one object, valid DOWNLOAD_URL_SECS. */
  download(objectName: string): Promise<string>;
}

/**
 * `publicUrl` replaces the origin and path prefix of `supabaseUrl` in the
 * URLs handed out: inside a local stack SUPABASE_URL is the gateway's
 * container address, which a client cannot reach.
 */
export function storageSigner(supabaseUrl: string, serviceKey: string, publicUrl?: string): Signer {
  const client = createClient(supabaseUrl, serviceKey, {
    auth: { persistSession: false, autoRefreshToken: false, detectSessionInUrl: false },
  });
  const bucket = client.storage.from(BUCKET);
  const rebase = (u: string): string => {
    if (!publicUrl) return u;
    const from = supabaseUrl.replace(/\/+$/, "");
    if (!u.startsWith(from + "/")) throw new Error("signed URL outside SUPABASE_URL");
    return publicUrl.replace(/\/+$/, "") + u.slice(from.length);
  };
  return {
    async upload(name) {
      const { data, error } = await bucket.createSignedUploadUrl(name);
      if (error || !data) throw new Error("signing an upload URL failed");
      return rebase(data.signedUrl);
    },
    async download(name) {
      const { data, error } = await bucket.createSignedUrl(name, DOWNLOAD_URL_SECS);
      if (error || !data) throw new Error("signing a download URL failed");
      return rebase(data.signedUrl);
    },
  };
}
