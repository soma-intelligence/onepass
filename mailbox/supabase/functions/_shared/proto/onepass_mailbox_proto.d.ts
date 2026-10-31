/* tslint:disable */
/* eslint-disable */

/**
 * Throws when `|now - created| > SKEW_SECS`. Both are `BigInt`.
 */
export function checkSkew(created: bigint, now: bigint): void;

export function checkTicketTimes(ticket: any, now: bigint): void;

export function contentDigest(body: Uint8Array): string;

export function credentialId(public_key: Uint8Array): Uint8Array;

export function decodeBlobAnnounce(bytes: Uint8Array): any;

export function decodeBlobLookup(bytes: Uint8Array): any;

export function decodeCommit(bytes: Uint8Array): any;

export function decodeCreate(bytes: Uint8Array): any;

export function decodeEnroll(bytes: Uint8Array): any;

export function decodeSetPush(bytes: Uint8Array): any;

export function encodeBlobUrls(v: any): Uint8Array;

export function encodeChanges(v: any): Uint8Array;

export function encodeCommitResponse(v: any): Uint8Array;

export function encodeConfig(v: any): Uint8Array;

export function encodeCreated(v: any): Uint8Array;

export function encodeError(v: any): Uint8Array;

export function encodeInfo(v: any): Uint8Array;

/**
 * `{ params: { created, nonce, keyid }, sig }`.
 */
export function parseSignatureHeaders(signature_input: string, signature: string): any;

/**
 * `params` is the `params` object `parseSignatureHeaders` returned.
 */
export function signatureBase(method: string, target: string, content_digest: string, params: any): Uint8Array;

/**
 * `signed` is `decodeEnroll(...).ticket`.
 */
export function ticketHash(signed: any): Uint8Array;

/**
 * `ticket` is `decodeEnroll(...).ticket.ticket`.
 */
export function ticketSignedBytes(ticket: any): Uint8Array;
