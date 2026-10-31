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

export function encodeRecord(v: any): Uint8Array;

/**
 * `{ after, limit, full }` from the query string of `GET .../changes`
 * (without the `?`), in its only accepted spelling.
 */
export function parseChangesQuery(query: string): any;

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

export type InitInput = RequestInfo | URL | Response | BufferSource | WebAssembly.Module;

export interface InitOutput {
    readonly memory: WebAssembly.Memory;
    readonly checkSkew: (a: bigint, b: bigint) => [number, number];
    readonly checkTicketTimes: (a: any, b: bigint) => [number, number];
    readonly contentDigest: (a: number, b: number) => [number, number];
    readonly credentialId: (a: number, b: number) => [number, number, number, number];
    readonly decodeBlobAnnounce: (a: number, b: number) => [number, number, number];
    readonly decodeBlobLookup: (a: number, b: number) => [number, number, number];
    readonly decodeCommit: (a: number, b: number) => [number, number, number];
    readonly decodeCreate: (a: number, b: number) => [number, number, number];
    readonly decodeEnroll: (a: number, b: number) => [number, number, number];
    readonly decodeSetPush: (a: number, b: number) => [number, number, number];
    readonly encodeBlobUrls: (a: any) => [number, number, number, number];
    readonly encodeChanges: (a: any) => [number, number, number, number];
    readonly encodeCommitResponse: (a: any) => [number, number, number, number];
    readonly encodeConfig: (a: any) => [number, number, number, number];
    readonly encodeCreated: (a: any) => [number, number, number, number];
    readonly encodeError: (a: any) => [number, number, number, number];
    readonly encodeInfo: (a: any) => [number, number, number, number];
    readonly encodeRecord: (a: any) => [number, number, number, number];
    readonly parseChangesQuery: (a: number, b: number) => [number, number, number];
    readonly parseSignatureHeaders: (a: number, b: number, c: number, d: number) => [number, number, number];
    readonly signatureBase: (a: number, b: number, c: number, d: number, e: number, f: number, g: any) => [number, number, number, number];
    readonly ticketHash: (a: any) => [number, number, number, number];
    readonly ticketSignedBytes: (a: any) => [number, number, number, number];
    readonly __wbindgen_malloc: (a: number, b: number) => number;
    readonly __wbindgen_realloc: (a: number, b: number, c: number, d: number) => number;
    readonly __wbindgen_exn_store: (a: number) => void;
    readonly __externref_table_alloc: () => number;
    readonly __wbindgen_externrefs: WebAssembly.Table;
    readonly __externref_table_dealloc: (a: number) => void;
    readonly __wbindgen_free: (a: number, b: number, c: number) => void;
    readonly __wbindgen_start: () => void;
}

export type SyncInitInput = BufferSource | WebAssembly.Module;

/**
 * Instantiates the given `module`, which can either be bytes or
 * a precompiled `WebAssembly.Module`.
 *
 * @param {{ module: SyncInitInput }} module - Passing `SyncInitInput` directly is deprecated.
 *
 * @returns {InitOutput}
 */
export function initSync(module: { module: SyncInitInput } | SyncInitInput): InitOutput;

/**
 * If `module_or_path` is {RequestInfo} or {URL}, makes a request and
 * for everything else, calls `WebAssembly.instantiate` directly.
 *
 * @param {{ module_or_path: InitInput | Promise<InitInput> }} module_or_path - Passing `InitInput` directly is deprecated.
 *
 * @returns {Promise<InitOutput>}
 */
export default function __wbg_init (module_or_path?: { module_or_path: InitInput | Promise<InitInput> } | InitInput | Promise<InitInput>): Promise<InitOutput>;
