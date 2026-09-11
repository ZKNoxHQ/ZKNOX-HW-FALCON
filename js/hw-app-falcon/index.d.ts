import type Transport from '@ledgerhq/hw-transport';

export type Logn = 9 | 10;

export interface PublicKey { logn: number; n: number; h: Buffer; coefficients: Uint16Array; }
export interface Signature {
  logn: number; n: number;
  /** 40-byte salt (nonce) */ salt: Buffer;
  /** s2, int16 little-endian, 2n bytes */ s2Raw: Buffer;
  s2: Int16Array;
  timings: { signMs: number; totalMs: number };
}
export interface KeygenResult { logn: number; head: Buffer; ms: number; }

export declare class FalconAppError extends Error {
  statusCode: number; ins: number; p1: number;
}

export default class FalconApp {
  static CLA: number;
  static INS: Readonly<{ GET_VERSION: number; GET_APP_NAME: number; KEYGEN: number; GET_PK: number; SIGN: number; GET_SIG: number }>;
  static P1_SIGN: Readonly<{ INIT: number; FEED_MSG: number; FEED_SEED: number; GEN_SEED: number; SIGN_ALL: number; GET_NONCE: number }>;
  static SW: Readonly<Record<string, number>>;
  static SALT_LEN: 40;
  static DIGEST_LEN: 32;
  static FalconAppError: typeof FalconAppError;
  transport: Transport;
  constructor(transport: Transport, scrambleKey?: string);
  getVersion(): Promise<{ major: number; minor: number; patch: number }>;
  getAppName(): Promise<string>;
  generateKey(opts?: { logn?: Logn; force?: boolean }): Promise<KeygenResult>;
  getPublicKey(opts?: { logn?: Logn }): Promise<PublicKey>;
  signHash(opts: { logn?: Logn; hash: Buffer | string; seed?: Buffer | string }): Promise<Signature>;
}
