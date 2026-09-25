import * as asn1js from "asn1js";
import {
  Certificate,
  ExtKeyUsage,
  PKIStatus,
  SignedData,
  TSTInfo,
  TimeStampResp,
  getAlgorithmByOID,
} from "pkijs";

const SHA256_OID = "2.16.840.1.101.3.4.2.1";
const SIGNED_DATA_OID = "1.2.840.113549.1.7.2";
const TST_INFO_OID = "1.2.840.113549.1.9.16.1.4";
const EXTENDED_KEY_USAGE_OID = "2.5.29.37";
const TIME_STAMPING_KEY_PURPOSE_OID = "1.3.6.1.5.5.7.3.8";
const MAX_COMPONENT_BYTES = 10 * 1024 * 1024;
const MAX_ATTESTATION_JWS_BYTES = 100_000;
const MAX_CHAIN_CERTIFICATES = 16;
const MAX_TRUST_ROOTS = 100;
const MAX_PEM_CERTIFICATE_BYTES = 100_000;
const TIMESTAMP_ASN1_LIMITS = {
  maxDepth: 32,
  maxNodes: 4_096,
  maxContentLength: MAX_COMPONENT_BYTES,
} as const;
const TST_INFO_ASN1_LIMITS = {
  maxDepth: 16,
  maxNodes: 256,
  maxContentLength: 100_000,
} as const;
const CERTIFICATE_ASN1_LIMITS = {
  maxDepth: 24,
  maxNodes: 2_048,
  maxContentLength: MAX_PEM_CERTIFICATE_BYTES,
} as const;

export interface TimestampByteDescriptor {
  byte_length: number;
  media_type: string;
  path: string;
  sha256: string;
}

export interface TimestampEvidence {
  algorithm: string;
  certificate_chain: TimestampByteDescriptor;
  message_imprint_sha256: string;
  nonce_sha256: string;
  policy_oid: string;
  provider: string;
  schema_version: string;
  token: TimestampByteDescriptor;
  token_gen_time: string;
}

export interface TsaPolicy {
  certificate_roots_pem: readonly string[];
  policy_oids: readonly string[];
  tsa_id: string;
}

export interface PortableUtcInstant {
  epochSeconds: bigint;
  nanoseconds: number;
}

export interface AuthenticatedTimestamp {
  tokenGenTime: string;
  instant: PortableUtcInstant;
}

export interface AuthenticateArchivedTimestampInput {
  evidence: TimestampEvidence;
  tokenBytes: Uint8Array;
  certificateChainBytes: Uint8Array;
  attestationJwsBytes: Uint8Array;
  tsaPolicy: TsaPolicy;
}

export class TimestampVerificationError extends Error {
  readonly checkName = "timestamp" as const;

  constructor(message: string, options?: ErrorOptions) {
    super(message, options);
    this.name = "TimestampVerificationError";
  }
}

export class TimestampUnsupportedError extends TimestampVerificationError {
  constructor(message: string, options?: ErrorOptions) {
    super(message, options);
    this.name = "TimestampUnsupportedError";
  }
}

/** Parse a portable UTC time without losing authority-authored nanoseconds. */
export function parsePortableUtcTime(value: string): PortableUtcInstant {
  const match =
    /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.(\d{1,9}))?Z$/.exec(
      value,
    );
  if (!match) {
    throw new RangeError("portable time must be UTC with at most nine fractional digits");
  }
  const parts = match.slice(1, 7).map(Number);
  const [year, month, day, hour, minute, second] = parts;
  if (
    year === undefined ||
    month === undefined ||
    day === undefined ||
    hour === undefined ||
    minute === undefined ||
    second === undefined ||
    year < 1
  ) {
    throw new RangeError("portable time is not a valid UTC instant");
  }
  const date = new Date(0);
  date.setUTCFullYear(year, month - 1, day);
  date.setUTCHours(hour, minute, second, 0);
  if (
    !Number.isFinite(date.getTime()) ||
    date.getUTCFullYear() !== year ||
    date.getUTCMonth() !== month - 1 ||
    date.getUTCDate() !== day ||
    date.getUTCHours() !== hour ||
    date.getUTCMinutes() !== minute ||
    date.getUTCSeconds() !== second
  ) {
    throw new RangeError("portable time is not a valid UTC instant");
  }
  const fraction = match[7] ?? "";
  return {
    epochSeconds: BigInt(date.getTime() / 1000),
    nanoseconds: Number((fraction + "000000000").slice(0, 9)),
  };
}

/** Authenticate retained RFC 3161 evidence using only the supplied TSA policy. */
export async function authenticateArchivedTimestamp({
  evidence,
  tokenBytes,
  certificateChainBytes,
  attestationJwsBytes,
  tsaPolicy,
}: AuthenticateArchivedTimestampInput): Promise<AuthenticatedTimestamp> {
  requireNativeWebCrypto();
  requireBoundedInput(tokenBytes, "timestamp token", MAX_COMPONENT_BYTES);
  requireBoundedInput(certificateChainBytes, "timestamp certificate chain", MAX_COMPONENT_BYTES);
  requireBoundedInput(attestationJwsBytes, "attestation JWS", MAX_ATTESTATION_JWS_BYTES);
  requireWrapperProfile(evidence, tsaPolicy);

  try {
    await requireDescriptorBinding(evidence.token, tokenBytes, {
      mediaType: "application/timestamp-reply",
      path: "evidence/timestamp/attestation.tsr",
    });
    await requireDescriptorBinding(evidence.certificate_chain, certificateChainBytes, {
      mediaType: "application/pem-certificate-chain",
      path: "evidence/timestamp/tsa-chain.pem",
    });
    const expectedImprint = await sha256(attestationJwsBytes);
    if (hex(expectedImprint) !== evidence.message_imprint_sha256) {
      throw new TimestampVerificationError("timestamp wrapper does not bind the attestation JWS");
    }

    const response = parseTimestampResponse(tokenBytes);
    const { signedData, tstInfo, tokenGenTime, instant } = response;
    requireTimestampFields(tstInfo, expectedImprint, evidence, tokenGenTime);
    const nonce = requirePositiveNonce(tstInfo);
    if (hex(await sha256(minimalUnsignedBytes(nonce))) !== evidence.nonce_sha256) {
      throw new TimestampVerificationError("timestamp nonce does not match its wrapper");
    }

    const carriedCertificates = parsePemCertificates(
      new TextDecoder("utf-8", { fatal: true }).decode(certificateChainBytes),
      "timestamp certificate chain",
      MAX_CHAIN_CERTIFICATES,
    );
    const trustRoots = parseTrustRoots(tsaPolicy.certificate_roots_pem);
    const cmsCertificates = signedData.certificates ?? [];
    if (
      cmsCertificates.length === 0 ||
      cmsCertificates.length > MAX_CHAIN_CERTIFICATES ||
      cmsCertificates.some((certificate) => !(certificate instanceof Certificate))
    ) {
      throw new TimestampVerificationError("timestamp token certificate set is invalid");
    }
    const cmsX509Certificates = cmsCertificates.filter(
      (certificate): certificate is Certificate => certificate instanceof Certificate,
    );
    const verificationCertificates = deduplicateCertificates([
      ...cmsX509Certificates,
      ...carriedCertificates,
    ]);
    signedData.certificates = verificationCertificates;
    requireSupportedAlgorithms(signedData, verificationCertificates, trustRoots);

    const verification = await signedData.verify({
      signer: 0,
      data: copyArrayBuffer(attestationJwsBytes),
      trustedCerts: trustRoots,
      checkDate: instantToDate(instant),
      checkChain: true,
      passedWhenNotRevValues: true,
      extendedMode: true,
    });
    if (
      verification.signatureVerified !== true ||
      verification.signerCertificateVerified !== true ||
      !verification.signerCertificate ||
      verification.certificatePath.length === 0
    ) {
      throw new TimestampVerificationError("timestamp CMS signature or certificate path is invalid");
    }
    requirePathEndsAtExternalRoot(verification.certificatePath, trustRoots);
    requireCertificateValidityAtExactTime(verification.certificatePath, instant);
    requireTimestampingEku(verification.signerCertificate);

    return { tokenGenTime, instant };
  } catch (error) {
    if (error instanceof TimestampVerificationError) {
      throw error;
    }
    if (error instanceof Error && error.name === "NotSupportedError") {
      throw new TimestampUnsupportedError("native timestamp cryptography is unsupported", {
        cause: error,
      });
    }
    throw new TimestampVerificationError("archived RFC 3161 evidence is invalid", {
      cause: error,
    });
  }
}

function requireNativeWebCrypto(): SubtleCrypto {
  if (
    typeof globalThis.crypto?.subtle?.digest !== "function" ||
    typeof globalThis.crypto.subtle.importKey !== "function" ||
    typeof globalThis.crypto.subtle.verify !== "function"
  ) {
    throw new TimestampUnsupportedError("native WebCrypto is required for timestamp verification");
  }
  return globalThis.crypto.subtle;
}

function requireBoundedInput(bytes: Uint8Array, label: string, maximum: number): void {
  if (!(bytes instanceof Uint8Array) || bytes.byteLength === 0 || bytes.byteLength > maximum) {
    throw new TimestampVerificationError(`${label} has an invalid byte length`);
  }
}

function requireWrapperProfile(evidence: TimestampEvidence, tsaPolicy: TsaPolicy): void {
  if (
    evidence.schema_version !== "rproof.timestamp-evidence.v1" ||
    evidence.algorithm !== "rfc3161-sha256"
  ) {
    throw new TimestampUnsupportedError("timestamp wrapper version or algorithm is unsupported");
  }
  if (
    evidence.provider !== tsaPolicy.tsa_id ||
    !tsaPolicy.policy_oids.includes(evidence.policy_oid) ||
    tsaPolicy.certificate_roots_pem.length === 0 ||
    tsaPolicy.certificate_roots_pem.length > MAX_TRUST_ROOTS
  ) {
    throw new TimestampVerificationError("timestamp wrapper is outside the trusted profile");
  }
}

async function requireDescriptorBinding(
  descriptor: TimestampByteDescriptor,
  bytes: Uint8Array,
  expected: { mediaType: string; path: string },
): Promise<void> {
  if (
    descriptor.path !== expected.path ||
    descriptor.media_type !== expected.mediaType ||
    descriptor.byte_length !== bytes.byteLength ||
    descriptor.sha256 !== hex(await sha256(bytes))
  ) {
    throw new TimestampVerificationError("timestamp component binding is invalid");
  }
}

function parseTimestampResponse(tokenBytes: Uint8Array): {
  signedData: SignedData;
  tstInfo: TSTInfo;
  tokenGenTime: string;
  instant: PortableUtcInstant;
} {
  const decoded = asn1js.fromBER(tokenBytes, TIMESTAMP_ASN1_LIMITS);
  if (
    decoded.offset !== tokenBytes.byteLength ||
    decoded.result.error !== "" ||
    !equalBytes(new Uint8Array(decoded.result.toBER(false)), tokenBytes)
  ) {
    throw new TimestampVerificationError("timestamp reply framing is invalid or unsupported");
  }
  const response = new TimeStampResp({ schema: decoded.result });
  if (
    response.status.status !== PKIStatus.granted ||
    !response.timeStampToken ||
    response.timeStampToken.contentType !== SIGNED_DATA_OID
  ) {
    throw new TimestampVerificationError("timestamp reply status or content type is invalid");
  }
  const signedData = new SignedData({ schema: response.timeStampToken.content });
  if (
    signedData.signerInfos.length !== 1 ||
    signedData.encapContentInfo.eContentType !== TST_INFO_OID ||
    !(signedData.encapContentInfo.eContent instanceof asn1js.OctetString) ||
    signedData.encapContentInfo.eContent.idBlock.isConstructed
  ) {
    throw new TimestampVerificationError("timestamp token SignedData profile is invalid");
  }
  const tstInfoBytes = signedData.encapContentInfo.eContent.valueBlock.valueHexView;
  const tstDecoded = asn1js.fromBER(tstInfoBytes, TST_INFO_ASN1_LIMITS);
  if (
    tstDecoded.offset !== tstInfoBytes.byteLength ||
    tstDecoded.result.error !== "" ||
    !equalBytes(new Uint8Array(tstDecoded.result.toBER(false)), tstInfoBytes)
  ) {
    throw new TimestampVerificationError("timestamp TSTInfo framing is invalid or unsupported");
  }
  const tstInfo = new TSTInfo({ schema: tstDecoded.result });
  const sequence = tstDecoded.result;
  if (!(sequence instanceof asn1js.Sequence)) {
    throw new TimestampVerificationError("timestamp token does not contain TSTInfo");
  }
  const genTimeBlock = sequence.valueBlock.value[4];
  if (!(genTimeBlock instanceof asn1js.GeneralizedTime)) {
    throw new TimestampVerificationError("timestamp token has no GeneralizedTime");
  }
  const tokenGenTime = portableTimeFromGeneralizedTime(genTimeBlock);
  return {
    signedData,
    tstInfo,
    tokenGenTime,
    instant: parsePortableUtcTime(tokenGenTime),
  };
}

function requireTimestampFields(
  tstInfo: TSTInfo,
  expectedImprint: Uint8Array,
  evidence: TimestampEvidence,
  tokenGenTime: string,
): void {
  let wrapperTime: PortableUtcInstant;
  try {
    wrapperTime = parsePortableUtcTime(evidence.token_gen_time);
  } catch (error) {
    throw new TimestampVerificationError("timestamp wrapper generation time is invalid", {
      cause: error,
    });
  }
  const tokenTime = parsePortableUtcTime(tokenGenTime);
  if (tstInfo.version !== 1 || tstInfo.messageImprint.hashAlgorithm.algorithmId !== SHA256_OID) {
    throw new TimestampUnsupportedError("timestamp token version or imprint algorithm is unsupported");
  }
  if (
    !equalBytes(tstInfo.messageImprint.hashedMessage.valueBlock.valueHexView, expectedImprint) ||
    tstInfo.policy !== evidence.policy_oid ||
    compareInstants(tokenTime, wrapperTime) !== 0
  ) {
    throw new TimestampVerificationError("timestamp token fields do not match the wrapper");
  }
}

function requirePositiveNonce(tstInfo: TSTInfo): bigint {
  if (!tstInfo.nonce) {
    throw new TimestampVerificationError("timestamp token has no nonce");
  }
  const nonce = tstInfo.nonce.toBigInt();
  if (nonce <= 0n) {
    throw new TimestampVerificationError("timestamp nonce must be positive");
  }
  return nonce;
}

function portableTimeFromGeneralizedTime(value: asn1js.GeneralizedTime): string {
  const encoded = value.valueBeforeDecodeView;
  if (encoded.byteLength < 3 || encoded[0] !== 0x18 || encoded[1] !== encoded.byteLength - 2) {
    throw new TimestampVerificationError("timestamp GeneralizedTime is not strict short-form DER");
  }
  const contents = String.fromCharCode(...encoded.subarray(2));
  const match = /^(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})(?:\.(\d{1,9}))?Z$/.exec(
    contents,
  );
  if (!match) {
    throw new TimestampVerificationError(
      "timestamp generation time must be UTC with at most nine fractional digits",
    );
  }
  const fraction = match[7] ? `.${match[7]}` : "";
  return `${match[1]}-${match[2]}-${match[3]}T${match[4]}:${match[5]}:${match[6]}${fraction}Z`;
}

function parseTrustRoots(pemRoots: readonly string[]): Certificate[] {
  const roots: Certificate[] = [];
  for (const pem of pemRoots) {
    if (typeof pem !== "string" || pem.length === 0 || pem.length > MAX_PEM_CERTIFICATE_BYTES) {
      throw new TimestampVerificationError("timestamp trust root is invalid");
    }
    roots.push(...parsePemCertificates(pem, "timestamp trust root", MAX_TRUST_ROOTS));
    if (roots.length > MAX_TRUST_ROOTS) {
      throw new TimestampVerificationError("timestamp trust policy has too many roots");
    }
  }
  return deduplicateCertificates(roots);
}

function parsePemCertificates(text: string, label: string, maximum: number): Certificate[] {
  const begin = "-----BEGIN CERTIFICATE-----";
  const end = "-----END CERTIFICATE-----";
  const certificates: Certificate[] = [];
  let cursor = 0;
  while (cursor < text.length) {
    while (cursor < text.length && /\s/.test(text[cursor] ?? "")) cursor += 1;
    if (cursor === text.length) break;
    if (!text.startsWith(begin, cursor)) {
      throw new TimestampVerificationError(`${label} is not valid PEM`);
    }
    const bodyStart = cursor + begin.length;
    const endAt = text.indexOf(end, bodyStart);
    if (endAt < 0) {
      throw new TimestampVerificationError(`${label} is not valid PEM`);
    }
    const body = text.slice(bodyStart, endAt).replace(/\s/g, "");
    if (!/^[A-Za-z0-9+/]+={0,2}$/.test(body) || body.length % 4 !== 0) {
      throw new TimestampVerificationError(`${label} is not valid PEM`);
    }
    let der: Uint8Array;
    try {
      der = Uint8Array.from(atob(body), (character) => character.charCodeAt(0));
    } catch (error) {
      throw new TimestampVerificationError(`${label} is not valid PEM`, { cause: error });
    }
    if (der.byteLength === 0 || der.byteLength > MAX_PEM_CERTIFICATE_BYTES) {
      throw new TimestampVerificationError(`${label} certificate has an invalid byte length`);
    }
    const decoded = asn1js.fromBER(der, CERTIFICATE_ASN1_LIMITS);
    if (
      decoded.offset !== der.byteLength ||
      decoded.result.error !== "" ||
      !equalBytes(new Uint8Array(decoded.result.toBER(false)), der)
    ) {
      throw new TimestampVerificationError(`${label} certificate framing is invalid or unsupported`);
    }
    certificates.push(new Certificate({ schema: decoded.result }));
    if (certificates.length > maximum) {
      throw new TimestampVerificationError(`${label} has too many certificates`);
    }
    cursor = endAt + end.length;
  }
  if (certificates.length === 0) {
    throw new TimestampVerificationError(`${label} has no certificates`);
  }
  return certificates;
}

function deduplicateCertificates(certificates: Certificate[]): Certificate[] {
  const unique = new Map<string, Certificate>();
  for (const certificate of certificates) {
    const der = new Uint8Array(certificate.toSchema(true).toBER(false));
    unique.set(hex(der), certificate);
  }
  return [...unique.values()];
}

function requirePathEndsAtExternalRoot(path: Certificate[], roots: Certificate[]): void {
  const last = path.at(-1);
  if (!last) {
    throw new TimestampVerificationError("timestamp certificate path is empty");
  }
  const lastDer = new Uint8Array(last.toSchema(true).toBER(false));
  if (
    !roots.some((root) =>
      equalBytes(new Uint8Array(root.toSchema(true).toBER(false)), lastDer),
    )
  ) {
    throw new TimestampVerificationError("timestamp path does not end at an external trust root");
  }
}

function requireCertificateValidityAtExactTime(
  path: Certificate[],
  instant: PortableUtcInstant,
): void {
  for (const certificate of path) {
    const notBefore = instantFromDate(certificate.notBefore.value);
    const notAfter = instantFromDate(certificate.notAfter.value);
    if (compareInstants(instant, notBefore) < 0 || compareInstants(instant, notAfter) > 0) {
      throw new TimestampVerificationError(
        "timestamp certificate is not valid at the exact generation time",
      );
    }
  }
}

function requireTimestampingEku(certificate: Certificate): void {
  const extensions = (certificate.extensions ?? []).filter(
    (extension) => extension.extnID === EXTENDED_KEY_USAGE_OID,
  );
  if (
    extensions.length !== 1 ||
    extensions[0]?.critical !== true ||
    !(extensions[0].parsedValue instanceof ExtKeyUsage) ||
    extensions[0].parsedValue.keyPurposes.length !== 1 ||
    extensions[0].parsedValue.keyPurposes[0] !== TIME_STAMPING_KEY_PURPOSE_OID
  ) {
    throw new TimestampVerificationError(
      "timestamp signer EKU must be critical and exclusively time stamping",
    );
  }
}

function requireSupportedAlgorithms(
  signedData: SignedData,
  certificates: Certificate[],
  roots: Certificate[],
): void {
  const signer = signedData.signerInfos[0];
  if (!signer) {
    throw new TimestampVerificationError("timestamp token has no signer");
  }
  const algorithmOids = [
    ...signedData.digestAlgorithms.map((algorithm) => algorithm.algorithmId),
    signer.digestAlgorithm.algorithmId,
    signer.signatureAlgorithm.algorithmId,
    ...[...certificates, ...roots].flatMap((certificate) => [
      certificate.subjectPublicKeyInfo.algorithm.algorithmId,
      certificate.signatureAlgorithm.algorithmId,
    ]),
  ];
  try {
    for (const oid of algorithmOids) getAlgorithmByOID(oid, true, "timestamp algorithm");
  } catch (error) {
    throw new TimestampUnsupportedError("timestamp uses an unsupported PKI algorithm", {
      cause: error,
    });
  }
}

function minimalUnsignedBytes(value: bigint): Uint8Array {
  let encoded = value.toString(16);
  if (encoded.length % 2 !== 0) encoded = `0${encoded}`;
  const bytes = new Uint8Array(encoded.length / 2);
  for (let index = 0; index < bytes.length; index += 1) {
    bytes[index] = Number.parseInt(encoded.slice(index * 2, index * 2 + 2), 16);
  }
  return bytes;
}

async function sha256(bytes: Uint8Array): Promise<Uint8Array> {
  return new Uint8Array(await requireNativeWebCrypto().digest("SHA-256", copyArrayBuffer(bytes)));
}

function copyArrayBuffer(bytes: Uint8Array): ArrayBuffer {
  return bytes.slice().buffer;
}

function instantToDate(instant: PortableUtcInstant): Date {
  return new Date(
    Number(instant.epochSeconds) * 1000 + Math.floor(instant.nanoseconds / 1_000_000),
  );
}

function instantFromDate(value: Date): PortableUtcInstant {
  const milliseconds = value.getTime();
  const wholeSeconds = Math.floor(milliseconds / 1000);
  return {
    epochSeconds: BigInt(wholeSeconds),
    nanoseconds: (milliseconds - wholeSeconds * 1000) * 1_000_000,
  };
}

function compareInstants(left: PortableUtcInstant, right: PortableUtcInstant): number {
  if (left.epochSeconds < right.epochSeconds) return -1;
  if (left.epochSeconds > right.epochSeconds) return 1;
  return Math.sign(left.nanoseconds - right.nanoseconds);
}

function equalBytes(left: Uint8Array, right: Uint8Array): boolean {
  if (left.byteLength !== right.byteLength) return false;
  let difference = 0;
  for (let index = 0; index < left.byteLength; index += 1) {
    difference |= (left[index] ?? 0) ^ (right[index] ?? 0);
  }
  return difference === 0;
}

function hex(bytes: Uint8Array): string {
  return [...bytes].map((value) => value.toString(16).padStart(2, "0")).join("");
}
