/**
 * Device sharing: an owner grants other users full access to a device.
 *
 * The device itself only accepts a session whose Google id_token has the owner's aud:sub (it
 * stores that identity at adoption and verifies every cloud session against it). A shared
 * user's session therefore carries an id_token minted for the OWNER from the refresh token the
 * owner granted with offline access. The token goes only to the device, never to the browser.
 * The device cannot tell a shared user from the owner, so there is one level: full access.
 */
import { createCipheriv, createDecipheriv, createHash, randomBytes } from "crypto";
import express from "express";
import * as jose from "jose";
import { prisma } from "./db";
import { isIdentityAllowed } from "./auth";
import {
  ConflictError,
  InternalServerError,
  NotFoundError,
  UnauthorizedError,
  UnprocessableEntityError,
} from "./errors";
import { getGoogleOIDCClient } from "./oidc";

const sessionSub = (req: express.Request) => {
  const { sub } = jose.decodeJwt(req.session?.id_token);
  if (!sub) throw new UnauthorizedError("Missing sub in token");
  return sub;
};

// ==========================================================================
// Access
// ==========================================================================

/** Who may use a device: its owner, or a user a share is bound to. */
export const accessibleBy = (sub: string) => ({
  OR: [{ user: { googleId: sub } }, { shares: { some: { user: { googleId: sub } } } }],
});

/** The device if `sub` may use it, with `shared` true unless `sub` owns it. */
export async function findAccessibleDevice(id: string, sub: string) {
  const device = await prisma.device.findFirst({
    where: { id, ...accessibleBy(sub) },
    select: {
      id: true,
      name: true,
      lastSeen: true,
      user: { select: { id: true, googleId: true, email: true } },
    },
  });
  if (!device) return null;
  return { ...device, shared: device.user.googleId !== sub };
}

async function findOwnedDevice(id: string, sub: string) {
  const device = await prisma.device.findFirst({
    where: { id, user: { googleId: sub } },
    select: { id: true, user: { select: { id: true, email: true, googleRefreshToken: true } } },
  });
  if (!device) throw new NotFoundError("Device not found");
  return device;
}

/** The id_token to forward to the device: the caller's own, or a minted owner token if shared. */
export async function deviceSessionToken(
  device: { shared: boolean; user: { id: bigint } },
  ownIdToken: string,
) {
  return device.shared ? mintOwnerIdToken(device.user.id) : ownIdToken;
}

// ==========================================================================
// Owner id_token minting
// ==========================================================================

const refreshTokenKey = () => {
  const secret = process.env.COOKIE_SECRET;
  if (!secret) throw new InternalServerError("COOKIE_SECRET is not set");
  return createHash("sha256").update(`jetkvm-google-refresh-token\0${secret}`).digest();
};

export function sealRefreshToken(refreshToken: string) {
  const iv = randomBytes(12);
  const cipher = createCipheriv("aes-256-gcm", refreshTokenKey(), iv);
  const sealed = Buffer.concat([cipher.update(refreshToken, "utf8"), cipher.final()]);
  return ["v1", iv, sealed, cipher.getAuthTag()]
    .map(p => (typeof p === "string" ? p : p.toString("base64url")))
    .join(".");
}

/** null when it cannot be opened, e.g. after COOKIE_SECRET was rotated. */
export function openRefreshToken(value: string) {
  const [version, iv, sealed, tag] = value.split(".");
  if (version !== "v1" || !iv || !sealed || !tag) return null;
  try {
    const decipher = createDecipheriv(
      "aes-256-gcm",
      refreshTokenKey(),
      Buffer.from(iv, "base64url"),
    );
    decipher.setAuthTag(Buffer.from(tag, "base64url"));
    return Buffer.concat([
      decipher.update(Buffer.from(sealed, "base64url")),
      decipher.final(),
    ]).toString("utf8");
  } catch {
    return null;
  }
}

export class RefreshTokenRevokedError extends Error {}

/** Replaceable in tests. Returns a fresh Google-signed id_token for the refresh token's owner. */
export const googleTokens = {
  async refreshIdToken(refreshToken: string): Promise<string> {
    const client = await getGoogleOIDCClient();
    try {
      const tokenSet = await client.refresh(refreshToken);
      if (!tokenSet.id_token) throw new Error("Google returned no id_token on refresh");
      return tokenSet.id_token;
    } catch (e) {
      if ((e as { error?: string }).error === "invalid_grant") throw new RefreshTokenRevokedError();
      throw e;
    }
  },
};

const ownerTokens = new Map<string, { idToken: string; exp: number }>();
// A minted token is reused until this close to its expiry.
const MIN_REMAINING_SECONDS = 5 * 60;

export const clearOwnerTokenCache = () => ownerTokens.clear();

const ownerConsentRequired = () =>
  new ConflictError(
    "The device owner has to enable sharing before this device can be used by others",
    "owner_consent_required",
  );

export async function mintOwnerIdToken(ownerId: bigint) {
  const owner = await prisma.user.findUnique({
    where: { id: ownerId },
    select: { googleId: true, email: true, googleRefreshToken: true },
  });
  // The owner losing access ends every share of theirs.
  if (!owner || !isIdentityAllowed(owner.email)) throw new NotFoundError("Device not found");

  const refreshToken = owner.googleRefreshToken && openRefreshToken(owner.googleRefreshToken);
  if (!refreshToken) throw ownerConsentRequired();

  const cacheKey = ownerId.toString();
  const cached = ownerTokens.get(cacheKey);
  if (cached && cached.exp - Date.now() / 1000 > MIN_REMAINING_SECONDS) return cached.idToken;

  let idToken: string;
  try {
    idToken = await googleTokens.refreshIdToken(refreshToken);
  } catch (e) {
    if (!(e instanceof RefreshTokenRevokedError)) throw e;
    await prisma.user.update({ where: { id: ownerId }, data: { googleRefreshToken: null } });
    ownerTokens.delete(cacheKey);
    throw ownerConsentRequired();
  }

  const { sub, exp } = jose.decodeJwt(idToken);
  if (sub !== owner.googleId || !exp) {
    throw new InternalServerError("Refreshed id_token is not the owner's");
  }
  ownerTokens.set(cacheKey, { idToken, exp });
  return idToken;
}

// ==========================================================================
// Invites
// ==========================================================================

const normalizeEmail = (email: string) => email.trim().toLowerCase();

/** Binds every unbound share addressed to `email` to this user. Called at login. */
export async function bindPendingShares(userId: bigint, email: string) {
  await prisma.deviceShare.updateMany({
    where: { email: normalizeEmail(email), userId: null, device: { userId: { not: userId } } },
    data: { userId },
  });
}

const shareJson = (share: {
  id: bigint;
  email: string;
  userId: bigint | null;
  createdAt: Date;
}) => ({
  id: share.id.toString(),
  email: share.email,
  // Whether the invitee has logged in since; until then it is only an address.
  accepted: share.userId !== null,
  // Whether ALLOWED_IDENTITIES lets the invitee log in at all.
  allowed: isIdentityAllowed(share.email),
  createdAt: share.createdAt,
});

// ==========================================================================
// Routes, all owner-only
// ==========================================================================

export const List = async (req: express.Request<{ id: string }>, res: express.Response) => {
  const device = await findOwnedDevice(req.params.id, sessionSub(req));
  const shares = await prisma.deviceShare.findMany({
    where: { deviceId: device.id },
    orderBy: { createdAt: "asc" },
  });
  return res.json({
    shares: shares.map(shareJson),
    ownerConsent: !!device.user.googleRefreshToken,
  });
};

export const Create = async (req: express.Request<{ id: string }>, res: express.Response) => {
  const device = await findOwnedDevice(req.params.id, sessionSub(req));

  const raw = (req.body as { email?: unknown })?.email;
  if (typeof raw !== "string") throw new UnprocessableEntityError("Missing email in body");
  const email = normalizeEmail(raw);
  if (email.length > 320 || !/^[^\s@]+@[^\s@]+$/.test(email)) {
    throw new UnprocessableEntityError("Invalid email", "invalid_email");
  }
  if (device.user.email && email === normalizeEmail(device.user.email)) {
    throw new UnprocessableEntityError("The owner cannot share a device with themselves", "self_share");
  }

  // Bind now if the invitee already has an account; otherwise their next login does.
  const invitee = await prisma.user.findFirst({
    where: { email: { equals: email, mode: "insensitive" }, id: { not: device.user.id } },
    select: { id: true },
  });

  const share = await prisma.deviceShare.upsert({
    where: { deviceId_email: { deviceId: device.id, email } },
    update: {},
    create: { deviceId: device.id, email, userId: invitee?.id ?? null },
  });
  return res.status(201).json({ share: shareJson(share) });
};

export const Delete = async (
  req: express.Request<{ id: string; shareId: string }>,
  res: express.Response,
) => {
  const device = await findOwnedDevice(req.params.id, sessionSub(req));
  if (!/^\d{1,18}$/.test(req.params.shareId)) throw new NotFoundError("Share not found");

  const { count } = await prisma.deviceShare.deleteMany({
    where: { id: BigInt(req.params.shareId), deviceId: device.id },
  });
  if (count === 0) throw new NotFoundError("Share not found");
  return res.status(204).send();
};
