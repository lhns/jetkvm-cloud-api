import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { Request, Response } from "express";

import { testPrisma } from "./setup";

// Session tokens are unsigned test JWTs: signature checks are stubbed, claims are real.
vi.mock("jose", async importOriginal => {
  const actual = await importOriginal<typeof import("jose")>();
  return {
    ...actual,
    createRemoteJWKSet: () => () => undefined,
    jwtVerify: async (token: string) => ({ payload: actual.decodeJwt(token), protectedHeader: {} }),
  };
});

// Google, as seen through openid-client.
const google = vi.hoisted(() => ({
  authorizationUrl: vi.fn((params: Record<string, string>) => {
    return `https://accounts.google.test/auth?${new URLSearchParams(params)}`;
  }),
  callbackParams: vi.fn(() => ({ state: "csrf=csrf-state" })),
  callback: vi.fn(),
  userinfo: vi.fn(),
  refresh: vi.fn(),
}));
vi.mock("openid-client", () => ({
  generators: { state: () => "csrf-state", codeVerifier: () => "verifier", codeChallenge: () => "challenge" },
  Issuer: { discover: async () => ({ Client: function Client() { return google; } }) },
}));

// webrtc-signaling imports the cookie middleware from src/index.ts, which would start a server.
vi.mock("../src/index", () => ({ cookieSessionMiddleware: () => undefined }));

const OWNER = { sub: "share-test-owner", email: "owner@example.com" };
const FRIEND = { sub: "share-test-friend", email: "friend@example.com" };
const STRANGER = { sub: "share-test-stranger", email: "stranger@example.com" };
const LATE = { sub: "share-test-late", email: "late@example.com" };
const OUTSIDER = { sub: "share-test-outsider", email: "outsider@example.com" };
const ALL = [OWNER, FRIEND, STRANGER, LATE, OUTSIDER];
const DEVICE = "share-test-device";
const OTHER_DEVICE = "share-test-other-device";

process.env.ALLOWED_IDENTITIES = [OWNER, FRIEND, STRANGER, LATE].map(u => u.email).join(",");
process.env.COOKIE_SECRET = "share-test-cookie-secret";
process.env.GOOGLE_CLIENT_ID = "share-test-client";
process.env.APP_HOSTNAME = "https://app.test";
process.env.API_HOSTNAME = "https://api.test";
process.env.CLOUDFLARE_TURN_ID = "turn-id";
process.env.CLOUDFLARE_TURN_TOKEN = "turn-token";

const Devices = await import("../src/devices");
const Sharing = await import("../src/sharing");
const Webrtc = await import("../src/webrtc");
const OIDC = await import("../src/oidc");
const { authenticated } = await import("../src/auth");
const { activeConnections, authenticateClientRequest, setupClientWebSocket } = await import(
  "../src/webrtc-signaling"
);

type User = { sub: string; email: string };

function jwt(user: User, lifetime = 3600) {
  const encode = (value: unknown) => Buffer.from(JSON.stringify(value)).toString("base64url");
  const now = Math.floor(Date.now() / 1000);
  return `${encode({ alg: "none" })}.${encode({
    iss: "https://accounts.google.com",
    aud: "share-test-client",
    sub: user.sub,
    email: user.email,
    iat: now,
    exp: now + lifetime,
  })}.`;
}

function request(
  user: User | null,
  { params = {}, body = {} }: { params?: Record<string, string>; body?: unknown } = {},
) {
  return {
    params,
    body,
    headers: {},
    query: {},
    session: user ? { id_token: jwt(user) } : {},
    socket: { on: () => undefined, off: () => undefined },
  } as unknown as Request<any>;
}

function response() {
  const res = {
    statusCode: 200,
    body: undefined as any,
    redirectedTo: undefined as string | undefined,
    status(code: number) {
      res.statusCode = code;
      return res;
    },
    json(data: unknown) {
      res.body = data;
      return res;
    },
    send(data?: unknown) {
      res.body = data;
      return res;
    },
    redirect(url: string) {
      res.redirectedTo = url;
      return res;
    },
  };
  return res as typeof res & Response;
}

async function call(handler: (req: any, res: any) => Promise<unknown>, req: Request<any>) {
  const res = response();
  await handler(req, res);
  return res;
}

/** An online device that answers every offer and records what it was sent. */
function connectDevice(id = DEVICE) {
  const sent: any[] = [];
  const ws: any = {
    onmessage: null,
    onerror: null,
    onclose: null,
    send(data: string) {
      sent.push(JSON.parse(data));
      setImmediate(() => ws.onmessage?.({ data: JSON.stringify({ sd: "answer-sd" }) }));
    },
  };
  activeConnections.set(id, { ws, ip: "203.0.113.7", version: "0.5.8", sku: null });
  return sent;
}

const userId = async (user: User) =>
  (await testPrisma.user.findUniqueOrThrow({ where: { googleId: user.sub } })).id;

/** Owner's refresh grant: a fresh Google id_token for the owner. */
function ownerRefreshWorks() {
  google.refresh.mockImplementation(async () => ({ id_token: jwt(OWNER) }));
}

async function cleanup() {
  await testPrisma.deviceShare.deleteMany({ where: { deviceId: { in: [DEVICE, OTHER_DEVICE] } } });
  await testPrisma.device.deleteMany({ where: { id: { in: [DEVICE, OTHER_DEVICE] } } });
  const subs = ALL.map(u => u.sub);
  await testPrisma.turnActivity.deleteMany({ where: { user: { googleId: { in: subs } } } });
  await testPrisma.user.deleteMany({ where: { googleId: { in: subs } } });
}

beforeEach(async () => {
  await cleanup();
  activeConnections.clear();
  Sharing.clearOwnerTokenCache();
  vi.clearAllMocks();
  ownerRefreshWorks();

  for (const user of [OWNER, FRIEND, STRANGER, OUTSIDER]) {
    await testPrisma.user.create({ data: { googleId: user.sub, email: user.email } });
  }
  await testPrisma.user.update({
    where: { googleId: OWNER.sub },
    data: { googleRefreshToken: Sharing.sealRefreshToken("owner-refresh-token") },
  });
  await testPrisma.device.create({
    data: { id: DEVICE, name: "rack", userId: await userId(OWNER) },
  });
  await testPrisma.deviceShare.create({
    data: { deviceId: DEVICE, email: FRIEND.email, userId: await userId(FRIEND) },
  });
});

afterEach(cleanup);

describe("access matrix", () => {
  it("lists owned and shared devices, and nothing for a stranger", async () => {
    const owner = await call(Devices.List, request(OWNER));
    expect(owner.body.devices).toEqual([expect.objectContaining({ id: DEVICE, shared: false })]);
    expect(owner.body.devices[0]).not.toHaveProperty("ownerEmail");

    const friend = await call(Devices.List, request(FRIEND));
    expect(friend.body.devices).toEqual([
      expect.objectContaining({ id: DEVICE, name: "rack", shared: true, ownerEmail: OWNER.email }),
    ]);
    expect(friend.body.devices[0]).not.toHaveProperty("user");

    const stranger = await call(Devices.List, request(STRANGER));
    expect(stranger.body.devices).toEqual([]);
  });

  it("gets a device as owner or shared user, never as a stranger", async () => {
    const owner = await call(Devices.Retrieve, request(OWNER, { params: { id: DEVICE } }));
    expect(owner.body.device).toMatchObject({ id: DEVICE, shared: false, user: { googleId: OWNER.sub } });

    const friend = await call(Devices.Retrieve, request(FRIEND, { params: { id: DEVICE } }));
    expect(friend.body.device).toMatchObject({ id: DEVICE, shared: true, ownerEmail: OWNER.email });
    // The owner's Google id is not disclosed to a shared user.
    expect(friend.body.device).not.toHaveProperty("user");

    await expect(
      call(Devices.Retrieve, request(STRANGER, { params: { id: DEVICE } })),
    ).rejects.toMatchObject({ status: 404 });
  });

  it("lets only the owner rename", async () => {
    for (const user of [FRIEND, STRANGER]) {
      await expect(
        call(Devices.Update, request(user, { params: { id: DEVICE }, body: { name: "hijacked" } })),
      ).rejects.toMatchObject({ status: 404 });
    }
    expect((await testPrisma.device.findUniqueOrThrow({ where: { id: DEVICE } })).name).toBe("rack");

    await call(Devices.Update, request(OWNER, { params: { id: DEVICE }, body: { name: "desk" } }));
    expect((await testPrisma.device.findUniqueOrThrow({ where: { id: DEVICE } })).name).toBe("desk");
  });

  it("lets only the owner delete, and deleting drops the shares", async () => {
    for (const user of [FRIEND, STRANGER]) {
      await expect(
        call(Devices.Delete, request(user, { params: { id: DEVICE } })),
      ).rejects.toMatchObject({ status: 404 });
    }
    expect(await testPrisma.device.count({ where: { id: DEVICE } })).toBe(1);

    const res = await call(Devices.Delete, request(OWNER, { params: { id: DEVICE } }));
    expect(res.statusCode).toBe(204);
    expect(await testPrisma.device.count({ where: { id: DEVICE } })).toBe(0);
    expect(await testPrisma.deviceShare.count({ where: { deviceId: DEVICE } })).toBe(0);
  });

  it("rejects an unauthenticated delete instead of leaving it hanging", async () => {
    await expect(
      call(Devices.Delete, request(null, { params: { id: DEVICE } })),
    ).rejects.toMatchObject({ status: 400 });
    expect(await testPrisma.device.count({ where: { id: DEVICE } })).toBe(1);
  });

  it("lets only the owner manage shares", async () => {
    const shareId = (await testPrisma.deviceShare.findFirstOrThrow({ where: { deviceId: DEVICE } })).id.toString();
    for (const user of [FRIEND, STRANGER]) {
      await expect(call(Sharing.List, request(user, { params: { id: DEVICE } }))).rejects.toMatchObject({ status: 404 });
      await expect(
        call(Sharing.Create, request(user, { params: { id: DEVICE }, body: { email: STRANGER.email } })),
      ).rejects.toMatchObject({ status: 404 });
      await expect(
        call(Sharing.Delete, request(user, { params: { id: DEVICE, shareId } })),
      ).rejects.toMatchObject({ status: 404 });
    }
    expect(await testPrisma.deviceShare.count({ where: { deviceId: DEVICE } })).toBe(1);

    const list = await call(Sharing.List, request(OWNER, { params: { id: DEVICE } }));
    expect(list.body).toEqual({
      shares: [expect.objectContaining({ id: shareId, email: FRIEND.email, accepted: true, allowed: true })],
      ownerConsent: true,
    });
  });

  it("starts a session as owner with the owner's own token", async () => {
    const sent = connectDevice();
    const req = request(OWNER, { body: { id: DEVICE, sd: "offer-sd" } });
    const res = await call(Webrtc.CreateSession, req);

    expect(res.body).toEqual({ sd: "answer-sd" });
    expect(sent[0].OidcGoogle).toBe(req.session!.id_token);
    expect(google.refresh).not.toHaveBeenCalled();
  });

  it("starts a session as a shared user with a minted owner token", async () => {
    const sent = connectDevice();
    const req = request(FRIEND, { body: { id: DEVICE, sd: "offer-sd" } });
    const res = await call(Webrtc.CreateSession, req);

    expect(res.body).toEqual({ sd: "answer-sd" });
    expect(google.refresh).toHaveBeenCalledWith("owner-refresh-token");
    // The device checks aud:sub against the owner; the shared user's own token never reaches it.
    expect(sent[0].OidcGoogle).not.toBe(req.session!.id_token);
    expect(JSON.parse(Buffer.from(sent[0].OidcGoogle.split(".")[1], "base64url").toString()).sub).toBe(OWNER.sub);
  });

  it("refuses a session to a stranger without contacting the device", async () => {
    const sent = connectDevice();
    await expect(
      call(Webrtc.CreateSession, request(STRANGER, { body: { id: DEVICE, sd: "offer-sd" } })),
    ).rejects.toMatchObject({ status: 404 });
    expect(sent).toEqual([]);
  });

  it("authenticates signaling websockets the same way", async () => {
    const ws = (user: User | null, token?: string) =>
      authenticateClientRequest({
        url: `/webrtc/signaling/client?id=${DEVICE}`,
        session: token ? { id_token: token } : user ? { id_token: jwt(user) } : {},
      } as any);

    const owner = await ws(OWNER);
    expect(owner.deviceId).toBe(DEVICE);
    expect(JSON.parse(Buffer.from((await owner.token!()).split(".")[1], "base64url").toString()).sub).toBe(OWNER.sub);

    const friend = await ws(FRIEND);
    expect(friend.deviceId).toBe(DEVICE);
    expect(JSON.parse(Buffer.from((await friend.token!()).split(".")[1], "base64url").toString()).sub).toBe(OWNER.sub);

    expect((await ws(STRANGER)).deviceId).toBeNull();
    expect((await ws(null)).deviceId).toBeNull();
    expect((await ws(FRIEND, jwt(FRIEND, -60))).deviceId).toBeNull();

    // A share alone is not enough: the user must also be in ALLOWED_IDENTITIES.
    await testPrisma.deviceShare.create({
      data: { deviceId: DEVICE, email: OUTSIDER.email, userId: await userId(OUTSIDER) },
    });
    expect((await ws(OUTSIDER)).deviceId).toBeNull();
  });

  it("forwards an offer before the ICE candidates that follow it", async () => {
    const sent = connectDevice();
    const { EventEmitter } = await import("events");
    const client: any = Object.assign(new EventEmitter(), { send: vi.fn(), close: vi.fn() });
    let release!: () => void;
    const minted = new Promise<void>(resolve => (release = resolve));

    setupClientWebSocket(client, DEVICE, async () => {
      await minted;
      return "owner-token";
    });
    client.emit("message", Buffer.from(JSON.stringify({ type: "offer", data: { sd: "offer-sd" } })));
    client.emit("message", Buffer.from(JSON.stringify({ type: "new-ice-candidate", data: { c: 1 } })));
    await new Promise(resolve => setImmediate(resolve));
    expect(sent).toEqual([]);

    release();
    await vi.waitFor(() => expect(sent.map(m => m.type)).toEqual(["offer", "new-ice-candidate"]));
    expect(sent[0].data.OidcGoogle).toBe("owner-token");
  });

  it("serves ice_config and turn_activity to any allowed user, and nothing unauthenticated", async () => {
    vi.stubGlobal("fetch", vi.fn(async () => ({
      json: async () => ({ iceServers: { urls: ["turn:turn.test:3478"], username: "u", credential: "c" } }),
    })));
    try {
      for (const user of [OWNER, FRIEND, STRANGER]) {
        const res = await call(Webrtc.CreateIceCredentials, request(user));
        expect(res.body.iceServers.urls).toContain("turn:turn.test:3478");
      }
    } finally {
      vi.unstubAllGlobals();
    }

    await call(Webrtc.CreateTurnActivity, request(FRIEND, { body: { bytesSent: 1, bytesReceived: 2 } }));
    expect(await testPrisma.turnActivity.count({ where: { userId: await userId(FRIEND) } })).toBe(1);

    await expect(authenticated(request(null), response(), vi.fn())).rejects.toMatchObject({ status: 401 });
    await expect(authenticated(request(OUTSIDER), response(), vi.fn())).rejects.toMatchObject({ status: 401 });
  });
});

describe("revocation", () => {
  it("ends a shared user's access at the next call", async () => {
    connectDevice();
    const shareId = (await testPrisma.deviceShare.findFirstOrThrow({ where: { deviceId: DEVICE } })).id.toString();
    const res = await call(Sharing.Delete, request(OWNER, { params: { id: DEVICE, shareId } }));
    expect(res.statusCode).toBe(204);

    expect((await call(Devices.List, request(FRIEND))).body.devices).toEqual([]);
    await expect(
      call(Devices.Retrieve, request(FRIEND, { params: { id: DEVICE } })),
    ).rejects.toMatchObject({ status: 404 });
    await expect(
      call(Webrtc.CreateSession, request(FRIEND, { body: { id: DEVICE, sd: "offer-sd" } })),
    ).rejects.toMatchObject({ status: 404 });
    const ws = await authenticateClientRequest({
      url: `/webrtc/signaling/client?id=${DEVICE}`,
      session: { id_token: jwt(FRIEND) },
    } as any);
    expect(ws.deviceId).toBeNull();
  });

  it("will not delete a share through another device", async () => {
    await testPrisma.device.create({ data: { id: OTHER_DEVICE, userId: await userId(OWNER) } });
    const shareId = (await testPrisma.deviceShare.findFirstOrThrow({ where: { deviceId: DEVICE } })).id.toString();
    await expect(
      call(Sharing.Delete, request(OWNER, { params: { id: OTHER_DEVICE, shareId } })),
    ).rejects.toMatchObject({ status: 404 });
    await expect(
      call(Sharing.Delete, request(OWNER, { params: { id: DEVICE, shareId: "not-a-number" } })),
    ).rejects.toMatchObject({ status: 404 });
    expect(await testPrisma.deviceShare.count({ where: { deviceId: DEVICE } })).toBe(1);
  });

  it("ends every share when the owner leaves ALLOWED_IDENTITIES", async () => {
    connectDevice();
    await testPrisma.user.update({ where: { googleId: OWNER.sub }, data: { email: "gone@example.com" } });
    await expect(
      call(Webrtc.CreateSession, request(FRIEND, { body: { id: DEVICE, sd: "offer-sd" } })),
    ).rejects.toMatchObject({ status: 404 });
    expect(google.refresh).not.toHaveBeenCalled();
  });
});

describe("invites by email", () => {
  it("normalises, validates and deduplicates", async () => {
    const add = (email: unknown) =>
      call(Sharing.Create, request(OWNER, { params: { id: DEVICE }, body: { email } }));

    const first = await add("  Stranger@Example.com ");
    expect(first.statusCode).toBe(201);
    expect(first.body.share).toMatchObject({ email: STRANGER.email, accepted: true, allowed: true });
    const again = await add(STRANGER.email);
    expect(again.body.share.id).toBe(first.body.share.id);

    await expect(add(OWNER.email)).rejects.toMatchObject({ status: 422 });
    await expect(add("not-an-email")).rejects.toMatchObject({ status: 422 });
    await expect(add(undefined)).rejects.toMatchObject({ status: 422 });

    // Allowed to invite, but flagged: this address cannot log in until it is allowlisted.
    expect((await add(OUTSIDER.email)).body.share).toMatchObject({ allowed: false });
  });

  it("binds an invite for an unknown address at that account's first login", async () => {
    const invite = await call(
      Sharing.Create,
      request(OWNER, { params: { id: DEVICE }, body: { email: "Late@Example.com" } }),
    );
    expect(invite.body.share).toMatchObject({ email: LATE.email, accepted: false });

    await login(LATE, { email_verified: true });

    const late = await call(Devices.Retrieve, request(LATE, { params: { id: DEVICE } }));
    expect(late.body.device).toMatchObject({ id: DEVICE, shared: true });
    const list = await call(Sharing.List, request(OWNER, { params: { id: DEVICE } }));
    expect(list.body.shares.find((s: any) => s.email === LATE.email)).toMatchObject({ accepted: true });
  });

  it("does not bind an invite to an unverified address", async () => {
    await call(Sharing.Create, request(OWNER, { params: { id: DEVICE }, body: { email: LATE.email } }));
    await login(LATE, { email_verified: false });
    await expect(
      call(Devices.Retrieve, request(LATE, { params: { id: DEVICE } })),
    ).rejects.toMatchObject({ status: 404 });
  });
});

describe("owner consent", () => {
  it("asks Google for offline access only when the owner enables sharing", async () => {
    const plain = response();
    await OIDC.Google({ ...request(null), body: {} } as any, plain);
    expect(plain.redirectedTo).not.toContain("access_type");

    const consent = response();
    await OIDC.Google({ ...request(null), body: { consent: "1" } } as any, consent);
    const params = new URL(consent.redirectedTo!).searchParams;
    expect(params.get("access_type")).toBe("offline");
    expect(params.get("prompt")).toBe("consent");
  });

  it("stores the refresh token sealed and keeps it across plain logins", async () => {
    await testPrisma.user.update({ where: { googleId: OWNER.sub }, data: { googleRefreshToken: null } });

    await login(OWNER, { refresh_token: "fresh-refresh-token" });
    const stored = (await testPrisma.user.findUniqueOrThrow({ where: { googleId: OWNER.sub } })).googleRefreshToken!;
    expect(stored).not.toContain("fresh-refresh-token");
    expect(Sharing.openRefreshToken(stored)).toBe("fresh-refresh-token");

    await login(OWNER, {});
    const kept = (await testPrisma.user.findUniqueOrThrow({ where: { googleId: OWNER.sub } })).googleRefreshToken;
    expect(kept).toBe(stored);
  });

  it("tells a shared user when the owner has not enabled sharing", async () => {
    connectDevice();
    await testPrisma.user.update({ where: { googleId: OWNER.sub }, data: { googleRefreshToken: null } });
    await expect(
      call(Webrtc.CreateSession, request(FRIEND, { body: { id: DEVICE, sd: "offer-sd" } })),
    ).rejects.toMatchObject({ status: 409, code: "owner_consent_required" });
    const list = await call(Sharing.List, request(OWNER, { params: { id: DEVICE } }));
    expect(list.body.ownerConsent).toBe(false);
  });

  it("forgets a refresh token Google has revoked", async () => {
    connectDevice();
    google.refresh.mockRejectedValue(Object.assign(new Error("revoked"), { error: "invalid_grant" }));
    await expect(
      call(Webrtc.CreateSession, request(FRIEND, { body: { id: DEVICE, sd: "offer-sd" } })),
    ).rejects.toMatchObject({ status: 409 });
    expect(
      (await testPrisma.user.findUniqueOrThrow({ where: { googleId: OWNER.sub } })).googleRefreshToken,
    ).toBeNull();
  });

  it("reuses a minted token until it nears expiry", async () => {
    connectDevice();
    await call(Webrtc.CreateSession, request(FRIEND, { body: { id: DEVICE, sd: "a" } }));
    await call(Webrtc.CreateSession, request(FRIEND, { body: { id: DEVICE, sd: "b" } }));
    expect(google.refresh).toHaveBeenCalledTimes(1);

    Sharing.clearOwnerTokenCache();
    google.refresh.mockImplementation(async () => ({ id_token: jwt(OWNER, 60) }));
    await call(Webrtc.CreateSession, request(FRIEND, { body: { id: DEVICE, sd: "c" } }));
    await call(Webrtc.CreateSession, request(FRIEND, { body: { id: DEVICE, sd: "d" } }));
    expect(google.refresh).toHaveBeenCalledTimes(3);
  });

  it("refuses a refreshed token that is not the owner's", async () => {
    connectDevice();
    google.refresh.mockImplementation(async () => ({ id_token: jwt(STRANGER) }));
    await expect(
      call(Webrtc.CreateSession, request(FRIEND, { body: { id: DEVICE, sd: "offer-sd" } })),
    ).rejects.toMatchObject({ status: 500 });
  });

  it("cannot open a token sealed under another COOKIE_SECRET", () => {
    const sealed = Sharing.sealRefreshToken("secret");
    process.env.COOKIE_SECRET = "rotated";
    try {
      expect(Sharing.openRefreshToken(sealed)).toBeNull();
    } finally {
      process.env.COOKIE_SECRET = "share-test-cookie-secret";
    }
  });
});

/** Runs the OIDC callback as `user`, the way Google would complete a login. */
async function login(
  user: User,
  { refresh_token, email_verified = true }: { refresh_token?: string; email_verified?: boolean },
) {
  google.callback.mockResolvedValue({
    id_token: jwt(user),
    refresh_token,
    claims: () => ({ sub: user.sub }),
  });
  google.userinfo.mockResolvedValue({ sub: user.sub, email: user.email, email_verified });
  const req = { ...request(null), session: { csrf: "csrf-state" }, query: { state: "csrf=csrf-state" } };
  const res = response();
  await OIDC.Callback(req as any, res);
  expect(res.redirectedTo).toBe("https://app.test/devices");
}
