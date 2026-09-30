import * as jose from "jose";
import { prisma } from "./db";
import express from "express";
import {
  BadRequestError,
  NotFoundError,
  UnauthorizedError,
  UnprocessableEntityError,
} from "./errors";
import * as crypto from "crypto";
import { verifySessionToken } from "./auth";
import { activeConnections } from "./webrtc-signaling";
import { effectiveSku } from "./skus";
import { accessibleBy, findAccessibleDevice } from "./sharing";

/**
 * Version and SKU are known only while the device holds a signaling
 * connection; they arrive as request headers and live in memory, not in the
 * database. Offline devices report null for both. An online device that
 * sends no SKU header is the original hardware.
 */
function liveDeviceState(id: string) {
  const conn = activeConnections.get(id);
  return {
    online: !!conn,
    version: conn?.version || null,
    sku: conn ? effectiveSku(conn.sku) : null,
  };
}

/** A shared user learns who owns the device, but not the owner's Google id. */
function sharedFields(shared: boolean, ownerEmail: string | null) {
  return shared ? { shared, ownerEmail } : { shared };
}

export const List = async (req: express.Request, res: express.Response) => {
  const idToken = req.session?.id_token;
  const { iss, sub } = jose.decodeJwt(idToken);

  // Authorization server’s identifier for the user
  const isGoogle = iss === "https://accounts.google.com";
  if (isGoogle) {
    if (!sub) throw new UnauthorizedError("Missing sub in token");
    const devices = await prisma.device.findMany({
      where: accessibleBy(sub),
      select: {
        id: true,
        name: true,
        lastSeen: true,
        user: { select: { googleId: true, email: true } },
      },
    });

    return res.json({
      devices: devices.map(({ user, ...device }) => ({
        ...device,
        ...sharedFields(user.googleId !== sub, user.email),
        ...liveDeviceState(device.id),
      })),
    });
  } else {
    throw new BadRequestError("Token is not from Google");
  }
};

export const Retrieve = async (
  req: express.Request<{ id: string }>,
  res: express.Response
) => {
  const idToken = req.session?.id_token;
  const { sub } = jose.decodeJwt(idToken);
  if (!sub) throw new UnauthorizedError("Missing sub in token");
  const { id } = req.params;
  if (!id) throw new UnprocessableEntityError("Missing device id in params");

  const device = await findAccessibleDevice(id, sub);
  if (!device) throw new NotFoundError("Device not found");

  const { user, shared, lastSeen, ...rest } = device;
  return res.status(200).json({
    device: {
      ...rest,
      ...(shared ? {} : { user: { googleId: user.googleId } }),
      ...sharedFields(shared, user.email),
      ...liveDeviceState(device.id),
    },
  });
};

export const Update = async (
  req: express.Request<{ id: string }>,
  res: express.Response
) => {
  const idToken = req.session?.id_token;
  const { sub } = jose.decodeJwt(idToken);
  if (!sub) throw new UnauthorizedError("Missing sub in token");

  const { id } = req.params;
  if (!id) throw new UnprocessableEntityError("Missing device id in params");

  const { name } = req.body as { name: string };
  if (!name) throw new UnprocessableEntityError("Missing name in body");

  // Owner only. A shared user gets the same 404 as a stranger.
  const owned = await prisma.device.findFirst({ where: { id, user: { googleId: sub } } });
  if (!owned) throw new NotFoundError("Device not found");

  const device = await prisma.device.update({
    where: { id, user: { googleId: sub } },
    data: { name },
    select: { id: true },
  });

  return res.json(device);
};

export const Token = async (req: express.Request, res: express.Response) => {
  const { tempToken } = req.body as { tempToken: string };
  if (!tempToken) throw new UnprocessableEntityError("Missing temp token in body");

  const device = await prisma.device.findFirst({ where: { tempToken } });
  if (!device?.tempToken) throw new NotFoundError("Device not found");
  if ((device?.tempTokenExpiresAt || 0) < new Date())
    throw new UnauthorizedError("Token expired");

  const secretToken = crypto.randomBytes(20).toString("hex");

  await prisma.device.update({
    where: { id: device.id },
    data: { secretToken, tempToken: null, tempTokenExpiresAt: null },
  });

  return res.json({ secretToken });
};

export const Delete = async (
  req: express.Request<{ id: string }>,
  res: express.Response
) => {
  if (req.headers.authorization?.startsWith("Bearer ")) {
    const secretToken = req.headers.authorization.split("Bearer ")[1];

    const hasDevice = await prisma.device.findUnique({ where: { secretToken } });
    if (!hasDevice) throw new NotFoundError("Device not found");

    await prisma.device.delete({ where: { secretToken } });
    return res.status(204).send();
  }

  // If the user doesn't have a secret token, we check their session cookie
  try {
    await verifySessionToken(req.session?.id_token);
  } catch (error) {
    throw new BadRequestError("Unauthorized");
  }

  const idToken = req.session?.id_token;
  const { sub } = jose.decodeJwt(idToken);
  if (!sub) throw new UnauthorizedError("Missing sub in token");

  const { id } = req.params;
  if (!id) throw new UnprocessableEntityError("Missing device id in params");

  // Owner only. A shared user gets the same 404 as a stranger.
  const owned = await prisma.device.findFirst({ where: { id, user: { googleId: sub } } });
  if (!owned) throw new NotFoundError("Device not found");

  await prisma.device.delete({ where: { id, user: { googleId: sub } } });

  // We just removed the device, so we should close any running open socket connections
  const conn = activeConnections.get(id);
  if (conn) {
    conn.ws.send("Deregistered from server");
    conn.ws.close();
  }

  return res.status(204).send();
};
