import {
  generateAuthenticationOptions,
  generateRegistrationOptions,
  verifyAuthenticationResponse,
  verifyRegistrationResponse,
} from "@simplewebauthn/server";
import { ActionError, defineAction, z } from "astro:actions";
import { and, db, eq, isNotNull, Sessions, Users } from "astro:db";

// TODO: Don't hard code?
const rpID = "localhost";
const rpName = "Demo App";
const expectedOrigin = "http://localhost:4321";

export const server = {
  registerOptions: defineAction({
    accept: "json",
    input: z.object({
      username: z.string(),
    }),
    handler: async ({ username }, context) => {
      const options = await generateRegistrationOptions({
        // "rp" stands for Relying Party, which is the server
        rpName,
        rpID,
        userID: new Uint8Array(Buffer.from(username)),
        userName: username,
        attestationType: "indirect",
        authenticatorSelection: {
          userVerification: "required",
        },
        supportedAlgorithmIDs: [-7, -257],
      });

      const id = crypto.randomUUID();
      const challenge = options.challenge;

      // Store the challenge in the session for verification
      await db.insert(Sessions).values({
        challenge,
        id,
      });

      context.cookies.delete("session");
      context.cookies.set("session", id, {
        maxAge: 3600,
        httpOnly: true,
        secure: import.meta.env.PROD,
        // domain: context.url.origin,
        sameSite: "strict",
        path: "/",
      });

      return { options };
    },
  }),
  registerVerify: defineAction({
    accept: "json",
    input: z.object({
      username: z.string(),
      // TODO: Better types?
      attestationResponse: z.any(),
    }),
    handler: async ({ username, attestationResponse }, context) => {
      const sessionCookie = context.cookies.get("session");
      if (!sessionCookie) {
        throw new ActionError({
          code: "NOT_FOUND",
          message: "No session found",
        });
      }

      const id = sessionCookie.value;

      const [existingChallenge] = await db
        .selectDistinct()
        .from(Sessions)
        .where(and(eq(Sessions.id, id), isNotNull(Sessions.challenge)));

      if (existingChallenge && existingChallenge.challenge) {
        await db.delete(Sessions).where(eq(Sessions.id, id));
      } else {
        throw new ActionError({
          code: "NOT_FOUND",
          message: "Existing Challenge not found",
        });
      }

      const expectedChallenge = existingChallenge.challenge;

      const verification = await verifyRegistrationResponse({
        response: attestationResponse,
        expectedChallenge,
        expectedOrigin,
        expectedRPID: "localhost",
      });
      if (!verification.verified || !verification.registrationInfo)
        throw new ActionError({
          message: "Verification failed",
          code: "BAD_REQUEST",
        });

      const { credentialID, credentialPublicKey } =
        verification.registrationInfo;
      const credential = {
        id: credentialID,
        publicKey: Buffer.from(credentialPublicKey).toString("base64"),
      };

      await db.insert(Users).values({
        username,
        id: crypto.randomUUID(),
        credentialPublicKey: credential.publicKey,
        credentialID: credential.id,
      });

      return {
        success: true,
        user: { username },
      } as const;
    },
  }),
  authenticateOptions: defineAction({
    accept: "json",
    input: z.object({
      username: z.string(),
    }),
    handler: async ({ username }, context) => {
      const [existingUser] = await db
        .select()
        .from(Users)
        .where(eq(Users.username, username));

      if (!existingUser) {
        throw new ActionError({
          message: "User not found!",
          code: "NOT_FOUND",
        });
      }

      const options = await generateAuthenticationOptions({
        rpID,
        userVerification: "required",
        allowCredentials: [
          {
            id: existingUser.credentialID,
            transports: [
              "ble",
              "cable",
              "hybrid",
              "internal",
              "nfc",
              "smart-card",
              "usb",
            ],
          },
        ],
      });

      const id = crypto.randomUUID();
      const challenge = options.challenge;

      // Store the challenge in the session for verification
      await db.insert(Sessions).values({ challenge, id });

      context.cookies.delete("session");
      context.cookies.set("session", id, {
        maxAge: 3600,
        httpOnly: true,
        secure: import.meta.env.PROD,
        // domain: context.url.origin,
        sameSite: "strict",
        path: "/",
      });

      return { options };
    },
  }),
  authenticateVerify: defineAction({
    accept: "json",
    input: z.object({
      username: z.string(),
      assertionResponse: z.any(),
    }),
    handler: async ({ username, assertionResponse }, context) => {
      const sessionCookie = context.cookies.get("session");
      if (!sessionCookie) {
        throw new ActionError({
          code: "NOT_FOUND",
          message: "No session found",
        });
      }

      const id = sessionCookie.value;

      const [existingChallenge] = await db
        .selectDistinct()
        .from(Sessions)
        .where(and(eq(Sessions.id, id), isNotNull(Sessions.challenge)));

      if (existingChallenge && existingChallenge.challenge) {
        await db.delete(Sessions).where(eq(Sessions.id, id));
      } else {
        throw new ActionError({
          code: "NOT_FOUND",
          message: "Existing Challenge not found",
        });
      }

      const expectedChallenge = existingChallenge.challenge;

      const [user] = await db
        .select()
        .from(Users)
        .where(eq(Users.username, username));

      if (!user)
        throw new ActionError({
          code: "UNAUTHORIZED",
          message: "Verification failed!",
        });

      const credentialID = user.credentialID;
      const credentialPublicKey = Uint8Array.from(
        Buffer.from(user.credentialPublicKey, "base64"),
      );

      if (assertionResponse.id !== credentialID)
        throw new ActionError({
          code: "UNAUTHORIZED",
          message: "Verification failed!",
        });

      const verification = await verifyAuthenticationResponse({
        response: assertionResponse,
        expectedChallenge,
        expectedOrigin,
        expectedRPID: rpID,
        authenticator: {
          credentialPublicKey,
          credentialID,
          counter: 0,
        },
      });

      if (!verification.verified)
        throw new ActionError({
          code: "UNAUTHORIZED",
          message: "Verification failed!",
        });

      // login successful! create valid user session!

      const session = {
        id: crypto.randomUUID(),
        userId: user.id,
      };

      await db.insert(Sessions).values(session);

      context.cookies.delete("session");
      context.cookies.set("session", session.id, {
        httpOnly: true,
        secure: import.meta.env.PROD,
        // domain: context.url.origin,
        sameSite: "strict",
        path: "/",
      });

      return {
        user,
      };
    },
  }),
};
