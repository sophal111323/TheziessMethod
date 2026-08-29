import { checkForeignerKeyStatus, verifyForeignerKey } from "../_db.js";

function readJsonBody(req) {
  if (!req.body) return {};
  if (typeof req.body === "object") return req.body;
  if (typeof req.body === "string") {
    try {
      return JSON.parse(req.body);
    } catch {
      return {};
    }
  }
  return {};
}

export default async function handler(req, res) {
  res.setHeader(
    "Cache-Control",
    "private, no-store, no-cache, must-revalidate, max-age=0",
  );

  if (req.method === "GET") {
    const key = req.query?.key || "";
    try {
      const status = await checkForeignerKeyStatus(key);
      return res.status(200).json({
        ok: true,
        ...status,
      });
    } catch (error) {
      console.error("Foreigner key check error:", error);
      return res.status(500).json({
        ok: false,
        valid: false,
        error: "Unable to check access key status.",
      });
    }
  }

  if (req.method === "POST") {
    const body = readJsonBody(req);
    const key = String(body.key || body.keyCode || "").trim();

    if (!key) {
      return res.status(400).json({
        ok: false,
        code: "KEY_REQUIRED",
        error: "Please enter an access key.",
      });
    }

    try {
      const result = await verifyForeignerKey(key);

      if (!result.valid) {
        return res.status(401).json({
          ok: false,
          code: result.reason || "INVALID_KEY",
          error: result.error || "The access key is invalid or has expired.",
          expiresAt: result.expiresAt || null,
        });
      }

      return res.status(200).json({
        ok: true,
        key: result.key,
        expiresAt: result.expiresAt,
        durationDays: result.durationDays,
        message: "Access granted for 1 day.",
      });
    } catch (error) {
      console.error("Foreigner key verification error:", error);
      return res.status(500).json({
        ok: false,
        code: "VERIFICATION_ERROR",
        error: "Unable to verify access key right now. Please try again.",
      });
    }
  }

  return res.status(405).json({
    ok: false,
    error: "Method not allowed",
  });
}

