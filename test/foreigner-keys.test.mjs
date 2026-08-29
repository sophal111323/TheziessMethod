import { beforeEach, describe, expect, it, vi } from "vitest";

const db = vi.hoisted(() => ({
    generateForeignerKey: vi.fn(),
    verifyForeignerKey: vi.fn(),
    checkForeignerKeyStatus: vi.fn(),
    listAdminForeignerKeys: vi.fn(),
    revokeForeignerKey: vi.fn(),
    getMaintenanceState: vi.fn().mockResolvedValue({ enabled: false }),
}));

const telegram = vi.hoisted(() => ({
    sendTelegramMessage: vi.fn(),
    answerTelegramCallback: vi.fn(),
}));

vi.mock("../server/routes/_db.js", () => ({
    generateForeignerKey: db.generateForeignerKey,
    verifyForeignerKey: db.verifyForeignerKey,
    checkForeignerKeyStatus: db.checkForeignerKeyStatus,
    listAdminForeignerKeys: db.listAdminForeignerKeys,
    revokeForeignerKey: db.revokeForeignerKey,
    getMaintenanceState: db.getMaintenanceState,
}));

vi.mock("../server/routes/_telegram-bot.js", () => ({
    answerTelegramCallback: telegram.answerTelegramCallback,
    escapeTelegramHtml: (value) =>
        String(value ?? "")
            .replace(/&/g, "&amp;")
            .replace(/</g, "&lt;")
            .replace(/>/g, "&gt;"),
    getTelegramWebhookSecret: () => "website-webhook-secret",
    isTelegramAdmin: (userId) => String(userId) === "123",
    safeEqual: (left, right) => left === right,
    sendTelegramMessage: telegram.sendTelegramMessage,
}));

import verifyKeyHandler from "../server/routes/foreigner/verify-key.js";
import telegramWebhook from "../server/routes/telegram/webhook.js";

function createResponse() {
    return {
        headers: {},
        statusCode: 200,
        payload: null,
        setHeader(name, value) {
            this.headers[name] = value;
        },
        status(code) {
            this.statusCode = code;
            return this;
        },
        json(payload) {
            this.payload = payload;
            return this;
        },
    };
}

describe("Foreigner 1-day access key system", () => {
    beforeEach(() => {
        db.generateForeignerKey.mockReset();
        db.verifyForeignerKey.mockReset();
        db.checkForeignerKeyStatus.mockReset();
        db.listAdminForeignerKeys.mockReset();
        db.revokeForeignerKey.mockReset();
        telegram.sendTelegramMessage.mockReset();
        telegram.answerTelegramCallback.mockReset();
    });

    describe("Telegram Bot Admin Key Generation", () => {
        it("allows Telegram admin to generate a 1-day access key via /key command", async () => {
            const fakeKey = {
                id: 1,
                key_code: "TZF-A1B2-C3D4",
                created_by: "123",
                duration_days: 1,
                created_at: new Date().toISOString(),
                expires_at: new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString(),
                is_revoked: false,
                used_count: 0,
            };
            db.generateForeignerKey.mockResolvedValue(fakeKey);

            const response = createResponse();
            await telegramWebhook(
                {
                    method: "POST",
                    headers: {
                        "x-telegram-bot-api-secret-token": "website-webhook-secret",
                    },
                    body: {
                        message: {
                            chat: { id: 777, type: "private" },
                            from: { id: 123 },
                            text: "/key",
                        },
                    },
                },
                response,
            );

            expect(response.statusCode).toBe(200);
            expect(db.generateForeignerKey).toHaveBeenCalledWith({
                adminTelegramId: 123,
                durationDays: 1,
            });
            expect(telegram.sendTelegramMessage).toHaveBeenCalledWith(
                777,
                expect.stringContaining("TZF-A1B2-C3D4"),
                expect.any(Object),
            );
        });

        it("allows Telegram admin to generate key via /genkey and /foreignerkey aliases", async () => {
            const fakeKey = {
                id: 2,
                key_code: "TZF-9988-7766",
                created_by: "123",
                duration_days: 1,
                created_at: new Date().toISOString(),
                expires_at: new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString(),
            };
            db.generateForeignerKey.mockResolvedValue(fakeKey);

            const response = createResponse();
            await telegramWebhook(
                {
                    method: "POST",
                    headers: {
                        "x-telegram-bot-api-secret-token": "website-webhook-secret",
                    },
                    body: {
                        message: {
                            chat: { id: 777, type: "private" },
                            from: { id: 123 },
                            text: "/genkey",
                        },
                    },
                },
                response,
            );

            expect(response.statusCode).toBe(200);
            expect(db.generateForeignerKey).toHaveBeenCalled();
            expect(telegram.sendTelegramMessage).toHaveBeenCalledWith(
                777,
                expect.stringContaining("TZF-9988-7766"),
                expect.any(Object),
            );
        });

        it("allows Telegram admin to generate key via callback query", async () => {
            const fakeKey = {
                id: 3,
                key_code: "TZF-1122-3344",
                created_by: "123",
                duration_days: 1,
                expires_at: new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString(),
            };
            db.generateForeignerKey.mockResolvedValue(fakeKey);

            const response = createResponse();
            await telegramWebhook(
                {
                    method: "POST",
                    headers: {
                        "x-telegram-bot-api-secret-token": "website-webhook-secret",
                    },
                    body: {
                        callback_query: {
                            id: "cb_123",
                            from: { id: 123 },
                            message: { chat: { id: 777 } },
                            data: "admin:foreigner:newkey",
                        },
                    },
                },
                response,
            );

            expect(response.statusCode).toBe(200);
            expect(telegram.answerTelegramCallback).toHaveBeenCalledWith("cb_123");
            expect(db.generateForeignerKey).toHaveBeenCalled();
            expect(telegram.sendTelegramMessage).toHaveBeenCalledWith(
                777,
                expect.stringContaining("TZF-1122-3344"),
                expect.any(Object),
            );
        });

        it("silently ignores non-admin attempts to run /key or /keys", async () => {
            const response = createResponse();
            await telegramWebhook(
                {
                    method: "POST",
                    headers: {
                        "x-telegram-bot-api-secret-token": "website-webhook-secret",
                    },
                    body: {
                        message: {
                            chat: { id: 777, type: "private" },
                            from: { id: 999 }, // not admin
                            text: "/key",
                        },
                    },
                },
                response,
            );

            expect(response.statusCode).toBe(200);
            expect(db.generateForeignerKey).not.toHaveBeenCalled();
            expect(telegram.sendTelegramMessage).not.toHaveBeenCalled();
        });

        it("allows admin to list keys with /keys", async () => {
            db.listAdminForeignerKeys.mockResolvedValue([
                {
                    id: 1,
                    key_code: "TZF-AAAA-BBBB",
                    expires_at: new Date(Date.now() + 100000).toISOString(),
                    is_revoked: false,
                    used_count: 3,
                },
            ]);

            const response = createResponse();
            await telegramWebhook(
                {
                    method: "POST",
                    headers: {
                        "x-telegram-bot-api-secret-token": "website-webhook-secret",
                    },
                    body: {
                        message: {
                            chat: { id: 777, type: "private" },
                            from: { id: 123 },
                            text: "/keys",
                        },
                    },
                },
                response,
            );

            expect(response.statusCode).toBe(200);
            expect(db.listAdminForeignerKeys).toHaveBeenCalledWith(10);
            expect(telegram.sendTelegramMessage).toHaveBeenCalledWith(
                777,
                expect.stringContaining("TZF-AAAA-BBBB"),
                expect.any(Object),
            );
        });

        it("allows admin to revoke key with /revokekey", async () => {
            db.revokeForeignerKey.mockResolvedValue({
                key_code: "TZF-REVOKE-ME",
                is_revoked: true,
            });

            const response = createResponse();
            await telegramWebhook(
                {
                    method: "POST",
                    headers: {
                        "x-telegram-bot-api-secret-token": "website-webhook-secret",
                    },
                    body: {
                        message: {
                            chat: { id: 777, type: "private" },
                            from: { id: 123 },
                            text: "/revokekey TZF-REVOKE-ME",
                        },
                    },
                },
                response,
            );

            expect(response.statusCode).toBe(200);
            expect(db.revokeForeignerKey).toHaveBeenCalledWith("TZF-REVOKE-ME");
            expect(telegram.sendTelegramMessage).toHaveBeenCalledWith(
                777,
                expect.stringContaining("has been revoked"),
                expect.any(Object),
            );
        });
    });

    describe("Foreigner Key Verification API", () => {
        it("returns 200 and access data when verifying a valid key", async () => {
            const expiryTime = Date.now() + 24 * 60 * 60 * 1000;
            db.verifyForeignerKey.mockResolvedValue({
                valid: true,
                key: "TZF-VALID-1234",
                expiresAt: expiryTime,
                durationDays: 1,
            });

            const response = createResponse();
            await verifyKeyHandler(
                {
                    method: "POST",
                    body: { key: "TZF-VALID-1234" },
                },
                response,
            );

            expect(response.statusCode).toBe(200);
            expect(response.payload.ok).toBe(true);
            expect(response.payload.key).toBe("TZF-VALID-1234");
            expect(response.payload.expiresAt).toBe(expiryTime);
            expect(response.payload.durationDays).toBe(1);
        });

        it("returns 401 when verifying an expired key", async () => {
            db.verifyForeignerKey.mockResolvedValue({
                valid: false,
                reason: "KEY_EXPIRED",
                error: "This access key has expired (1-day limit reached).",
            });

            const response = createResponse();
            await verifyKeyHandler(
                {
                    method: "POST",
                    body: { key: "TZF-EXPIRED-KEY" },
                },
                response,
            );

            expect(response.statusCode).toBe(401);
            expect(response.payload.ok).toBe(false);
            expect(response.payload.code).toBe("KEY_EXPIRED");
        });

        it("returns 400 when submitting an empty key", async () => {
            const response = createResponse();
            await verifyKeyHandler(
                {
                    method: "POST",
                    body: { key: "" },
                },
                response,
            );

            expect(response.statusCode).toBe(400);
            expect(response.payload.ok).toBe(false);
            expect(response.payload.code).toBe("KEY_REQUIRED");
        });

        it("returns 401 when key is revoked", async () => {
            db.verifyForeignerKey.mockResolvedValue({
                valid: false,
                reason: "KEY_REVOKED",
                error: "This access key has been revoked.",
            });

            const response = createResponse();
            await verifyKeyHandler(
                {
                    method: "POST",
                    body: { key: "TZF-REVOKED-KEY" },
                },
                response,
            );

            expect(response.statusCode).toBe(401);
            expect(response.payload.ok).toBe(false);
            expect(response.payload.code).toBe("KEY_REVOKED");
        });

        it("supports GET /api/foreigner/verify-key?key=... for status checks", async () => {
            const expiryTime = Date.now() + 12 * 60 * 60 * 1000;
            db.checkForeignerKeyStatus.mockResolvedValue({
                valid: true,
                key: "TZF-CHECK-KEY",
                expiresAt: expiryTime,
                durationDays: 1,
            });

            const response = createResponse();
            await verifyKeyHandler(
                {
                    method: "GET",
                    query: { key: "TZF-CHECK-KEY" },
                },
                response,
            );

            expect(response.statusCode).toBe(200);
            expect(response.payload.ok).toBe(true);
            expect(response.payload.valid).toBe(true);
            expect(response.payload.expiresAt).toBe(expiryTime);
        });
    });
});

