const { onRequest } = require("firebase-functions/v2/https");
const logger = require("firebase-functions/logger");
const admin = require("firebase-admin");

admin.initializeApp();
const db = admin.firestore();

exports.activateCode = onRequest(
  { cors: true },
  async (req, res) => {
    try {
      if (req.method !== "POST") {
        return res.status(405).json({
          ok: false,
          status: "method_not_allowed",
          message: "POST only"
        });
      }

      const { quiz_id, access_code, device_token } = req.body || {};

      if (!quiz_id || !access_code || !device_token) {
        return res.status(400).json({
          ok: false,
          status: "bad_request",
          message: "Missing required fields."
        });
      }

      const cleanCode = String(access_code).trim().toUpperCase();
      const docRef = db.collection("quiz_access_codes").doc(cleanCode);
      const docSnap = await docRef.get();

      if (!docSnap.exists) {
        return res.status(404).json({
          ok: false,
          status: "invalid_code",
          message: "Invalid access code."
        });
      }

      const data = docSnap.data();

      if (data.quizId !== quiz_id) {
        return res.status(403).json({
          ok: false,
          status: "wrong_quiz",
          message: "This code does not belong to this quiz."
        });
      }

      if (data.status === "revoked") {
        return res.status(403).json({
          ok: false,
          status: "revoked",
          message: "This access code has been revoked."
        });
      }

      if (data.expiresAt && new Date(data.expiresAt) < new Date()) {
        return res.status(403).json({
          ok: false,
          status: "expired",
          message: "This access code has expired."
        });
      }

      if (data.status === "unused") {
        await docRef.update({
          status: "active",
          deviceToken: device_token,
          activatedAt: new Date().toISOString(),
          lastSeenAt: new Date().toISOString()
        });

        return res.status(200).json({
          ok: true,
          status: "activated",
          message: "Access granted. This device is now linked."
        });
      }

      if (data.status === "active" && data.deviceToken === device_token) {
        await docRef.update({
          lastSeenAt: new Date().toISOString()
        });

        return res.status(200).json({
          ok: true,
          status: "recognized",
          message: "Welcome back."
        });
      }

      return res.status(403).json({
        ok: false,
        status: "locked_to_other_device",
        message: "This code is already active on another device."
      });

    } catch (error) {
      logger.error(error);
      return res.status(500).json({
        ok: false,
        status: "server_error",
        message: "Unexpected server error."
      });
    }
  }
);
