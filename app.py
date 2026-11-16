
import os
import hmac
import requests
from datetime import datetime, timezone
from flask import Flask, request, jsonify

app = Flask(__name__)

SUPABASE_URL = os.environ.get("SUPABASE_URL", "").rstrip("/")
SUPABASE_KEY = os.environ.get("SUPABASE_SERVICE_ROLE_KEY", "")
ADMIN_SECRET = os.environ.get("ADMIN_SECRET", "")


def database_request(method, params=None, data=None):
    if not SUPABASE_URL or not SUPABASE_KEY:
        raise RuntimeError("Database settings are missing")

   headers = {
    "apikey": SUPABASE_KEY,
    "Content-Type": "application/json",
    "Prefer": "return=representation",
}
    }

    response = requests.request(
        method,
        f"{SUPABASE_URL}/rest/v1/licenses",
        headers=headers,
        params=params,
        json=data,
        timeout=15,
    )
    response.raise_for_status()
    return response.json() if response.content else []


def admin_authorized():
    supplied = request.headers.get("X-Admin-Secret", "")
    return bool(ADMIN_SECRET) and hmac.compare_digest(
        supplied, ADMIN_SECRET
    )


@app.route("/", methods=["GET"])
def home():
    return jsonify({
        "message": "AFK BOT licence server is running"
    })


@app.route("/verify", methods=["POST"])
def verify_license():
    data = request.get_json(silent=True) or {}
    key_id = data.get("key_id")
    machine_id = data.get("machine_id")

    if not isinstance(key_id, str) or not isinstance(machine_id, str):
        return jsonify({"valid": False}), 400

    try:
        rows = database_request(
            "GET",
            params={
                "select": "key_id,status",
                "key_id": f"eq.{key_id}",
                "machine_id": f"eq.{machine_id}",
                "limit": "1",
            },
        )

        if not rows or rows[0]["status"] != "active":
            return jsonify({
                "valid": False,
                "message": "Licence invalid or revoked"
            })

        return jsonify({"valid": True})

    except Exception:
        app.logger.exception("Verification failed")
        return jsonify({"valid": False}), 503


@app.route("/register", methods=["POST"])
def register_license():
    if not admin_authorized():
        return jsonify({"error": "Unauthorized"}), 401

    data = request.get_json(silent=True) or {}
    key_id = data.get("key_id")
    machine_id = data.get("machine_id")
    customer_name = data.get("customer_name", "")

    if not isinstance(key_id, str) or not key_id.strip():
        return jsonify({"error": "Missing key_id"}), 400

    if not isinstance(machine_id, str) or not machine_id.strip():
        return jsonify({"error": "Missing machine_id"}), 400

    try:
        database_request(
            "POST",
            data={
                "key_id": key_id,
                "machine_id": machine_id,
                "customer_name": customer_name,
                "status": "active",
            },
        )
        return jsonify({"success": True})

    except Exception:
        app.logger.exception("Registration failed")
        return jsonify({"error": "Registration failed"}), 500


@app.route("/revoke", methods=["POST"])
def revoke_license():
    if not admin_authorized():
        return jsonify({"error": "Unauthorized"}), 401

    data = request.get_json(silent=True) or {}
    key_id = data.get("key_id")

    if not isinstance(key_id, str) or not key_id.strip():
        return jsonify({"error": "Missing key_id"}), 400

    try:
        rows = database_request(
            "PATCH",
            params={
                "key_id": f"eq.{key_id}",
                "select": "key_id",
            },
            data={
                "status": "revoked",
                "revoked_at": datetime.now(timezone.utc).isoformat(),
            },
        )

        if not rows:
            return jsonify({"error": "Licence not found"}), 404

        return jsonify({"success": True, "message": "Licence revoked"})

    except Exception:
        app.logger.exception("Revocation failed")
        return jsonify({"error": "Revocation failed"}), 500


if __name__ == "__main__":
    app.run(
        host="0.0.0.0",
        port=int(os.environ.get("PORT", 10000))
    )
