import os
import hmac
import requests
from flask import Flask, request, jsonify
from datetime import datetime, timezone

app = Flask(__name__)

SUPABASE_URL = os.environ.get("SUPABASE_URL", "").rstrip("/")
SUPABASE_KEY = os.environ.get("SUPABASE_SERVICE_ROLE_KEY", "")
ADMIN_SECRET = os.environ.get("ADMIN_SECRET", "")


def database_request(method, params=None, data=None):
    if not SUPABASE_URL or not SUPABASE_KEY:
        raise RuntimeError("Database settings are missing")

  headers = {
    "apikey": SUPABASE_KEY,
    "Authorization": f"Bearer {SUPABASE_KEY}",
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
    return jsonify({"message": "AFK BOT licence server is running"})


@app.route("/verify", methods=["POST"])
def verify_license():
    data = request.get_json(silent=True) or {}
    key_id = data.get("key_id")
    machine_id = data.get("machine_id")

    if not isinstance(key_id, str) or not isinstance(machine_id, str):
        return jsonify({"valid": False, "message": "Invalid request"}), 400

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

        if not rows:
            return jsonify({"valid": False, "message": "Licence not found"})

        if rows[0]["status"] != "active":
            return jsonify({"valid": False, "message": "Licence revoked"})

        return jsonify({"valid": True, "message": "Licence active"})

    except Exception:
        app.logger.exception("Licence verification failed")
        return jsonify({"valid": False, "message": "Server unavailable"}), 503


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
            params={"select": "key_id"},
            data={
                "key_id": key_id,
                "machine_id": machine_id,
                "customer_name": customer_name,
                "status": "active",
            },
        )
        return jsonify({"success": True, "message": "Licence registered"})

    except requests.HTTPError as exc:
        if exc.response is not None and exc.response.status_code == 409:
            return jsonify({"error": "That licence is already registered"}), 409
        app.logger.exception("Licence registration failed")
        return jsonify({"error": "Database error"}), 500
    except Exception:
        app.logger.exception("Licence registration failed")
        return jsonify({"error": "Server unavailable"}), 503


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
        app.logger.exception("Licence revocation failed")
        return jsonify({"error": "Server unavailable"}), 503


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 10000)))
