import base64
import hashlib
import json
import os
import shlex
from datetime import datetime, timezone
from pathlib import Path
from threading import Lock
from uuid import uuid4

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa, utils
from flask import Flask, jsonify, redirect, render_template, request, send_from_directory, url_for
from werkzeug.utils import secure_filename


BASE_DIR = Path(__file__).resolve().parent
UPLOAD_DIR = BASE_DIR / "uploads"
DATA_DIR = BASE_DIR / "data"
LOG_FILE = DATA_DIR / "logs.json"
COLLISION_DIR = BASE_DIR / "demo_collisions"

HASH_FUNCTIONS = {
    "md5": hashlib.md5,
    "sha1": hashlib.sha1,
    "sha256": hashlib.sha256,
}

PREHASH_ALGORITHMS = {
    "md5": hashes.MD5(),
    "sha1": hashes.SHA1(),
    "sha256": hashes.SHA256(),
}

SECURITY_LABELS = {
    "md5": "Weak",
    "sha1": "Deprecated",
    "sha256": "Secure",
}

LOG_LOCK = Lock()
LAB_LOCK = Lock()
LAB_SESSIONS = {}

PRIVATE_KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)
PUBLIC_KEY = PRIVATE_KEY.public_key()

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 16 * 1024 * 1024


def ensure_storage() -> None:
    UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    COLLISION_DIR.mkdir(parents=True, exist_ok=True)
    if not LOG_FILE.exists():
        LOG_FILE.write_text("[]", encoding="utf-8")


ensure_storage()


def compute_digest(data: bytes, algorithm: str) -> tuple[bytes, str]:
    digest = HASH_FUNCTIONS[algorithm](data).digest()
    return digest, digest.hex()


def save_bytes(filename: str, content: bytes, prefix: str) -> str:
    safe_name = secure_filename(filename) or "uploaded_file.bin"
    stored_name = f"{prefix}_{uuid4().hex}_{safe_name}"
    target = UPLOAD_DIR / stored_name
    target.write_bytes(content)
    return stored_name


def build_preview(data: bytes, size: int = 16) -> dict[str, str]:
    sample = data[:size]
    ascii_preview = "".join(chr(byte) if 32 <= byte <= 126 else "." for byte in sample)
    return {
        "hex": sample.hex(" "),
        "ascii": ascii_preview or "(empty file)",
    }


def build_text_preview(data: bytes, size: int = 240) -> str:
    sample = data[:size].decode("utf-8", errors="replace")
    sanitized = sample.replace("\r", "")
    return sanitized or "(empty file)"


def build_hex_preview(data: bytes, size: int = 64) -> str:
    sample = data[:size]
    return sample.hex(" ") or "(empty file)"


def sign_digest(digest: bytes, algorithm: str) -> bytes:
    return PRIVATE_KEY.sign(
        digest,
        padding.PKCS1v15(),
        utils.Prehashed(PREHASH_ALGORITHMS[algorithm]),
    )


def verify_digest_signature(digest: bytes, signature: bytes, algorithm: str) -> bool:
    try:
        PUBLIC_KEY.verify(
            signature,
            digest,
            padding.PKCS1v15(),
            utils.Prehashed(PREHASH_ALGORITHMS[algorithm]),
        )
        return True
    except InvalidSignature:
        return False


def append_log(entry: dict) -> None:
    with LOG_LOCK:
        try:
            existing = json.loads(LOG_FILE.read_text(encoding="utf-8"))
            if not isinstance(existing, list):
                existing = []
        except (FileNotFoundError, json.JSONDecodeError):
            existing = []
        existing.append(entry)
        LOG_FILE.write_text(json.dumps(existing[-100:], indent=2), encoding="utf-8")


def load_logs() -> list[dict]:
    try:
        data = json.loads(LOG_FILE.read_text(encoding="utf-8"))
        if isinstance(data, list):
            return list(reversed(data))
    except (FileNotFoundError, json.JSONDecodeError):
        pass
    return []


def load_collision_demo() -> dict:
    file_a = COLLISION_DIR / "md5_collision_a.txt"
    file_b = COLLISION_DIR / "md5_collision_b.txt"
    data_a = file_a.read_bytes()
    data_b = file_b.read_bytes()
    _, md5_a = compute_digest(data_a, "md5")
    _, md5_b = compute_digest(data_b, "md5")
    _, sha256_a = compute_digest(data_a, "sha256")
    _, sha256_b = compute_digest(data_b, "sha256")
    return {
        "file_a": {
            "name": file_a.name,
            "content": data_a.decode("utf-8"),
            "md5": md5_a,
            "sha256": sha256_a,
        },
        "file_b": {
            "name": file_b.name,
            "content": data_b.decode("utf-8"),
            "md5": md5_b,
            "sha256": sha256_b,
        },
        "collision": md5_a == md5_b,
        "note": "These two predefined text files share the same MD5 value even though their contents differ.",
    }


def simulate_encryption(data: bytes, enabled: bool) -> tuple[bytes, str]:
    if not enabled:
        return data, "Encryption disabled. File content was transferred in plain form for this educational demo."
    return data, "AES simulation enabled. The platform pretended to encrypt the file before delivery and decrypt it on receipt."


def build_hash_tool_result(uploaded_file, algorithm: str) -> dict:
    if uploaded_file is None or uploaded_file.filename == "":
        raise ValueError("Please choose a file to hash.")

    if algorithm not in HASH_FUNCTIONS:
        raise ValueError("Unsupported hash algorithm selected.")

    file_bytes = uploaded_file.read()
    _digest, hash_value = compute_digest(file_bytes, algorithm)
    return {
        "filename": uploaded_file.filename,
        "algorithm": algorithm.upper(),
        "hash_value": hash_value,
        "file_size": len(file_bytes),
        "security_label": SECURITY_LABELS[algorithm],
    }


def run_transfer(
    *,
    uploaded_file,
    algorithm: str,
    enable_signature: bool,
    encrypt_file: bool,
    recipient_email: str,
    persist_log: bool,
) -> dict:
    if uploaded_file is None or uploaded_file.filename == "":
        raise ValueError("Please choose a file to upload.")

    if algorithm not in HASH_FUNCTIONS:
        raise ValueError("Unsupported hash algorithm selected.")

    original_bytes = uploaded_file.read()
    sender_file = save_bytes(uploaded_file.filename, original_bytes, "sender")

    sender_digest, sender_hash = compute_digest(original_bytes, algorithm)
    signature = sign_digest(sender_digest, algorithm) if enable_signature else None

    receiver_bytes, encryption_summary = simulate_encryption(original_bytes, encrypt_file)
    receiver_file = save_bytes(uploaded_file.filename, receiver_bytes, "receiver")
    receiver_digest, receiver_hash = compute_digest(receiver_bytes, algorithm)

    safe = sender_hash == receiver_hash
    signature_valid = None
    signature_summary = "Digital signature was not enabled for this transfer."
    if enable_signature and signature is not None:
        signature_valid = verify_digest_signature(receiver_digest, signature, algorithm)
        signature_summary = (
            "Digital signature verified successfully."
            if signature_valid
            else "Digital signature verification failed because the receiver hash no longer matched."
        )

    timestamp = datetime.now(timezone.utc).isoformat()
    result_label = "File Safe" if safe else "File Tampered"
    recipient = recipient_email.strip() or "receiver@example.com"

    log_entry = {
        "filename": uploaded_file.filename,
        "algorithm": algorithm.upper(),
        "hash": sender_hash,
        "timestamp": timestamp,
        "result": result_label,
        "recipient": recipient,
        "signature_valid": signature_valid,
        "encryption_enabled": encrypt_file,
    }
    if persist_log:
        append_log(log_entry)

    return {
        "filename": uploaded_file.filename,
        "algorithm": algorithm.upper(),
        "security_label": SECURITY_LABELS[algorithm],
        "sender_hash": sender_hash,
        "receiver_hash": receiver_hash,
        "safe": safe,
        "status": result_label,
        "enable_signature": enable_signature,
        "signature_valid": signature_valid,
        "signature_summary": signature_summary,
        "encrypt_file": encrypt_file,
        "encryption_summary": encryption_summary,
        "sender_preview": build_preview(original_bytes),
        "receiver_preview": build_preview(receiver_bytes),
        "sender_file": sender_file,
        "receiver_file": receiver_file,
        "download_url": url_for("download_file", stored_name=receiver_file),
        "recipient_email": recipient,
        "delivery_message": f"Sending to {recipient}... File delivered successfully.",
        "share_message": "Share this hash with receiver to verify file integrity.",
        "sender_size": len(original_bytes),
        "receiver_size": len(receiver_bytes),
        "timestamp": timestamp,
        "log_entry": log_entry if persist_log else None,
    }


def create_lab_session(*, uploaded_file, algorithm: str, enable_signature: bool) -> dict:
    if uploaded_file is None or uploaded_file.filename == "":
        raise ValueError("Choose a file first, then run the 'load file' command.")

    if algorithm not in HASH_FUNCTIONS:
        raise ValueError("Unsupported hash algorithm selected.")

    original_bytes = uploaded_file.read()
    sender_digest, sender_hash = compute_digest(original_bytes, algorithm)
    signature = sign_digest(sender_digest, algorithm) if enable_signature else None

    return {
        "id": uuid4().hex,
        "filename": uploaded_file.filename,
        "algorithm": algorithm,
        "enable_signature": enable_signature,
        "original_bytes": original_bytes,
        "current_bytes": original_bytes,
        "sender_digest": sender_digest,
        "sender_hash": sender_hash,
        "signature": signature,
        "stage": "sender",
        "file_sent": False,
        "history": [],
        "learning_message": "File loaded into the simulated lab. Inspect it, tamper with it, then send it for verification.",
        "progress": {
            "loaded": True,
            "inspected": False,
            "modified": False,
            "sent": False,
            "verified": False,
        },
        "verification": None,
    }


def append_lab_history(session: dict, command: str, output: str, kind: str = "info") -> None:
    session["history"].append(
        {
            "command": command,
            "output": output,
            "kind": kind,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
    )
    session["history"] = session["history"][-24:]


def get_lab_session(session_id: str) -> dict:
    if not session_id:
        raise ValueError("Run 'load file' first to create a lab session.")

    session = LAB_SESSIONS.get(session_id)
    if session is None:
        raise ValueError("Lab session not found. Reload the file with 'load file' and try again.")
    return session


def set_lab_learning_message(session: dict, message: str) -> None:
    session["learning_message"] = message


def serialize_lab_session(session: dict, *, last_output: str = "") -> dict:
    current_digest, current_hash = compute_digest(session["current_bytes"], session["algorithm"])
    verification = session.get("verification") or {}

    return {
        "session_id": session["id"],
        "filename": session["filename"],
        "algorithm": session["algorithm"].upper(),
        "enable_signature": session["enable_signature"],
        "sender_hash": session["sender_hash"],
        "current_hash": current_hash,
        "receiver_hash": verification.get("receiver_hash", ""),
        "signature_valid": verification.get("signature_valid"),
        "safe": verification.get("safe"),
        "status": verification.get("status", "Awaiting verify"),
        "stage": session["stage"],
        "file_sent": session["file_sent"],
        "modified": session["current_bytes"] != session["original_bytes"],
        "learning_message": session["learning_message"],
        "history": session["history"],
        "last_output": last_output,
        "progress": session["progress"],
        "sender_size": len(session["original_bytes"]),
        "current_size": len(session["current_bytes"]),
        "current_digest_b64": base64.b64encode(current_digest).decode("ascii"),
    }


def execute_lab_command(
    *,
    command: str,
    session_id: str,
    uploaded_file,
    algorithm: str,
    enable_signature: bool,
) -> dict:
    cleaned_command = (command or "").strip()
    if not cleaned_command:
        raise ValueError("Enter a simulated terminal command.")

    try:
        tokens = shlex.split(cleaned_command)
    except ValueError as error:
        raise ValueError(f"Command parse error: {error}") from error

    if not tokens:
        raise ValueError("Enter a simulated terminal command.")

    normalized = [token.lower() for token in tokens]

    with LAB_LOCK:
        if normalized == ["load", "file"]:
            session = create_lab_session(
                uploaded_file=uploaded_file,
                algorithm=algorithm,
                enable_signature=enable_signature,
            )
            output = (
                f"Loaded '{session['filename']}' into the simulated attacker terminal. "
                f"Sender hash ({session['algorithm'].upper()}): {session['sender_hash']}"
            )
            append_lab_history(session, cleaned_command, output)
            LAB_SESSIONS[session["id"]] = session
            return serialize_lab_session(session, last_output=output)

        session = get_lab_session(session_id)

        if normalized == ["show", "content"]:
            session["progress"]["inspected"] = True
            session["stage"] = "attacker" if session["progress"]["modified"] else "sender"
            output = build_text_preview(session["current_bytes"])
            set_lab_learning_message(
                session,
                "The attacker terminal is displaying the current file contents exactly as they exist in the simulation state.",
            )
            append_lab_history(session, cleaned_command, output)
            return serialize_lab_session(session, last_output=output)

        if normalized == ["show", "hex"]:
            session["progress"]["inspected"] = True
            session["stage"] = "attacker" if session["progress"]["modified"] else "sender"
            output = build_hex_preview(session["current_bytes"])
            set_lab_learning_message(
                session,
                "Hex view reveals the raw byte pattern of the file. Binary-level changes here will produce a new hash fingerprint.",
            )
            append_lab_history(session, cleaned_command, output)
            return serialize_lab_session(session, last_output=output)

        if normalized[0] == "append":
            if len(tokens) < 2:
                raise ValueError('Usage: append "text to add"')
            session["current_bytes"] += " ".join(tokens[1:]).encode("utf-8")
            session["stage"] = "attacker"
            session["file_sent"] = False
            session["progress"]["modified"] = True
            session["progress"]["verified"] = False
            session["verification"] = None
            _, current_hash = compute_digest(session["current_bytes"], session["algorithm"])
            output = f"Appended text payload. Current hash ({session['algorithm'].upper()}): {current_hash}"
            set_lab_learning_message(
                session,
                "Appending even a short string changes the underlying bytes, so the hash shifts to a new fingerprint.",
            )
            append_lab_history(session, cleaned_command, output, kind="warning")
            return serialize_lab_session(session, last_output=output)

        if normalized[:2] == ["replace", "bytes"]:
            if len(tokens) < 3:
                raise ValueError('Usage: replace bytes "new text" or replace bytes 48 65 6c 6c 6f')
            payload_tokens = tokens[2:]
            if all(len(token) == 2 and all(char in "0123456789abcdefABCDEF" for char in token) for token in payload_tokens):
                session["current_bytes"] = bytes(int(token, 16) for token in payload_tokens)
            else:
                session["current_bytes"] = " ".join(payload_tokens).encode("utf-8")
            session["stage"] = "attacker"
            session["file_sent"] = False
            session["progress"]["modified"] = True
            session["progress"]["verified"] = False
            session["verification"] = None
            _, current_hash = compute_digest(session["current_bytes"], session["algorithm"])
            output = f"Replaced file bytes. Current hash ({session['algorithm'].upper()}): {current_hash}"
            set_lab_learning_message(
                session,
                "Replacing bytes rewrites the simulated payload. Hashing detects the new content immediately.",
            )
            append_lab_history(session, cleaned_command, output, kind="warning")
            return serialize_lab_session(session, last_output=output)

        if normalized[:2] == ["flip", "byte"]:
            index = 0
            if len(tokens) >= 3:
                try:
                    index = int(tokens[2])
                except ValueError as error:
                    raise ValueError("flip byte expects an integer index, for example: flip byte 0") from error
            if not session["current_bytes"]:
                raise ValueError("Cannot flip a byte in an empty file.")
            if index < 0 or index >= len(session["current_bytes"]):
                raise ValueError(f"Byte index out of range. Valid range: 0 to {len(session['current_bytes']) - 1}.")
            mutable = bytearray(session["current_bytes"])
            mutable[index] ^= 0xFF
            session["current_bytes"] = bytes(mutable)
            session["stage"] = "attacker"
            session["file_sent"] = False
            session["progress"]["modified"] = True
            session["progress"]["verified"] = False
            session["verification"] = None
            _, current_hash = compute_digest(session["current_bytes"], session["algorithm"])
            output = f"Flipped byte at offset {index}. Current hash ({session['algorithm'].upper()}): {current_hash}"
            set_lab_learning_message(
                session,
                "A one-byte flip is enough to alter the file fingerprint. This is the avalanche effect in action.",
            )
            append_lab_history(session, cleaned_command, output, kind="warning")
            return serialize_lab_session(session, last_output=output)

        if normalized == ["send"]:
            session["stage"] = "receiver"
            session["file_sent"] = True
            session["progress"]["sent"] = True
            output = "File sent to the receiver checkpoint. Run 'verify' to compare the receiver hash against the sender hash."
            set_lab_learning_message(
                session,
                "The modified file is now at the receiver. Verification will determine whether the fingerprint still matches.",
            )
            append_lab_history(session, cleaned_command, output)
            return serialize_lab_session(session, last_output=output)

        if normalized == ["verify"]:
            session["stage"] = "receiver"
            session["file_sent"] = True
            session["progress"]["sent"] = True
            session["progress"]["verified"] = True
            receiver_digest, receiver_hash = compute_digest(session["current_bytes"], session["algorithm"])
            safe = receiver_hash == session["sender_hash"]
            signature_valid = None
            if session["enable_signature"] and session["signature"] is not None:
                signature_valid = verify_digest_signature(receiver_digest, session["signature"], session["algorithm"])
            status = "File Safe" if safe else "File Tampered"
            output = (
                f"Verification complete. Receiver hash: {receiver_hash}. Result: {status}. "
                f"Signature check: {'valid' if signature_valid else 'failed' if signature_valid is False else 'disabled'}."
            )
            session["verification"] = {
                "receiver_hash": receiver_hash,
                "safe": safe,
                "status": status,
                "signature_valid": signature_valid,
            }
            set_lab_learning_message(
                session,
                "Verification compares the receiver-side hash with the sender's original hash. Matching hashes mean integrity held; mismatches reveal tampering.",
            )
            append_lab_history(session, cleaned_command, output, kind="success" if safe else "warning")
            return serialize_lab_session(session, last_output=output)

        raise ValueError(
            "Unknown command. Supported commands: load file, show content, show hex, append \"text\", "
            "replace bytes, flip byte, send, verify."
        )


@app.route("/")
def home_page():
    return redirect(url_for("hash_page"))


@app.route("/hash")
def hash_page():
    return render_template("hash.html", active_page="hash")


@app.route("/transfer")
def transfer_page():
    return render_template("transfer.html", active_page="transfer")


@app.route("/simulation")
def simulation_page():
    return render_template("simulation.html", active_page="simulation")


@app.route("/logs")
def logs_page():
    return render_template("logs.html", active_page="logs")


@app.get("/download/<stored_name>")
def download_file(stored_name: str):
    return send_from_directory(UPLOAD_DIR, stored_name, as_attachment=True)


@app.errorhandler(413)
def file_too_large(_error):
    return jsonify({"error": "File is too large. Please keep uploads under 16 MB."}), 413


@app.get("/api/collision-demo")
def collision_demo():
    return jsonify(load_collision_demo())


@app.get("/api/logs")
def logs_api():
    return jsonify({"logs": load_logs()[:50]})


@app.post("/api/hash-tool")
def hash_tool_api():
    uploaded_file = request.files.get("file")
    algorithm = (request.form.get("algorithm") or "sha256").lower()

    try:
        result = build_hash_tool_result(uploaded_file, algorithm)
    except ValueError as error:
        return jsonify({"error": str(error)}), 400

    return jsonify(result)


@app.post("/api/transfer-check")
def transfer_check():
    uploaded_file = request.files.get("file")
    algorithm = (request.form.get("algorithm") or "sha256").lower()
    enable_signature = (request.form.get("enable_signature") or "").lower() == "true"
    encrypt_file = (request.form.get("encrypt_file") or "").lower() == "true"
    recipient_email = request.form.get("recipient_email") or ""

    try:
        result = run_transfer(
            uploaded_file=uploaded_file,
            algorithm=algorithm,
            enable_signature=enable_signature,
            encrypt_file=encrypt_file,
            recipient_email=recipient_email,
            persist_log=True,
        )
    except ValueError as error:
        return jsonify({"error": str(error)}), 400

    return jsonify(result)


@app.post("/api/upload-check")
def upload_check_alias():
    return transfer_check()


@app.post("/api/simulation-terminal")
def simulation_terminal():
    command = request.form.get("command") or ""
    session_id = request.form.get("session_id") or ""
    algorithm = (request.form.get("algorithm") or "sha256").lower()
    enable_signature = (request.form.get("enable_signature") or "").lower() == "true"
    uploaded_file = request.files.get("file")

    try:
        result = execute_lab_command(
            command=command,
            session_id=session_id,
            uploaded_file=uploaded_file,
            algorithm=algorithm,
            enable_signature=enable_signature,
        )
    except ValueError as error:
        return jsonify({"error": str(error)}), 400

    return jsonify(result)


@app.post("/api/simulation-check")
def simulation_check_compat():
    uploaded_file = request.files.get("file")
    algorithm = (request.form.get("algorithm") or "sha256").lower()
    enable_signature = (request.form.get("enable_signature") or "").lower() == "true"
    command = 'load file'

    try:
        result = execute_lab_command(
            command=command,
            session_id="",
            uploaded_file=uploaded_file,
            algorithm=algorithm,
            enable_signature=enable_signature,
        )
    except ValueError as error:
        return jsonify({"error": str(error)}), 400

    return jsonify(result)


@app.post("/api/simulate")
def simulate_alias():
    return simulation_check_compat()


if __name__ == "__main__":
    debug_enabled = os.environ.get("FLASK_DEBUG", "").strip() == "1"
    app.run(host="0.0.0.0", port=5000, debug=debug_enabled)
