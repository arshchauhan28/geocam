import base64
import hashlib
import re
from datetime import datetime, timezone

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey


ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{2,119}$")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


def rv(record, camel, snake=None):
    try:
        return record[camel]
    except (KeyError, IndexError):
        return record[snake] if snake else None


def fmt(value, places):
    if value is None:
        return "null"
    return f"{float(value):.{places}f}"


def canonical(record):
    address_b64 = base64.b64encode(
        record["address"].encode("utf-8")
    ).decode("ascii")

    return "|".join([
        "v=2",
        f"id={record['id']}",
        f"type={rv(record, 'mediaType', 'media_type')}",
        f"ts={record['timestamp']}",
        f"lat={fmt(record['latitude'], 6)}",
        f"lng={fmt(record['longitude'], 6)}",
        f"acc={fmt(record['accuracy'], 1)}",
        f"alt={fmt(record['altitude'], 1)}",
        f"addr64={address_b64}",
        f"media_sha256={rv(record, 'mediaSha256', 'media_sha256')}",
    ]).encode("utf-8")


def validate_record(r):
    required = [
        "id",
        "timestamp",
        "mediaType",
        "signature",
        "mediaSha256",
        "publicKey",
    ]

    missing = [key for key in required if key not in r]

    if missing:
        raise ValueError("Missing fields: " + ", ".join(missing))

    if r.get("protocolVersion") != 2:
        raise ValueError("Unsupported protocol version")

    if not isinstance(r["id"], str) or not ID_RE.fullmatch(r["id"]):
        raise ValueError("Invalid record id")

    if r["mediaType"] not in ("photo", "video"):
        raise ValueError("Invalid media type")

    if not SHA256_RE.fullmatch(r["mediaSha256"]):
        raise ValueError("Invalid media SHA-256")

    try:
        sig = base64.b64decode(r["signature"], validate=True)
        pub = base64.b64decode(r["publicKey"], validate=True)

        if len(sig) != 64 or len(pub) != 32:
            raise ValueError("Invalid Ed25519 key/signature length")

    except Exception as exc:
        raise ValueError(
            "Invalid base64 cryptographic material"
        ) from exc

    dt = datetime.fromisoformat(
        r["timestamp"].replace("Z", "+00:00")
    )

    if dt.tzinfo is None or dt.utcoffset() != timezone.utc.utcoffset(dt):
        raise ValueError("Timestamp must be UTC ISO-8601")

    return r["timestamp"]


def verify_signature(record):
    try:
        public_key = rv(record, "publicKey", "public_key")
        signature = rv(record, "signature", "signature")

        if not public_key or not signature:
            return False

        public_key_raw = base64.b64decode(
            public_key,
            validate=True,
        )

        signature_raw = base64.b64decode(
            signature,
            validate=True,
        )

        public_key_obj = Ed25519PublicKey.from_public_bytes(
            public_key_raw
        )

        public_key_obj.verify(
            signature_raw,
            canonical(record),
        )

        return True

    except (
        InvalidSignature,
        ValueError,
        TypeError,
        KeyError,
        IndexError,
    ):
        return False


def key_fingerprint(public_key):
    return hashlib.sha256(
        base64.b64decode(public_key)
    ).hexdigest()[:16]


def row_to_result(row):
    result = dict(row)

    result["keyFingerprint"] = key_fingerprint(
        result["public_key"]
    )

    result["protocolVersion"] = result.pop(
        "protocol_version"
    )

    result["mediaType"] = result.pop(
        "media_type"
    )

    result["mediaSha256"] = result.pop(
        "media_sha256"
    )

    result["publicKey"] = result.pop(
        "public_key"
    )

    return result
