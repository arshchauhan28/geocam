import html
import re

from flask import Flask, Response, request

from store import VerificationStore
from verifier import (
    row_to_result,
    validate_record,
    verify_signature,
)

app = Flask(__name__)

ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{2,119}$")


def esc(value):
    return html.escape(str(value)) if value is not None else ""


def verification_page(record_id, result, media_url=None, error=None):
    if error:
        status = "Verification Failed"
        status_class = "failed"
        message = error
    else:
        status = "Verified"
        status_class = "verified"
        message = "This GeoCam record passed integrity and signature verification."

    media_html = ""

    if media_url and result.get("mediaType") == "photo":
        media_html = f"""
        <div class="media">
            <img src="{esc(media_url)}" alt="GeoCam evidence">
        </div>
        """
    elif media_url and result.get("mediaType") == "video":
        media_html = f"""
        <div class="media">
            <video controls preload="metadata">
                <source src="{esc(media_url)}" type="video/mp4">
            </video>
        </div>
        """

    details = ""

    if result:
        details = f"""
        <div class="details">
            <div><span>Record ID</span><strong>{esc(record_id)}</strong></div>
            <div><span>Timestamp</span><strong>{esc(result.get("timestamp"))}</strong></div>
            <div><span>Latitude</span><strong>{esc(result.get("latitude"))}</strong></div>
            <div><span>Longitude</span><strong>{esc(result.get("longitude"))}</strong></div>
            <div><span>Accuracy</span><strong>{esc(result.get("accuracy"))}</strong></div>
            <div><span>Altitude</span><strong>{esc(result.get("altitude"))}</strong></div>
            <div><span>Media Type</span><strong>{esc(result.get("mediaType"))}</strong></div>
            <div><span>Protocol</span><strong>{esc(result.get("protocolVersion"))}</strong></div>
            <div><span>Key Fingerprint</span><strong>{esc(result.get("keyFingerprint"))}</strong></div>
        </div>
        """

    return f"""
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>GeoCam Verification</title>
<style>
* {{
    box-sizing: border-box;
}}

body {{
    margin: 0;
    min-height: 100vh;
    font-family: Arial, Helvetica, sans-serif;
    background: #0b1020;
    color: #f5f7ff;
    display: flex;
    justify-content: center;
    padding: 32px 16px;
}}

.container {{
    width: 100%;
    max-width: 760px;
}}

.card {{
    background: #151b2f;
    border: 1px solid #29314d;
    border-radius: 20px;
    padding: 28px;
    box-shadow: 0 20px 60px rgba(0,0,0,.35);
}}

h1 {{
    margin: 0 0 8px;
    font-size: 28px;
}}

.subtitle {{
    color: #aeb7d0;
    margin-bottom: 24px;
}}

.status {{
    border-radius: 14px;
    padding: 18px;
    margin-bottom: 24px;
}}

.status.verified {{
    background: rgba(34,197,94,.12);
    border: 1px solid rgba(34,197,94,.35);
}}

.status.failed {{
    background: rgba(239,68,68,.12);
    border: 1px solid rgba(239,68,68,.35);
}}

.status-title {{
    font-size: 20px;
    font-weight: 700;
    margin-bottom: 6px;
}}

.status-message {{
    color: #c8cee0;
    line-height: 1.5;
}}

.details {{
    display: grid;
    gap: 12px;
    margin-bottom: 24px;
}}

.details div {{
    display: flex;
    justify-content: space-between;
    gap: 20px;
    padding: 12px 14px;
    background: #0f1527;
    border-radius: 10px;
}}

.details span {{
    color: #8f9ab7;
}}

.details strong {{
    text-align: right;
    word-break: break-word;
}}

.media {{
    margin-top: 20px;
    overflow: hidden;
    border-radius: 14px;
    background: #080c17;
}}

.media img,
.media video {{
    width: 100%;
    max-height: 560px;
    display: block;
    object-fit: contain;
}}

.footer {{
    margin-top: 20px;
    color: #77829e;
    font-size: 13px;
    text-align: center;
}}

@media (max-width: 600px) {{
    .card {{
        padding: 20px;
    }}

    .details div {{
        flex-direction: column;
        gap: 5px;
    }}

    .details strong {{
        text-align: left;
    }}
}}
</style>
</head>

<body>
<div class="container">
    <div class="card">
        <h1>GeoCam Verification</h1>
        <div class="subtitle">
            Cryptographically verified location evidence
        </div>

        <div class="status {status_class}">
            <div class="status-title">{esc(status)}</div>
            <div class="status-message">{esc(message)}</div>
        </div>

        {details}
        {media_html}

        <div class="footer">
            GeoCam public verification service
        </div>
    </div>
</div>
</body>
</html>
"""


def get_record_id(path):
    path = path.strip("/")

    if not path:
        return None

    parts = path.split("/")

    if len(parts) != 1:
        return None

    record_id = parts[0]

    if not ID_RE.fullmatch(record_id):
        return None

    return record_id


@app.route("/", methods=["GET"])
def home():
    return Response(
        verification_page(
            "",
            {},
            error="No GeoCam record ID was provided."
        ),
        status=400,
        mimetype="text/html",
    )


@app.route("/<path:path>", methods=["GET"])
def verify(path):
    record_id = get_record_id(request.args.get("id") or path)

    if not record_id:
        return Response(
            verification_page(
                "",
                {},
                error=f"Invalid GeoCam record ID. path={path!r}"
            ),
            status=400,
            mimetype="text/html",
        )

    try:
        store = VerificationStore()

        row = store.get_record(record_id)

        if not row:
            return Response(
                verification_page(
                    record_id,
                    {},
                    error="GeoCam record not found."
                ),
                status=404,
                mimetype="text/html",
            )

        validate_record(row)

        media_hash = store.media_sha256(row)

        if not media_hash:
            raise ValueError("Evidence media is missing.")

        if media_hash != row["media_sha256"]:
            raise ValueError("Evidence media integrity check failed.")

        if not verify_signature(row):
            raise ValueError("Cryptographic signature verification failed.")

        result = row_to_result(row)

        media_url = store.media_url(row)

        return Response(
            verification_page(
                record_id,
                result,
                media_url=media_url,
            ),
            status=200,
            mimetype="text/html",
        )

    except ValueError as exc:
        return Response(
            verification_page(
                record_id,
                {},
                error=str(exc),
            ),
            status=400,
            mimetype="text/html",
        )

    except Exception:
        return Response(
            verification_page(
                record_id,
                {},
                error="Verification service temporarily unavailable.",
            ),
            status=500,
            mimetype="text/html",
        )