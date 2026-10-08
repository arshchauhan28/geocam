import boto3
import psycopg
from botocore.config import Config
from psycopg.rows import dict_row

from config import (
    DATABASE_URL,
    S3_BUCKET,
    S3_ENDPOINT_URL,
    S3_ACCESS_KEY_ID,
    S3_SECRET_ACCESS_KEY,
    S3_REGION,
)

COLUMNS = [
    "id", "protocol_version", "timestamp",
    "latitude", "longitude", "accuracy", "altitude",
    "address", "media_type", "signature",
    "media_sha256", "public_key", "created_at",
]


def _ext(media_type):
    return "jpg" if media_type == "photo" else "mp4"


def _mime(media_type):
    return "image/jpeg" if media_type == "photo" else "video/mp4"


class VerificationStore:
    def __init__(self):
        missing = [
            name for name, value in {
                "DATABASE_URL": DATABASE_URL,
                "S3_BUCKET": S3_BUCKET,
                "S3_ACCESS_KEY_ID": S3_ACCESS_KEY_ID,
                "S3_SECRET_ACCESS_KEY": S3_SECRET_ACCESS_KEY,
            }.items()
            if not value
        ]

        if missing:
            raise RuntimeError(
                "Missing verification storage configuration: "
                + ", ".join(missing)
            )

        self.database_url = DATABASE_URL
        self.bucket = S3_BUCKET

        self.s3 = boto3.client(
            "s3",
            endpoint_url=S3_ENDPOINT_URL or None,
            aws_access_key_id=S3_ACCESS_KEY_ID,
            aws_secret_access_key=S3_SECRET_ACCESS_KEY,
            region_name=S3_REGION,
            config=Config(
                signature_version="s3v4",
                s3={"addressing_style": "path"},
                retries={"max_attempts": 3},
                request_checksum_calculation="when_required",
                response_checksum_validation="when_required",
            ),
        )

    def _connect(self):
        return psycopg.connect(
            self.database_url,
            row_factory=dict_row,
            connect_timeout=10,
        )

    @staticmethod
    def _key(record_id, media_type):
        return f"media/{record_id}.{_ext(media_type)}"

    def get_record(self, record_id):
        with self._connect() as conn:
            return conn.execute(
                f"SELECT {', '.join(COLUMNS)} "
                "FROM records WHERE id=%s",
                (record_id,),
            ).fetchone()

    def media_exists(self, row):
        from botocore.exceptions import ClientError

        try:
            self.s3.head_object(
                Bucket=self.bucket,
                Key=self._key(row["id"], row["media_type"]),
            )
            return True
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code in ("404", "NoSuchKey", "NotFound"):
                return False
            raise

    def media_sha256(self, row):
        from botocore.exceptions import ClientError
        import hashlib

        try:
            obj = self.s3.get_object(
                Bucket=self.bucket,
                Key=self._key(row["id"], row["media_type"]),
            )
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code in ("404", "NoSuchKey", "NotFound"):
                return None
            raise

        digest = hashlib.sha256()

        for chunk in obj["Body"].iter_chunks(1 << 20):
            digest.update(chunk)

        return digest.hexdigest()

    def media_url(self, row):
        return self.s3.generate_presigned_url(
            "get_object",
            Params={
                "Bucket": self.bucket,
                "Key": self._key(row["id"], row["media_type"]),
                "ResponseContentType": _mime(row["media_type"]),
            },
            ExpiresIn=900,
        )
