import os

DATABASE_URL = os.environ.get("DATABASE_URL")
S3_BUCKET = os.environ.get("S3_BUCKET")
S3_ENDPOINT_URL = os.environ.get("S3_ENDPOINT_URL")
S3_ACCESS_KEY_ID = os.environ.get("S3_ACCESS_KEY_ID")
S3_SECRET_ACCESS_KEY = os.environ.get("S3_SECRET_ACCESS_KEY")
S3_REGION = os.environ.get("S3_REGION", "auto")
