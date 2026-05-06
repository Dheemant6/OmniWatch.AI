import boto3
import logging
import json
from app.core.config import settings

logger = logging.getLogger(__name__)

class S3Manager:
    def __init__(self):
        self.bucket = settings.AWS_BUCKET_NAME
        # Use credentials if available, otherwise boto3 falls back to IAM/env defaults
        kwargs = {}
        if settings.AWS_ACCESS_KEY_ID:
            kwargs["aws_access_key_id"] = settings.AWS_ACCESS_KEY_ID
        if settings.AWS_SECRET_ACCESS_KEY:
            kwargs["aws_secret_access_key"] = settings.AWS_SECRET_ACCESS_KEY
        if settings.AWS_ENDPOINT_URL:
            kwargs["endpoint_url"] = settings.AWS_ENDPOINT_URL

        try:
            self.client = boto3.client('s3', **kwargs)
        except Exception as e:
            logger.error(f"Failed to initialize S3 client: {e}")
            self.client = None

    def upload_artifact(self, file_name: str, data: dict):
        """
        Uploads a JSON dictionary artifact to the specified S3/MinIO bucket.
        """
        if not self.client:
            logger.warning(f"S3 client not initialized. Skipping upload for {file_name}")
            return False

        try:
            json_data = json.dumps(data, indent=2)
            self.client.put_object(
                Bucket=self.bucket,
                Key=file_name,
                Body=json_data,
                ContentType="application/json"
            )
            logger.info(f"Successfully uploaded {file_name} to bucket {self.bucket}")
            return True
        except Exception as e:
            logger.error(f"Error uploading artifact to S3: {e}")
            return False
