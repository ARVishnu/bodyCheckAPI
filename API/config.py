import os

# Load from environment; do not hardcode secrets
SENDGRID_API_KEY = os.environ.get("SENDGRID_API_KEY")
SENDGRID_FROM_EMAIL = os.environ.get("SENDGRID_FROM_EMAIL")
OTP_TTL_MINUTES = int(os.environ.get("OTP_TTL_MINUTES", 15))


