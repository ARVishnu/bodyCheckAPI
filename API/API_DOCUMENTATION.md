# BodyCheck Backend API Documentation

## Base URL
```
http://localhost:8000
```

## Authentication Endpoints

### 1. Signup (Step 1: Initiate Registration)
**POST** `/signup`

Initiates the signup process by creating a pending account and sending an OTP verification email.

**Request Body:**
```json
{
  "full_name": "John Doe",
  "email": "john@example.com",
  "password": "securepassword123"
}
```

**Response:**
```json
{
  "message": "Signup initiated. Please check your email for OTP verification."
}
```

**Error Responses:**
- `400`: Email already registered
- `500`: Google Sheet not available or other server errors

---

### 2. Signup Verification (Step 2: Complete Registration)
**POST** `/signup-verify`

Completes the signup process by verifying the OTP sent to the user's email.

**Request Body:**
```json
{
  "email": "john@example.com",
  "otp": "123456"
}
```

**Response:**
```json
{
  "message": "Signup verified successfully! You can now login."
}
```

**Error Responses:**
- `400`: Invalid signup status, OTP expired, or no OTP found
- `401`: Invalid OTP
- `404`: Signup request not found
- `500`: Server errors

---

### 3. Login
**POST** `/login`

Authenticates a user with email and password.

**Request Body:**
```json
{
  "email": "john@example.com",
  "password": "securepassword123"
}
```

**Response:**
```json
{
  "message": "Login successful"
}
```

**Error Responses:**
- `401`: Invalid password or account not verified
- `404`: User not found
- `500`: Server errors

---

### 4. Forgot Password
**POST** `/forgot-password`

Sends an OTP to the user's email for password reset.

**Request Body:**
```json
{
  "email": "john@example.com"
}
```

**Response:**
```json
{
  "message": "If that email exists, an OTP has been sent"
}
```

**Note:** For security reasons, the same message is returned regardless of whether the email exists.

---

### 5. Reset Password
**POST** `/reset-password`

Resets the user's password using the OTP received via email.

**Request Body:**
```json
{
  "email": "john@example.com",
  "otp": "123456",
  "new_password": "newsecurepassword123"
}
```

**Response:**
```json
{
  "message": "Password reset successful"
}
```

**Error Responses:**
- `400`: No OTP requested, OTP expired, or invalid expiry format
- `401`: Invalid OTP
- `404`: User not found
- `500`: Server errors

---

### 6. Health Check
**GET** `/health`

Checks the health status of the backend and Google Sheets connection.

**Response:**
```json
{
  "status": "healthy",
  "headers": ["Full Name", "Email", "Password", "Signup Date", "OTP_Code", "OTP_Expiry"]
}
```

---

## Complete Signup Flow Example

### Step 1: Initiate Signup
```bash
curl -X POST http://localhost:8000/signup \
  -H "Content-Type: application/json" \
  -d '{
    "full_name": "John Doe",
    "email": "john@example.com",
    "password": "securepassword123"
  }'
```

### Step 2: Check Email for OTP
The user receives an email with a 6-digit OTP code.

### Step 3: Verify Signup
```bash
curl -X POST http://localhost:8000/signup-verify \
  -H "Content-Type: application/json" \
  -d '{
    "email": "john@example.com",
    "otp": "123456"
  }'
```

### Step 4: Login
```bash
curl -X POST http://localhost:8000/login \
  -H "Content-Type: application/json" \
  -d '{
    "email": "john@example.com",
    "password": "securepassword123"
  }'
```

---

## Password Reset Flow Example

### Step 1: Request Password Reset
```bash
curl -X POST http://localhost:8000/forgot-password \
  -H "Content-Type: application/json" \
  -d '{
    "email": "john@example.com"
  }'
```

### Step 2: Check Email for OTP
The user receives an email with a 6-digit OTP code.

### Step 3: Reset Password
```bash
curl -X POST http://localhost:8000/reset-password \
  -H "Content-Type: application/json" \
  -d '{
    "email": "john@example.com",
    "otp": "123456",
    "new_password": "newsecurepassword123"
  }'
```

---

## Security Features

1. **Password Hashing**: All passwords are hashed using bcrypt
2. **OTP Verification**: Email verification required for new accounts
3. **Secure OTP**: 6-digit codes with 15-minute expiration
4. **Backward Compatibility**: Existing accounts without OTP verification still work
5. **Email Security**: Generic responses don't reveal if emails exist

## Error Handling

All endpoints return appropriate HTTP status codes:
- `200`: Success
- `400`: Bad Request (validation errors)
- `401`: Unauthorized (invalid credentials/OTP)
- `404`: Not Found (user/email not found)
- `500`: Internal Server Error

## Notes

- OTP codes expire after 15 minutes
- Email verification is required for new signups
- Existing accounts are automatically treated as verified
- All sensitive data is properly hashed and secured
