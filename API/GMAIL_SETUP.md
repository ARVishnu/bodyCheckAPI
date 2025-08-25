# Gmail SMTP Setup for OTP Emails

## Step 1: Enable 2-Step Verification
1. Go to your Google Account settings: https://myaccount.google.com/
2. Click on "Security" in the left sidebar
3. Under "Signing in to Google", click on "2-Step Verification"
4. Follow the steps to enable 2-Step Verification if not already enabled

## Step 2: Generate an App Password
1. In the same Security section, click on "App passwords"
2. You might need to sign in again
3. Under "Select app", choose "Mail"
4. Under "Select device", choose "Other" and type "BodyCheck Backend"
5. Click "Generate"
6. Google will display a 16-character app password (e.g., "abcd efgh ijkl mnop")
7. **Copy this password** - you won't be able to see it again!

## Step 3: Configure the Backend
1. Open the `config.py` file in your project
2. Replace the placeholder values:
   ```python
   SMTP_USER = "your-actual-gmail@gmail.com"  # Your Gmail address
   SMTP_PASS = "your-16-character-app-password"  # The app password from Step 2
   ```
3. Save the file

## Step 4: Test the Setup
1. Restart your FastAPI server
2. Test the forgot password endpoint:
   ```bash
   curl -X POST http://localhost:8000/forgot-password \
     -H "Content-Type: application/json" \
     -d '{"email": "test@example.com"}'
   ```
3. Check your email for the OTP code

## Important Notes:
- **Never use your regular Gmail password** - only use the App Password
- **Keep the App Password secure** - don't commit it to version control
- **The App Password is 16 characters** with spaces (remove spaces when using)
- **If you change your Gmail password**, you'll need to generate a new App Password

## Troubleshooting:
- If you get "Authentication failed", double-check your App Password
- If you get "Username and Password not accepted", make sure 2-Step Verification is enabled
- If emails aren't sending, check your Gmail's "Less secure app access" settings (should be disabled when using App Passwords)
