# Auth Workflow with NodeJS

This is a workflow that conrains all the controllers related to auth with NodeJS, you can use it directly in your project.

Developed with Express and MongoDB


## Setup

```bash
npm install && npm start
```

don't forget to add .env file contain the following variables:

- MONGO_URI
- PORT
- JWT_SECRET
- JWT_VERIFY_SECRET
- BASE_URL (for ex "http://localhost:5000")
- EMAIL (the email you use to send email with nodemailer)
- EMAIL_PASSWORD


## Functionality

- Register
- Login
- Verify email (send email verification)
- Reset password (send reset password email)
- Change Password

## Future Upgrades

- Maybe i'll add change user information in the future

## Routers

- auth.js
