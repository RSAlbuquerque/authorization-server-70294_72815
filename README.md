# 🚀 Setup Guide

## 1. 📦 Install dependencies

```bash
npm i
```

---

## 2. ⚙️ Create .env file in both client and server directories.

### ➡️ Client .env Format

```properties
CLIENT_ID=client-id
CLIENT_PORT=3000

CLIENT_URL={baseClientURL}
CALLBACK_URL={baseClientURL}/auth/provider/callback

AUTHORIZATION_URL={baseServerURL}/authorize
TOKEN_URL={baseServerURL}/token

CLIENT_SECRET=client-secret
SESSION_SECRET=session-secret
JWT_SECRET=jwt-secret

ADMIN_ID=admin-server-id
ADMIN_SECRET=admin-server-secret
```

### ➡️ Server .env Format

```properties
SERVER_URL={baseServerURL}

SERVER_PORT=9000
SERVER_NAME=server-name-or-id

SESSION_SECRET=session-secret
JWT_SECRET=jwt-secret

ADMIN_ID=admin-server-id
ADMIN_SECRET=admin-server-secret
```

Configure the environment variables.
ADMIN_ID and ADMIN_SECRET are the credentials used on the Auth Server's basic authentication.
If you are using the deployed authorization server, a list of registered clients is shown below.

---

## 3. 🏃 Run the programms

```bash
npm run dev
```

---

## 4. 🌐 Login through the client on your browser.

Click on the 'Login with OAuth2' link. If the authorization server is running locally, you will need to create a client and user on the server. If you are using the deployed version, use one of the available logins/clients below:

👤 Available Logins (username | password):

- TBA | TBA
- TBA | TBA
- TBA | TBA

🛡️ Available Clients (client_id | client_secret | redirect_uri)

- TBA | TBA | TBA
- TBA | TBA | TBA
- TBA | TBA | TBA

After successfully loging in, you will see the profile page with information about the user logged in and the JWT token.

---

## 5. 🔐 JWT Token Claims

The JWT token given by the server will have the following claims present on the paylod:

- username: The username of the authenticated user.

- client: The client ID of the OAuth client making the request.

- authorized: The name of the server that authorized the token (from env. variable SERVER_NAME).

- serverurl: The URL of the server that issued the token (from env. variable SERVER_URL).

- jti: A unique identifier for the token.

- iat: The issued-at timestamp.

- exp: The expiration timestamp, set to 10 minutes after iat.

---
