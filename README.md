# SylesStacks Google Auth Server

A small Node.js backend for Google Identity Services (GIS). It verifies the Google ID token on the server and creates an HttpOnly session cookie.

## What it provides

- `GET /health` — Render health check.
- `POST /api/auth/google` — accepts `{ "credential": "..." }` from Google Identity Services, verifies it with Google, then creates a session.
- `GET /api/me` — returns the signed-in user's basic profile.
- `POST /api/logout` — clears the session cookie.

This starter does **not** store user accounts in a database. The session is stateless and expires after `SESSION_DAYS`. Add PostgreSQL later if you need persistent user records, account settings, or cross-device data.

## 1. Push to GitHub

Upload the contents of this folder to a new GitHub repository. Do not upload a real `.env` file or secrets.

## 2. Create the Render Web Service

In Render, choose **New + → Web Service**, connect the repository, and use:

- Runtime: Node
- Build command: `npm install`
- Start command: `npm start`
- Health check path: `/health`

You can also use the included `render.yaml` Blueprint.

After deployment, copy the service URL, for example `https://sylesstacks-auth.onrender.com`.

## 3. Add Render environment variables

In Render → your service → Environment, add:

| Variable | Value |
|---|---|
| `NODE_ENV` | `production` |
| `GOOGLE_CLIENT_ID` | Your Google **Web application** Client ID |
| `SESSION_SECRET` | A random secret of at least 32 characters |
| `FRONTEND_ORIGIN` | Exact origin of the hosted SylesStacks page, e.g. `https://username.github.io` |
| `COOKIE_SAME_SITE` | `none` |
| `SESSION_DAYS` | `7` |

Do not share `SESSION_SECRET` or any OAuth client secret in chat or commit them to GitHub. This backend does not need the Google OAuth Client Secret.

`FRONTEND_ORIGIN` is an origin only: scheme + hostname + optional port, without a path or trailing slash. If you host the HTML on a different domain later, update this variable.

## 4. Configure Google Identity Services

In Google Cloud Console:

1. Create/select a project.
2. Configure the OAuth consent screen.
3. Create an OAuth Client ID with application type **Web application**.
4. Add the exact website origin to **Authorized JavaScript origins**. For GitHub Pages, use the origin only, e.g. `https://username.github.io` (not the repository path).
5. Use the resulting Client ID as `GOOGLE_CLIENT_ID` in Render.

For testing while the OAuth consent screen is in Testing mode, add the Google accounts that will test the sign-in as test users.

## 5. Test deployment

Open:

`https://YOUR-RENDER-SERVICE.onrender.com/health`

Expected response:

```json
{"ok":true,"service":"sylesstacks-auth","version":"1.0.0"}
```

Then test `GET /api/me` from the hosted frontend. It should return `{"authenticated":false}` before sign-in.

## Frontend integration contract

Your HTML must initialize Google Identity Services with the same `GOOGLE_CLIENT_ID`. When GIS returns a credential, send it to the backend:

```js
const response = await fetch("https://YOUR-RENDER-SERVICE.onrender.com/api/auth/google", {
  method: "POST",
  credentials: "include",
  headers: { "Content-Type": "application/json" },
  body: JSON.stringify({ credential: responseFromGoogle.credential })
});
const result = await response.json();
```

Check the actual GIS callback object: the ID token is `response.credential`.

To restore the session:

```js
const response = await fetch("https://YOUR-RENDER-SERVICE.onrender.com/api/me", {
  credentials: "include"
});
const result = await response.json();
```

To log out:

```js
await fetch("https://YOUR-RENDER-SERVICE.onrender.com/api/logout", {
  method: "POST",
  credentials: "include"
});
```

Replace the example service URL with your deployed Render URL. Keep `credentials: "include"` on all requests that need the session cookie.

## Important notes

- Google sign-in here signs the user into **SylesStacks**. It does not sign them into Google Play or grant Android app / Play Games access.
- The browser frontend must be served over HTTPS for secure cross-site cookies.
- This server verifies Google ID tokens; it does not accept a client-supplied email/name as proof of identity.
- Do not put secrets in frontend JavaScript.
