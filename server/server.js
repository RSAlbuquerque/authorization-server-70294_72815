require("dotenv").config();
const bcrypt = require("bcrypt");
const express = require("express");
const session = require("express-session");
const db = require("./db");
const escapeHtml = require("escape-html");
const { v4: uuidv4 } = require("uuid");

const app = express();

app.use(
  session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: true,
  })
);

app.use(express.urlencoded({ extended: true }));
app.use(express.json());

// Pages
// Homepage
app.get("/", (req, res) => {
  res.send(`
      <h2>Register New User</h2>
      <form method="POST" action="/register-user">
        <label>Username: <input name="username" /></label><br/>
        <label>Password: <input type="password" name="password" /></label><br/>
        <button type="submit">Register User</button>
      </form>
  
      <h2>Register New OAuth Client</h2>
      <form method="POST" action="/register-client">
        <label>Client ID: <input name="client_id" /></label><br/>
        <label>Client Secret: <input name="client_secret" /></label><br/>
        <label>Redirect URI: <input name="redirect_uri" /></label><br/>
        <button type="submit">Register Client</button>
      </form>
    `);
});

// Login Form
app.get("/login", (req, res) => {
  const { client_id, redirect_uri, response_type } = req.query;
  res.send(`
    <h2>Login</h2>
    <form method="POST" action="/login">
    <input type="hidden" name="client_id" value="${escapeHtml(
      client_id || ""
    )}" />
      <input type="hidden" name="redirect_uri" value="${escapeHtml(
        redirect_uri || ""
      )}" />
      <input type="hidden" name="response_type" value="${escapeHtml(
        response_type || ""
      )}" />
      <label>Username: <input name="username" /></label><br/>
      <label>Password: <input type="password" name="password" /></label><br/>
      <button type="submit">Login</button>
    </form>
  `);
});

// Handlers
// Add User
app.post("/register-user", async (req, res) => {
  const { username, password } = req.body;
  try {
    const hashedPassword = await bcrypt.hash(password, 10);

    const stmt = db.prepare(
      "INSERT INTO users (username, password) VALUES (?, ?)"
    );
    stmt.run(username, hashedPassword);

    res.send(
      `<h2>User registered successfully!</h2>
      <p><strong>Username:</strong> ${escapeHtml(username)}</p>
        <p><a href="/">Back to Home</a></p>
      `
    );
  } catch (e) {
    console.error(e);
    res.send(
      "<h2>Error: Username already exists.</h2><a href='/'>Back to Home</a>"
    );
  }
});

// Add Client
app.post("/register-client", (req, res) => {
  const { client_id, client_secret, redirect_uri } = req.body;

  try {
    const stmt = db.prepare(
      "INSERT INTO clients (client_id, client_secret, redirect_uri) VALUES (?, ?, ?)"
    );
    stmt.run(client_id, client_secret, redirect_uri);
    res.send(`
        <h2>Client Registered!</h2>
        <p><strong>Client ID:</strong> ${escapeHtml(client_id)}</p>
        <p><a href="/">Back to Home</a></p>
      `);
  } catch (e) {
    console.error(e);
    res.send(
      "<h2>Error: Client creation failed.</h2><a href='/'>Try again</a>"
    );
  }
});

// Authorization
app.get("/authorize", (req, res) => {
  const { client_id, redirect_uri, response_type } = req.query;

  const client = db
    .prepare("SELECT * FROM clients WHERE client_id = ?")
    .get(client_id);

  if (!client) {
    return res.status(400).send("Unknown client");
  }

  if (client.redirect_uri !== redirect_uri) {
    return res.status(400).send("Invalid redirect_uri");
  }

  if (!client_id || !redirect_uri || response_type !== "code") {
    return res.status(400).send("Invalid request");
  }

  if (!req.session.username) {
    res.send(`
      <h2>Login</h2>
      <form method="POST" action="/login">
      <input type="hidden" name="client_id" value="${escapeHtml(
        client_id || ""
      )}" />
        <input type="hidden" name="redirect_uri" value="${escapeHtml(
          redirect_uri || ""
        )}" />
        <input type="hidden" name="response_type" value="${escapeHtml(
          response_type || ""
        )}" />
        <label>Username: <input name="username" /></label><br/>
        <label>Password: <input type="password" name="password" /></label><br/>
        <button type="submit">Login</button>
      </form>
    `);
  }
});

// Token
app.post("/token", (req, res) => {
  const { grant_type, code, client_id, client_secret, redirect_uri } = req.body;

  if (grant_type !== "authorization_code") {
    return res.status(400).send("Unsupported grant_type");
  }

  const client = db
    .prepare("SELECT * FROM clients WHERE client_id = ?")
    .get(client_id);

  if (
    !client ||
    client.client_secret !== client_secret ||
    client.redirect_uri !== redirect_uri
  ) {
    return res.status(400).send("Invalid request");
  }

  const authCode = db
    .prepare("SELECT * FROM codes WHERE code = ? AND client_id = ?")
    .get(code, client_id);

  if (!authCode) {
    return res.status(400).send("Invalid authorization code");
  }

  const token = require("jsonwebtoken").sign(
    {
      username: authCode.username,
      client: client_id,
      authorized: process.env.SERVER_NAME,
      jti: uuidv4(),
      iat: Math.floor(Date.now() / 1000),
      exp: Math.floor(Date.now() / 1000) + 600,
    },
    process.env.JWT_SECRET
  );

  db.prepare("DELETE FROM codes WHERE code = ?").run(code);

  res.json({
    access_token: token,
    token_type: "Bearer",
    expires_in: 600,
  });
});

// Login
app.post("/login", async (req, res) => {
  const { username, password, client_id, redirect_uri, response_type } =
    req.body;
  const user = db
    .prepare("SELECT * FROM users WHERE username = ?")
    .get(username);

  if (!user) {
    return res.send("Invalid username or password");
  }

  const match = await bcrypt.compare(password, user.password);
  if (!match) {
    return res.send("Invalid username or password");
  }

  req.session.username = username;
  const code = uuidv4();

  db.prepare(
    "INSERT INTO codes (code, client_id, username) VALUES (?, ?, ?)"
  ).run(code, client_id, username);

  const redirectUrl = new URL(redirect_uri);
  redirectUrl.searchParams.append("code", escapeHtml(code));

  res.redirect(redirectUrl.toString());
});

// Start autorization server
app.listen(process.env.SERVER_PORT, () => {
  console.log(`Authorization server running at ${process.env.SERVER_URL}`);
});
