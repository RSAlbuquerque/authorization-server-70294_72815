require("dotenv").config();
const express = require("express");
const session = require("express-session");
const passport = require("passport");
const OAuth2Strategy = require("passport-oauth2");
const jwt = require("jsonwebtoken");
const escapeHtml = require("escape-html");

const app = express();

// Session middleware
app.use(
  session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: true,
  })
);

// Initialize Passport
app.use(passport.initialize());
app.use(passport.session());

// OAuth2 Strategy setup
const strategy = new OAuth2Strategy(
  {
    authorizationURL: process.env.AUTHORIZATION_URL,
    tokenURL: process.env.TOKEN_URL,
    clientID: process.env.CLIENT_ID,
    clientSecret: process.env.CLIENT_SECRET,
    callbackURL: process.env.CALLBACK_URL,
    state: false, // TODO: Figure out this
    customHeaders: {
      Authorization:
        "Basic " +
        Buffer.from(
          `${process.env.ADMIN_ID}:${process.env.ADMIN_SECRET}`
        ).toString("base64"),
    },
  },
  (accessToken, refreshToken, profile, cb) => {
    const user = accessToken;
    return cb(null, user);
  }
);
passport.use(strategy);

// Serialize / Deserialize user
passport.serializeUser((user, done) => done(null, user));
passport.deserializeUser((user, done) => done(null, user));

// Routes
// Home page
app.get("/", (req, res) => {
  res.send('<a href="/auth/provider">Login with OAuth2</a>');
});

// Start OAuth2 login
app.get("/auth/provider", passport.authenticate("oauth2"));

// OAuth2 callback
app.get(
  "/auth/provider/callback",
  passport.authenticate("oauth2", { failureRedirect: "/login-failed" }),
  (req, res) => {
    res.redirect("/profile");
  }
);

// Profile page
app.get("/profile", (req, res) => {
  if (!req.isAuthenticated()) {
    return res.redirect("/");
  }

  const accessToken = req.user;
  let username;
  let client;
  let authorized;
  let serverUrl;
  let jti;
  let iat;
  let exp;

  try {
    const decoded = jwt.verify(accessToken, process.env.JWT_SECRET);
    username = decoded.username;
    client = decoded.client;
    authorized = decoded.authorized;
    serverUrl = decoded.serverurl;
    jti = decoded.jti;
    iat = decoded.iat;
    exp = decoded.exp;
  } catch (err) {
    console.error("Failed to decode JWT:", err);
  }

  const formatToken = (token, chunkSize = 50) => {
    return token.match(new RegExp(`.{1,${chunkSize}}`, "g")).join("<br/>");
  };

  const formattedToken = formatToken(accessToken);

  res.send(`
    <h1>Profile</h1>
    <p><h2>Username:</h2> ${escapeHtml(username)}</p>
    <h2>JWT Token:</h2>
    <pre>${formattedToken}</pre>
    <h2>Decoded JWT:</h2>
    <p><strong>Username:</strong> ${escapeHtml(username)}</p>
    <p><strong>Client:</strong> ${escapeHtml(client)}</p>
    <p><strong>Authorized by:</strong> ${escapeHtml(authorized)}</p>
    <p><strong>Auth Server URL:</strong> ${escapeHtml(serverUrl)}</p>
    <p><strong>JTI:</strong> ${escapeHtml(jti)}</p>
    <p><strong>Issued At:</strong> ${escapeHtml(
      new Date(iat * 1000).toLocaleString()
    )}</p>
    <p><strong>Expiration:</strong> ${escapeHtml(
      new Date(exp * 1000).toLocaleString()
    )}</p>
    <form method="POST" action="/logout">
      <button type="submit">Logout</button>
    </form>
    `);
});

// Logout
app.post("/logout", (req, res, next) => {
  // Destroy the session on the server
  req.logout(function (err) {
    if (err) {
      return next(err);
    }
    req.session.destroy((err) => {
      if (err) {
        console.error("Failed to destroy session during logout", err);
        return res.status(500).send("Failed to logout.");
      }

      // Clear the cookie on the client side
      res.clearCookie("connect.sid", { path: "/" });

      // Redirect to home or login page
      res.redirect("/");
    });
  });
});

// Login failed
app.get("/login-failed", (req, res) => {
  res.send("<h1>Login Failed</h1>");
});

// Start client
app.listen(process.env.CLIENT_PORT, () => {
  console.log(`Client running at ${process.env.CLIENT_URL}`);
});
