// Intentionally vulnerable source-only fixture. This file is data for static intake tests.
// It is never imported or executed by the WP8 harness.
const express = require("express");
const app = express();

app.get("/vulnerable", (req, res) => {
  const result = eval(req.query.input);
  res.send(String(result));
});

app.get("/items/:itemId", (_req, res) => res.send("dynamic route"));
