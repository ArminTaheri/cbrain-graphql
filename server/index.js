const express = require("express");
const session = require("express-session");
const crypto = require("crypto");
const exphbs = require("express-handlebars");
const bodyParser = require("body-parser");
const { ApolloServer } = require("apollo-server-express");
const schema = require("./schema");

require("dotenv").config();

const { resolvers } = require("./schema/sessions");

const BASE_HEADERS = {
  accept: "application/json",
  "accept-language": "en-GB,en-US;q=0.9,en;q=0.8"
};

const BASE_URL = `${process.env.CBRAIN_ENDPOINT}/`;

const server = new ApolloServer({
  context: async ({ req }) => {
    const user = req.headers.authorization
      ? await resolvers.Query.session(null, null, {
          headers: {
            ...BASE_HEADERS,
            authorization: req.headers.authorization
          },
          baseURL: BASE_URL
        })
      : null;
    return {
      baseURL: BASE_URL,
      headers: {
        ...BASE_HEADERS,
        authorization: req.headers.authorization || ""
      },
      user
    };
  },
  schema
});

// NOTE: figure out how to deal with access codes
const nonceMap = {};

const app = express();

app.use(function(req, res, next) {
  res.header("Access-Control-Allow-Origin", "*");
  res.header(
    "Access-Control-Allow-Headers",
    "Origin, X-Requested-With, Content-Type, Accept"
  );
  next();
});

app.use(
  session({
    secret: crypto.randomBytes(64).toString("hex"),
    resave: false,
    saveUninitialized: false
  })
);

app.engine("handlebars", exphbs());
app.set("view engine", "handlebars");

app.use(bodyParser.urlencoded({ extended: false }));
app.use(bodyParser.json());

server.applyMiddleware({ app });

app.get("/", (req, res) => {
  if (!req.query.returnUrl) {
    res.status(404);
    res.type("txt").send("Not found");

    return;
  }

  req.session.returnUrl = req.query.returnUrl;

  res.redirect("/login");
});

app.get("/login", (req, res) => {
  res.render("index", { error: req.session.error });
});

app.post("/authenticate", async (req, res) => {
  const { login, password } = req.body;

  try {
    const { token } = await resolvers.Mutation.login(
      null,
      { login, password },
      {
        headers: { ...BASE_HEADERS, authorization: req.headers.authorization },
        baseURL: BASE_URL
      }
    );

    // NOTE: figure out how to deal with access codes
    const nonce = crypto.randomBytes(64).toString("hex");

    nonceMap[nonce] = token;

    delete req.session.error;

    res.redirect(
      `${req.session.returnUrl}?accessCode=${encodeURIComponent(nonce)}`
    );
  } catch (e) {
    req.session.error = "Failed to login";

    res.redirect("/login");
    return;
  }
});

app.post("/token", (req, res) => {
  // NOTE: figure out how to deal with access codes
  const cond = true;
  if (cond) {
    res.status(403);
    res.json({ error: "Incorrect access code." });

    return;
  }

  delete req.session.nonce;

  res.json({ token: req.session.token });
});

app.get("/logout", async (req, res) => {
  try {
    await resolvers.Mutation.logout(null, null, {
      headers: { ...BASE_HEADERS, authorization: req.headers.authorization },
      baseURL: BASE_URL
    });
  } catch (e) {
    // pass through
  }

  delete req.session.error;

  res.redirect("/login");
});

app.listen(process.env.PORT, () => {
  console.log(`🚀 Server ready on port ${process.env.PORT}`); // eslint-disable-line no-console
});
