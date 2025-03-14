const path = require("node:path");
const { Pool } = require("pg");
const express = require("express");
const bcrypt = require("bcryptjs")
const session = require("express-session");
const passport = require("passport");
const LocalStrategy = require('passport-local').Strategy;
require("dotenv").config();

const pool = new Pool({
    connectionString: process.env.DATABASE_URL
});

const app = express();
app.use(express.urlencoded({ extended: true }));
app.set("views", path.join(__dirname, "views"));
app.set("view engine", "ejs");

app.use(session({ secret: "cats", resave: false, saveUninitialized: false }));
app.use(passport.session());
app.use(express.urlencoded({ extended: false }));

passport.use(
    new LocalStrategy(async (username, password, done) => {
      try {
        const { rows } = await pool.query("SELECT * FROM users WHERE username = $1", [username]);
        const user = rows[0];
  
        if (!user) {
          return done(null, false, { message: "Incorrect username" });
        }
        const match = await bcrypt.compare(password, user.password);
        if (!match) {
          return done(null, false, { message: "Incorrect password" })
  }
        return done(null, user);
      } catch(err) {
        return done(err);
      }
    })
);

passport.serializeUser((user, done) => {
    done(null, user.id);
});

passport.deserializeUser(async (id, done) => {
    try {
      const { rows } = await pool.query("SELECT * FROM users WHERE id = $1", [id]);
      const user = rows[0];
  
      done(null, user);
    } catch(err) {
      done(err);
    }
});

app.get("/", (req, res) => {
    res.render("index", { user: req.user });
});

app.get("/sign-up", (req, res) => res.render("sign_up"));

const { body, validationResult } = require("express-validator");

const validateUser = [
  body("email")
    .isEmail().withMessage(`You must enter a valid email.`),
  body("password").custom((value, { req }) => {
    if (value !== req.body.confirm_password) {
      throw new Error('Passwords do not match!');
    }
    return true;
  })
];

app.post("/sign-up", validateUser, async (req, res, next) => {
  const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).render("sign_up", {
        errors: errors.array()
      });
    }
    try {
      const hashedPassword = await bcrypt.hash(req.body.password, 10);
      await pool.query(`insert into users (firstname, lastname, username, password, membership) 
        values ($1, $2, $3, $4, $5)`, 
        [req.body.firstname, req.body.lastname, req.body.email, hashedPassword, "basic"]);
      res.redirect("/");
     } catch (error) {
        console.error(error);
        next(error);
       }
});

app.get("/login", (req, res) => res.render("login"));

app.post(
  "/login",
  passport.authenticate("local", {
    successRedirect: "/",
    failureRedirect: "/"
  })
);

app.get("/log-out", (req, res, next) => {
  req.logout((err) => {
    if (err) {
      return next(err);
    }
    res.redirect("/");
  });
});

app.post("/upgrade", async (req, res, next) => {
  if (req.body.code == "secret") {
    try {
      await pool.query("UPDATE users SET membership = $1 WHERE id = $2", ["premium", req.user.id]);
      res.redirect("/");
    } catch (error) {
    console.error(error);
    next(error);
   }
  }
})

app.get("/messages", async (req, res, next) => {
  try {
    posts = await pool.query(`SELECT post.id, firstname, lastname, created_at, title, content 
      FROM post
      JOIN users ON users.id = post.user_id
      ORDER BY created_at DESC;`)
    res.render("messages", { posts: posts['rows'], user: req.user });
  } catch (error) {
    console.error(error);
    next(error);
  }
});

app.post("/messages", async (req, res, next) => {
  try {
    await pool.query(`INSERT INTO post (user_id, title, content) 
      VALUES ($1, $2, $3)`,
    [req.user.id, req.body.title, req.body.content]);
    res.redirect("/messages");
  } catch (error) {
  console.error(error);
  next(error);
  }
})

app.post('/delete-post/:id', async (req, res, next) => {
  try {
    await pool.query("DELETE FROM post WHERE id = $1", [req.params.id]);
    res.redirect("/messages");
  } catch (error) {
  console.error(error);
  next(error);
  }
});

app.listen(3000, () => console.log("app listening on port 3000!"));