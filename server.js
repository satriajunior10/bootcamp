const express = require("express");
const mysql = require("mysql2");
const bodyParser = require("body-parser");
const bcrypt = require("bcrypt");
const session = require("express-session");

const app = express();
const port = 3000;

app.use(bodyParser.urlencoded({ extended: false }));
app.use(
  session({
    secret: "your-secret-key",
    resave: true,
    saveUninitialized: true,
  })
);

// MySQL connection
const db = mysql.createConnection({
  host: "localhost",
  user: "root",
  password: "",
  database: "bootcamp",
});

db.connect((err) => {
  if (err) {
    console.error("Error connecting to the database:", err);
    throw err;
  }
  console.log("Connected to database");
});

// Serve static files (HTML, CSS, JS)
app.use(express.static("public"));

// Register route
app.post("/register", (req, res) => {
  const { name, email, password } = req.body;

  // Hash the password
  bcrypt.hash(password, 10, (err, hash) => {
    if (err) {
      console.error("Error hashing password:", err);
      return res.status(500).send("Internal server error");
    }

    // Insert the new user into the database
    const sql = "INSERT INTO users (name, email, password) VALUES (?, ?, ?)";
    db.query(sql, [name, email, hash], (err, result) => {
      if (err) {
        if (err.code === "ER_DUP_ENTRY") {
          return res.status(400).send("Email already exists");
        }
        console.error("Error inserting user into database:", err);
        return res.status(500).send("Internal server error");
      }
      res.send("User registered");
    });
  });
});

// Login route
app.post("/login", (req, res) => {
  const { email, password } = req.body;

  // Find the user by email
  const sql = "SELECT * FROM users WHERE email = ?";
  db.query(sql, [email], (err, results) => {
    if (err) {
      console.error("Error querying database:", err);
      return res.status(500).send("Internal server error");
    }

    if (results.length === 0) {
      return res.status(400).send("Email or password is incorrect");
    }

    const user = results[0];

    // Compare the password
    bcrypt.compare(password, user.password, (err, isMatch) => {
      if (err) {
        console.error("Error comparing passwords:", err);
        return res.status(500).send("Internal server error");
      }

      if (!isMatch) {
        return res.status(400).send("Email or password is incorrect");
      }

      // Save user id in session
      req.session.userId = user.id;

      // Redirect to juney.id/index2.html after successful login
      res.redirect("https://juney.id/index2.html");
    });
  });
});

// GET method to retrieve all users
app.get("/users", (req, res) => {
  // Query all users from the database
  const sql = "SELECT * FROM users";
  db.query(sql, (err, results) => {
    if (err) {
      console.error("Error querying database:", err);
      return res.status(500).send("Internal server error");
    }
    res.json(results);
  });
});

// Profile route
app.get("/profile", (req, res) => {
  // Ensure user is logged in
  if (!req.session.userId) {
    // Redirect user to login page if not logged in
    return res.redirect("/login");
  }

  // Retrieve user information from database based on user id stored in session
  const userId = req.session.userId;
  const sql = "SELECT * FROM users WHERE id = ?";
  db.query(sql, [userId], (err, results) => {
    if (err) {
      console.error("Error querying database:", err);
      return res.status(500).send("Internal server error");
    }

    // Send user information to profile page
    const user = results[0];
    res.render("profile.html", { user });
  });
});

app.listen(port, () => {
  console.log(`Server running on port ${port}`);
});
