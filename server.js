const express = require("express");
const mysql = require("mysql");
const cors = require("cors");
const crypto = require("crypto");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const cookieParser = require("cookie-parser");
const salt = 10;

// const whitelist = [
//   "http://localhost:3000",
//   undefined, //for testing with POSTMAN,
// ];
// const corsOptions = {
//   origin: (origin, callback) => {
//     if (whitelist.indexOf(origin) !== -1) {
//       callback(null, true);
//     } else {
//       callback(new Error());
//     }
//   },
//   optionsSuccessStatus: 200, // some legacy browsers (IE11, various SmartTVs) choke on 204
// };

const app = express();
app.use(
  cors({
    origin: ["http://localhost:3000"],
    methods: ["GET", "POST"],
    credentials: true,
  })
);
app.use(express.json());
app.use(cookieParser());

const db = mysql.createConnection({
  host: "localhost",
  user: "root",
  password: "password",
  database: "dev",
});

const verifyUser = (req, res, next) => {
  const token = req.cookies.token;
  if (!token) {
    return res.json({ status: "You are not authenticated" });
  } else {
    jwt.verify(token, "jwt-secret-key", (err, decoded) => {
      if (err) {
        return res.json({ status: "Incorrect token" });
      } else {
        req.name = decoded.name;
        next();
      }
    });
  }
};

app.get("/home", verifyUser, (req, res) => {
  return res.json({ status: "Success", name: req.name });
});

app.post("/signup", (req, res) => {
  const sql =
    "INSERT INTO Users (uid, email, firstName, lastName, password) VALUES (?)";
  bcrypt.hash(req.body.password.toString(), salt, (err, hash) => {
    if (err) return res.json({ status: "Error hashing password" });
    const values = [
      crypto.randomUUID(),
      req.body.email,
      req.body.firstName,
      req.body.lastName,
      hash,
    ];
    db.query(sql, [values], (err, data) => {
      if (err) {
        console.log(err);
        return res.json({ status: "Server Side Error" });
      }
      console.log("Register succesfully!");
      return res.json({ status: "Success" });
    });
  });
});

app.post("/login", (req, res) => {
  const sql = "SELECT * FROM Users WHERE email = ?";
  db.query(sql, [req.body.email], (err, data) => {
    if (err) {
      console.log(err);
      return res.json({ status: "Wrong email or password" });
    }
    if (data.length > 0) {
      bcrypt.compare(
        req.body.password.toString(),
        data[0].password,
        (err, response) => {
          if (err) return res.json({ status: "Wrong email or password" });
          if (response) {
            console.log("Login successfully");
            const name = data[0].firstName + "-" + data[0].lastName;
            const token = jwt.sign({ name }, "jwt-secret-key", {
              expiresIn: "1d",
            });
            res.cookie("token", token);
            return res.json({ status: "Success" });
          } else {
            return res.json({ status: "Wrong email or password" });
          }
        }
      );
    } else {
      return res.json({ status: "Login Failed" });
    }
  });
});

app.get("/logout", (req, res) => {
  res.clearCookie("token");
  return res.json({ status: "Success" });
});

app.listen(8081, () => {
  console.log("listening on port 8081");
});
