require("dotenv").config();
const express = require("express");
const mysql = require("mysql");
const cors = require("cors");
const crypto = require("crypto");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const cookieParser = require("cookie-parser");
const salt = 10;
const INITIAL = "INITIAL";
const REGISTERED = "REGISTERED";

const app = express();

const proxy = require("http-proxy-middleware");

app.use(
  cors({
    origin: [process.env.REACT_APP_HOST, process.env.KONG_APP_HOST],
    methods: ["GET", "POST"],
    credentials: true,
  })
);
app.use(express.json());
app.use(cookieParser());

const db = mysql.createConnection({
  host: process.env.MYSQL_DB_HOST,
  user: process.env.MYSQL_DB_USER,
  password: process.env.MYSQL_DB_PWD,
  database: process.env.MYSQL_DB_SCHEMA,
});

//verify whether cookie user is a valid user
const verifyUser = (req, res, next) => {
  const token = req.cookies.token;
  if (!token) {
    return res.json({ status: "You are not authenticated" });
  } else {
    jwt.verify(token, process.env.JWT_SECRET_KEY, (err, decoded) => {
      if (err) {
        return res.json({ status: "Incorrect token" });
      } else {
        req.name = decoded.name;
        next();
      }
    });
  }
};

//create token
const createToken = (siteUID) => {
  const token = jwt.sign({ siteUID }, process.env.JWT_SECRET_KEY, {
    expiresIn: "1d",
  });
  return token;
};

//home API
app.post("/home", verifyUser, (req, res) => {
  console.log("home: ", req.body);
  const sql = "SELECT * FROM Users WHERE uid = ?";
  db.query(sql, [req.body.siteUID], (err, data) => {
    if (err) {
      return res.json({ status: "Wrong email or password" });
    }
    if (data.length > 0) {
      const name = data[0].firstName + "-" + data[0].lastName;
      return res.json({ status: "Success", name: name });
    } else {
      return res.json({ status: "Login Failed" });
    }
  });
});

//initRegister API
app.post("/initRegister", (req, res) => {
  console.log("initRegister: ", req.body);
  const sql =
    "INSERT INTO Users (uid, email, firstName, lastName, status, password ) VALUES (?)";
  bcrypt.hash(req.body.password.toString(), salt, (err, hash) => {
    if (err) return res.json({ status: "Error hashing password" });
    const uid = crypto.randomUUID();
    const values = [
      uid,
      req.body.email,
      req.body.firstName,
      req.body.lastName,
      INITIAL,
      hash,
    ];
    db.query(sql, [values], (err, data) => {
      if (err) {
        console.log(err);
        return res.json({ status: "Email is taken" });
      }
      console.log("Initial Registration succesful!");
      return res.json({ status: "Success", siteUID: uid });
    });
  });
});

//finalRegister API
app.post("/finalRegister", (req, res) => {
  console.log("finalRegister:", req.body);
  const sql = "UPDATE Users SET status = ? WHERE uid = ?";

  db.query(sql, [REGISTERED, req.body.siteUID], (err, data) => {
    if (err) {
      console.log(err);
      return res.json({ status: "Server Side Error1" });
    }
    const token = createToken(req.body.siteUID);
    res.cookie("token", token);
    return res.json({ status: "Success" });
  });
});

//checkEmail API
app.post("/checkEmail", (req, res) => {
  console.log("checkEmail: ", req.body);
  const sql = "SELECT * FROM Users WHERE email = ?";
  db.query(sql, [req.body.email], (err, data) => {
    if (err) {
      console.log(err);
      return res.json({ status: "Check Again later" });
    }
    // console.log(data);
    if (data.length > 0) {
      return res.json({ status: "Email taken" });
    } else {
      return res.json({ status: "Success" });
    }
  });
});

//initLogin API
app.post("/initLogin", (req, res) => {
  console.log("Init Login:", req.body);
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
            console.log("Intial Login successful!");
            return res.json({ status: "Success", siteUID: data[0].uid });
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

//finalLogin API
app.post("/finalLogin", (req, res) => {
  console.log("finalLogin:", req.body);
  const token = createToken(req.body.siteUID);
  res.cookie("token", token);
  return res.json({ status: "Success" });
});

//logout API
app.get("/logout", (req, res) => {
  res.clearCookie("token");
  return res.json({ status: "Success" });
});

app.listen(8081, () => {
  console.log("listening on port 8081");
});
