var express = require("express");
var router = express.Router();
const bcrypt = require("bcrypt");
const { body, validationResult } = require("express-validator");
const session = require("express-session");

const userList = [];

/* GET home page. */
router.get("/", function (req, res, next) {
  res.render("index", { title: "Express" });
});

router.post(
  "/api/user/register",
  body("username").isLength({ min: 3 }).trim().escape(),
  body("password").isLength({ min: 5 }),
  (req, res, next) => {
    let userfound = 0;
    const username = req.body.username;
    const password = req.body.password;
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    } else {
      userList.forEach((user) => {
        if (user.username == username) {
          userfound = 1;
        }
      });
      if (userfound == 1) {
        return res.status(400).json({ username: "User already in use." });
      } else {
        bcrypt.genSalt(10, (err, salt) => {
          bcrypt.hash(password, salt, (err, hash) => {
            if (err) throw err;
            const userData = {
              username: username,
              password: hash,
              id: Date.now().toString(),
            };
            userList.push(userData);
            return res.send(userData);
          });
        });
      }
    }
  }
);

router.get("/api/user/list", (req, res, next) => {
  res.send(userList);
});

router.post("/api/user/login", (req, res, next) => {
  const userFound = userList.find((user) => user.username == req.body.username);
  if (userFound) {
    bcrypt.compare(req.body.password, user.password, (err, isMatch) => {
      if (err) throw err;
      if (isMatch) {
        req.session.user = userFound;
        console.log("User logged in");
        return res.status(200).send();
      } else {
        console.log("Log in failed");
        return res.status(401).json({ msg: "Invalid password" });
      }
    });
  } else {
    res.status(401).json({ msg: "Failed to login" });
  }
});

module.exports = router;
