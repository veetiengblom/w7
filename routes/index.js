var express = require("express");
var router = express.Router();
const bcrypt = require("bcrypt");
const { body, validationResult } = require("express-validator");

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
              id: Date.now().toString(36) + Math.random().toString(36),
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

module.exports = router;
