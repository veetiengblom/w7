var express = require("express");
var router = express.Router();
const bcrypt = require("bcrypt");
const { body, validationResult } = require("express-validator");
const session = require("express-session");

const userList = [];
const todoList = [];

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

    if (req.session.user == username) {
      return res.redirect("/");
    }

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
              id: Date.now().toString(),
              username: username,
              password: hash,
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
    if (req.session.user == userFound.username) {
      return res.redirect("/");
    }
    bcrypt.compare(req.body.password, userFound.password, (err, isMatch) => {
      if (err) throw err;
      if (isMatch) {
        req.session.user = userFound.username;
        console.log("Req.session.user:" + req.session.user);
        console.log("id?: " + req.session.user.id);
        console.log("username?: " + req.session.user.username);
        console.log("password?: " + req.session.user.password);
        return res.status(200).send("ok");
      } else {
        return res.status(401).json({ msg: "Failed to login" });
      }
    });
  } else {
    res.status(401).json({ msg: "Failed to login" });
  }
});

router.get("/api/secret", (req, res, next) => {
  if (req.session.user) {
    console.log("This is the user session: " + req.session.user);
    return res.status(200).send("ok");
  } else {
    return res.status(401).json({ msg: "Unauthorized" });
  }
});

router.post("/api/todos", (req, res, next) => {
  if (req.session.user) {
    const todo = req.body.todo;
    const user = userList.find((user) => req.session.user == user.username);
    const userFound = todoList.find((list) => list.id === user.id);

    if (userFound) {
      console.log("user has todos");
      userFound.todos.push(todo);
      return res.json(userFound);
    } else {
      console.log("User does not have todos");
      const newUser = {
        id: user.id,
        todos: [todo],
      };
      todoList.push(newUser);
      return res.json(newUser);
    }
  } else {
    return res.status(401).json({ msg: "Unauthorized" });
  }
});

router.get("/api/todos/list", (req, res, next) => {
  res.send(todoList);
});

module.exports = router;
