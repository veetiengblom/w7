const express = require("express");
const router = express.Router();
const bcrypt = require("bcrypt");
const { body, validationResult } = require("express-validator");
const session = require("express-session");

const users = [];
const todoList = [];

const validateRegistration = [
  body("username").isLength({ min: 3 }).trim().escape(),
  body("password").isLength({ min: 3 }),
];

const validateLogin = [
  body("username").isLength({ min: 3 }).trim().escape(),
  body("password").isLength({ min: 3 }),
];

// GET home page
router.get("/", (req, res) => {
  res.render("index", { title: "Express" });
});

// User registration
router.post("/api/user/register", validateRegistration, (req, res) => {
  try {
    if (req.session.user) {
      return res.redirect("/");
    }

    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    const isUsernameTaken = users.some(
      (user) => user.username === req.body.username
    );
    if (isUsernameTaken) {
      return res.status(400).json({ username: "Username already in use." });
    }

    bcrypt.genSalt(10, (err, salt) => {
      if (err) throw err;

      bcrypt.hash(req.body.password, salt, (err, hash) => {
        if (err) throw err;

        const newUser = {
          id: Date.now().toString(),
          username: req.body.username,
          password: hash,
        };

        users.push(newUser);
        console.log(users);
        return res.status(200).json(newUser);
      });
    });
  } catch {}
});

// Get list of registered users
router.get("/api/user/list", (req, res) => {
  res.json(users);
});

// User login
router.post("/api/user/login", validateLogin, (req, res) => {
  if (req.session.user) {
    return res.redirect("/");
  }

  const { username, password } = req.body;
  const user = users.find((user) => user.username === username);

  if (!user) {
    return res.status(401).json({ message: "Invalid username or passwor" });
  }

  bcrypt.compare(password, user.password, (err, isMatch) => {
    if (err) {
      throw err;
    }

    if (isMatch) {
      req.session.user = user;
      return res.status(200).send();
    } else {
      return res.status(401).json({ message: "Invalid username or passwor" });
    }
  });
});

// Secret route
router.get("/api/secret", (req, res) => {
  if (req.session.user) {
    res.status(200).send();
  } else {
    res.status(401).json({ message: "Unauthorized" });
  }
});

// Add todo
router.post("/api/todos", (req, res) => {
  if (!req.session.user) {
    return res.status(401).json({ message: "Unauthorized" });
  }

  let userFound = todoList.find((list) => list.id === req.session.user.id);
  if (!userFound) {
    userFound = { id: req.session.user.id, todos: [] };
    todoList.push(userFound);
  }

  userFound.todos.push(req.body.todo);

  res.json(userFound);
});

// Get list of todos
router.get("/api/todos/list", (req, res) => {
  res.json(todoList);
});

module.exports = router;

/*
var express = require("express");
var router = express.Router();
const bcrypt = require("bcrypt");
const { body, validationResult } = require("express-validator");
const session = require("express-session");
const users = require("./user-data");

const passport = require("./passport-config");

const todosList = [];
*/
/* GET home page. */
/*
router.get("/", function (req, res, next) {
  res.render("index", { title: "Express" });
});

router.post(
  "/api/user/register",
  body("username").isLength({ min: 3 }).trim().escape(),
  body("password").isLength({ min: 5 }),
  (req, res, next) => {
    const { username, password } = req.body;
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    } else {
      // Check if username is already taken
      if (users.some((user) => user.username === username)) {
        return res.status(400).json({ message: "Username already taken" });
      }

      // Hash the password
      const hashedPassword = bcrypt.hashSync(password, 10);

      // Create user object
      const user = {
        id: Date.now().toString(),
        username: username,
        password: hashedPassword,
      };

      // Save user
      users.push(user);

      // Respond with the created user object
      res.json(user);
    }
    
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
  passport.authenticate("local", (err, user, info) => {
    if (err) {
      return next(err);
    }

    if (!user) {
      return res.status(401).json({ message: "Invalid username or password" });
    }

    req.logIn(user, (err) => {
      if (err) {
        return next(err);
      }

      // Successful login, send session cookie
      res.sendStatus(200);
    });
  })(req, res, next);
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

router.get("/api/secret", isAuthenticated, (req, res) => {
  res.sendStatus(200);
});

// Login redirection middleware
function isAuthenticated(req, res, next) {
  if (req.isAuthenticated()) {
    return next();
  }
  res.redirect("/");
}

router.post("/api/todos", isAuthenticated, (req, res) => {
  const userId = req.user.id;
  const { todo } = req.body;

  // Find user's todos
  let userTodos = todosList.find((t) => t.id === userId);
  // If user has no todos yet, create a new entry
  if (!userTodos) {
    userTodos = { id: userId, todos: [] };
    todosList.push({ id: userId, todos: [todo] });
  }

  // Add todo to existing user's todos
  userTodos.todos.push(todo);

  // Respond with the user's todo object
  res.json({ id: userId, todos: userTodos.todos });
});

router.get("/api/todos/list", (req, res, next) => {
  res.send(todosList);
});

module.exports = router;
*/
