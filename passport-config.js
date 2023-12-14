const passport = require("passport");
const LocalStrategy = require("passport-local").Strategy;
const bcrypt = require("bcrypt");
const users = require("./user-data");

// Sample data structure to store users

passport.use(
  new LocalStrategy((username, password, done) => {
    // Find user by username
    const user = users.find((u) => u.username === username);

    if (!user || !bcrypt.compareSync(password, user.password)) {
      return done(null, false, { message: "Invalid username or password" });
    }

    return done(null, user);
  })
);

passport.serializeUser((user, done) => {
  done(null, user.id);
});

passport.deserializeUser((id, done) => {
  const user = users.find((u) => u.id === id);
  done(null, user);
});

module.exports = passport;
