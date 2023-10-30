const express = require("express");
const router = new express.Router();
const ExpressError = require("../expressError");
const User = require("../models/user");


router.get("/test", async (req, res, next) => {
  res.send("Auth is working!");
});

/** POST /register - register user: registers, logs in, and returns token.
 *
 * {username, password, first_name, last_name, phone} => {token}.
 *
 *  Make sure to update their last-login!
 *
 */
router.post("/register", async (req, res, next) => {
  try {
    const { username, password, first_name, last_name, phone } = req.body;
    if (!username || !password) {
      throw new ExpressError("Username and password required", 400);
    }

    let token = await User.register({
      username,
      password,
      first_name,
      last_name,
      phone,
    });
    res.json({ token });
  } catch (err) {
    console.log(err);
    if (err.code === `23505`) {
      return next(new ExpressError("Username taken, please pick another", 400));
    }
    return next(err);
  }
});

/** POST /login - login: {username, password} => {token}
 *
 *
 * Make sure to update their last-login!
 *
 **/

router.post("/login", async (req, res, next) => {
  try {
    const { username, password } = req.body;

    if (!username || !password) {
      throw new ExpressError("Username and password required", 400);
    }
    if (await User.authenticate(username, password)) {
      const token = User.generateToken(username);
      await User.updateLoginTimestamp(username);
      return res.json({ token });
    }
    throw new ExpressError("Invalid username/password", 400);
  } catch (err) {
    console.log(err);
    return next(err);
  }
});

module.exports = router;
