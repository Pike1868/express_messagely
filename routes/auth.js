const express = require("express");
const router = new express.Router();
const ExpressError = require("../expressError");
const db = require("../db");
const bcrypt = require("bcrypt");


router.get("/test", async (req, res, next) => {
  res.send("Auth is working!");
});

/** POST /login - login: {username, password} => {token}
 *
 *
 * Make sure to update their last-login!
 *
 **/

router.post("/login", async (req, res, next) => {
  try {
    const { username } = req.body;
    if (!username || !password) {
      throw new ExpressError("Username and password required", 400);
    }
    const result = await db.query(
      `SELECT username, password 
        FROM users 
        WHERE username=$1`,
      [username]
    );

    const user = result.rows[0];
    if (user) {
      if (await bcrypt.compare(password, user.password)) {
        return res.json({ message: `Logged in!` });
      }
    }
    throw new ExpressError("Username not found", 400);
  } catch (err) {
    return next(err);
  }
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
    const { username, password } = req.body;
    if (!username || !password) {
      throw new ExpressError("Username and password required", 400);
    }
    //hash password
    let hashedPassword = await bcrypt.hash(password, BCRYPT_WORK_FACTOR);

    //save to db
    let result = await db.query(
      `INSERT INTO users (username, password) 
            VALUES ($1, $2)
            RETURNING username`,
      [username, hashedPassword]
    );
    return res.json(result.rows[0]);
  } catch (err) {
    // console.log(err);
    if (err.code === `23505`) {
      return next(new ExpressError("Username taken, please pick another", 400));
    }
    return next(err);
  }
});

module.exports = router;
