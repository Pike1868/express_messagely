const express = require("express");
const router = new express.Router();
const User = require("../models/user");

router.get("/test", async (req, res, next) => {
  res.send("user routes are working!");
});

/** GET / - get list of users.
 *
 * => {users: [{username, first_name, last_name, phone}, ...]}
 *
 **/
router.get("/", async (req, res, next) => {
  try {
    const users = await User.all();
    return res.json({ users });
  } catch (err) {
    return next(err);
  }
});

/** GET /:username - get detail of users.
 *
 * => {user: {username, first_name, last_name, phone, join_at, last_login_at}}
 *
 **/

router.get("/:username", async (req, res, next) => {
  try {
    const { username } = req.params;
    const user = await User.get({ username });

    return res.json(user);
  } catch (err) {
    return next(err);
  }
});

/** GET /:username/to - get messages to user
 *
 * => {messages: [{id,
 *                 body,
 *                 sent_at,
 *                 read_at,
 *                 from_user: {username, first_name, last_name, phone}}, ...]}
 *
 **/

router.get("/:username/to", async (req, res, next) => {
  try {
    const { username } = req.params;
    let user_messages = await User.messagesTo(username);
    return res.json({ user_messages });
  } catch (err) {
    return next(err);
  }
});

/** GET /:username/from - get messages from user
 *
 * => {messages: [{id,
 *                 body,
 *                 sent_at,
 *                 read_at,
 *                 to_user: {username, first_name, last_name, phone}}, ...]}
 *
 **/

router.get("/:username/from", async (req, res, next) => {
  try {
    const { username } = req.params;
    let user_messages = await User.messagesFrom(username);
    return res.json({ user_messages });
  } catch (err) {
    return next(err);
  }
});

module.exports = router;
