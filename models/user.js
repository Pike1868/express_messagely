/** User class for message.ly */
const db = require("../db");
const bcrypt = require("bcrypt");
const ExpressError = require("../expressError");
const { SECRET_KEY, BCRYPT_WORK_FACTOR } = require("../config");
const jwt = require("jsonwebtoken");
const JWT_OPTIONS = { expiresIn: 60 * 60 }; // 1 hour

/** User of the site. */

class User {
  /** register new user -- returns
   *    {username, password, first_name, last_name, phone}
   */

  static async register({ username, password, first_name, last_name, phone }) {
    let hashedPassword = await bcrypt.hash(password, BCRYPT_WORK_FACTOR);
    const user = await db.query(
      `INSERT INTO users (username, password, first_name, last_name, phone, join_at, last_login_at)
      VALUES ($1, $2, $3, $4, $5, current_timestamp, current_timestamp) RETURNING username, password, first_name, last_name, phone`,
      [username, hashedPassword, first_name, last_name, phone]
    );

    const token = jwt.sign(
      { username: user.rows[0].username },
      SECRET_KEY,
      JWT_OPTIONS
    );
    return token;
  }

  /** Authenticate: is this username/password valid? Returns boolean. */

  static async authenticate(username, password) {
    const result = await db.query(
      `SELECT username, password
      FROM users
      WHERE username = $1`,
      [username]
    );
    const user = result.rows[0];
    if (!user) return false;
    if (await bcrypt.compare(password, user.password)) {
      return true;
    }

    return false;
  }

  /** Update last_login_at for user */

  static async updateLoginTimestamp(username) {
    const result = await db.query(
      `UPDATE users
      SET last_login_at = current_timestamp
      WHERE username = $1
      RETURNING username, last_login_at`,
      [username]
    );
    if (!result.rows[0]) {
      throw new ExpressError(`No such user: ${username}`, 404);
    }
  }

  /** All: basic info on all users:
   * [{username, first_name, last_name, phone}, ...] */

  static async all() {
    const results = await db.query(
      `SELECT username, first_name, last_name, phone
        FROM users`
    );

    return results.rows;
  }

  /** Get: get user by username
   *
   * returns {username,
   *          first_name,
   *          last_name,
   *          phone,
   *          join_at,
   *          last_login_at } */

  static async get(username) {
    const user = await db.query(
      `SELECT username, first_name, last_name, phone, join_at, last_login_at
      FROM users
      WHERE username = $1`,
      [username]
    );

    return user.rows[0];
  }

  /** Generate token for user */
  static generateToken(username) {
    return jwt.sign({ username }, SECRET_KEY, JWT_OPTIONS);
  }

  /** Return messages from this user.
   *
   * [{id, to_user, body, sent_at, read_at}]
   *
   * where to_user is
   *   {username, first_name, last_name, phone}
   */

  static async messagesFrom(username) {
    const result = await db.query(
      `SELECT m.id, 
      m.to_username,
      u.first_name,
      u.last_name,
      u.phone,
      m.body,
      m.sent_at,
      m.read_at
      FROM messages AS m
      JOIN users as u ON m.to_username = u.username 
      WHERE from_username = $1`,
      [username]
    );
    return result.rows.map((msg) => {
      return {
        id: msg.id,
        to_user: {
          username: msg.to_username,
          first_name: msg.first_name,
          last_name: msg.last_name,
          phone: msg.phone,
        },
        body: msg.body,
        sent_at: msg.sent_at,
        read_at: msg.read_at,
      };
    });
  }

  /** Return messages to this user.
   *
   * [{id, from_user, body, sent_at, read_at}]
   *
   * where from_user is
   *   {username, first_name, last_name, phone}
   */

  static async messagesTo(username) {
    const result = await db.query(
      `SELECT m.id, 
      m.from_username,
      u.first_name,
      u.last_name,
      u.phone,
      m.body,
      m.sent_at,
      m.read_at
      FROM messages AS m
      JOIN users as u ON m.from_username = u.username 
      WHERE to_username = $1`,
      [username]
    );
    return result.rows.map((msg) => {
      return {
        id: msg.id,
        from_user: {
          username: msg.from_username,
          first_name: msg.first_name,
          last_name: msg.last_name,
          phone: msg.phone,
        },
        body: msg.body,
        sent_at: msg.sent_at,
        read_at: msg.read_at,
      };
    });
  }
}

module.exports = User;
