const { request } = require("express");
const mysql = require("mysql");
const sha512 = require("js-sha512");
const crypto = require("crypto");
const aes256 = require("aes256");
const { error } = require("console");
const db = mysql.createConnection({
  host: process.env.DATABASE_HOST,
  user: process.env.DATABASE_USER,
  database: process.env.DATABASE,
  multipleStatements: true,
});
// DECLARING CUSTOM MIDDLEWARE
const hmacPassGenerator = (password, salt) => {
  let hashedPass = null;
  hashedPass = sha512.hmac(salt, password);
  return hashedPass;
};

const sha512PassGenerator = (password, salt) => {
  let hashedPass = null;
  let hash = sha512.update(password);
  hash.update(salt);
  hashedPass = hash.hex();
  return hashedPass;
};

const genRandomString = (length) => {
  return crypto
    .randomBytes(Math.ceil(length / 2))
    .toString("hex") /** convert to hexadecimal format */
    .slice(0, length); /** return required number of characters */
};
const checkPasswordType = (hashSelect, password) => {
  const salt = genRandomString(16);
  let hashedPass = null;
  let boolType = false;
  if (hashSelect === "HMAC") {
    hashedPass = hmacPassGenerator(password, salt);
    boolType = false;
  } else if (hashSelect === "SHA512") {
    hashedPass = sha512PassGenerator(password, salt);
    boolType = true;
  }
  return {
    boolType,
    hashedPass,
    salt,
  };
};

exports.register = (req, res) => {
  const { name, email, password, passwordConfirm, hashSelect } = req.body;
  db.query(
    "SELECT email FROM users WHERE email = ?",
    [email],
    (error, results) => {
      if (error) {
        console.log(error);
      }
      if (results.length > 0) {
        return res.render("register", {
          message: "That email hasbeen taken",
        });
      } else if (password !== passwordConfirm) {
        return res.render("register", {
          message: "Password not match",
        });
      }
      const { boolType, hashedPass, salt } = checkPasswordType(
        hashSelect,
        password
      );

      db.query(
        "INSERT INTO users SET ?",
        {
          login: name,
          salt: salt,
          isPasswordKeptAsHash: boolType,
          email: email,
          password: hashedPass,
        },
        (error, results) => {
          if (error) {
            // console.log(error);
          } else {
            // console.log(results);
            return res.render("register", {
              message: "User succesfully created!!",
            });
          }
        }
      );
    }
  );
};

exports.login = async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) {
      return res.status(400).render("login", {
        message: "Please provide an email or password",
      });
    }
    db.query(
      "SELECT * FROM users where email = ?",
      [email],
      async (error, results) => {
        const salt = await results[0].salt;
        const hmacPassword = hmacPassGenerator(password, salt);
        const shaPassword = sha512PassGenerator(password, salt);
        const userPassword = await results[0].password;
        const elems = [shaPassword, hmacPassword];
        const truePass = elems.filter((item) => {
          return item == userPassword;
        });
        if (truePass.length == 0) {
          res.status(401).render("login", {
            message: "Email or password is incorect",
          });
        } else {
          const sess = req.session;
          sess.userId = results[0].id;
          sess.user = results[0];
          res.redirect("/dashboard");
        }
      }
    );
  } catch (error) {
    console.log(error);
  }
};
exports.dashboard = async (req, res) => {
  try {
    const user = req.session.user,
      userId = req.session.userId;
    const userMasterPass = req.session.user.password;
    const sql = "SELECT * FROM `passwords` WHERE `user_id`='" + userId + "'";

    db.query(sql, function (err, results) {
      if (results.length > 0) {
        results.map((item, index) => {
          const notePass = item.password;
          return (item.decrypted = aes256.decrypt(userMasterPass, notePass));
        });
        const decrypted = results.map((item) => {
          return item.decrypted;
        });
        return res.render("dashboard", {
          user,
          results,
          decrypted,
        });
      } else {
        return res.render("dashboard", {
          user,
        });
      }
    });
  } catch (e) {
    console.log(e);
    return;
  }
};
//------------------------------------logout functionality----------------------------------------------
exports.logout = function (req, res) {
  req.session.destroy(function (err) {
    return res.redirect("/login");
  });
};
//------------------------------------reset password functionality----------------------------------------------
exports.resetPassword = async (req, res) => {
  try {
    //tade data from html form
    const { passwordOld, passwordNew, passwordConfirm, hashSelect } = req.body;
    //take data from cookies,session
    const user = req.session.user,
      userId = req.session.userId;
    const salt = user.salt;
    //Select user to compare password
    db.query(
      "SELECT * FROM users where id = ?",
      [userId],
      async (error, results) => {
        //Hash old password to compare with password id DB
        const hmacPassword = hmacPassGenerator(passwordOld, salt);
        const shaPassword = sha512PassGenerator(passwordOld, salt);
        const userPassword = await results[0].password;
        const elems = [shaPassword, hmacPassword];
        const truePass = elems.filter((item) => {
          return item == userPassword;
        });
        if (truePass.length == 0) {
          return res.status(401).render("resetPassword", {
            message: "Old password is incorrect!",
          });
        } else {
          if (passwordNew != passwordConfirm) {
            return res.status(401).render("resetPassword", {
              message: "Password not match!",
            });
          }
          const { boolType, hashedPass, salt } = checkPasswordType(
            hashSelect,
            passwordNew
          );
          //Update hash,salt, and Type of password
          db.query(
            "UPDATE users SET salt=?, isPasswordKeptAsHash=?, password=?  WHERE id=?",
            [salt, boolType, hashedPass, userId],
            (err, results) => {
              if (err) {
                console.log(err);
              }
              const sql =
                "SELECT * FROM `passwords` WHERE `user_id`='" + userId + "'";
              db.query(sql, function (err, results) {
                if (results.length > 0) {
                  const decrypted = results.map((item) => {
                    return (item.password = aes256.decrypt(
                      userPassword,
                      item.password
                    ));
                  });
                  const encrypted = decrypted.map((item) => {
                    return aes256.encrypt(hashedPass, item);
                  });
                  // const goodPass = encrypted.map((item) => {
                  //   return aes256.decrypt(hashedPass, item);
                  // });

                  const idWallet = results.map((item) => {
                    return item.id;
                  });
                  const items = idWallet.map(function (i, index) {
                    return {
                      id: i,
                      password: encrypted[index],
                    };
                  });
                  console.log(items);
                  items.map((item) => {
                    db.query(
                      "UPDATE passwords SET password=? WHERE id=?",
                      [item.password, item.id],
                      (err, results) => {
                        if (err) {
                          console.log(err);
                        }
                        console.log(results);
                      }
                    );
                  });

                  const goodPass = items.map((item) => {
                    return (item.password = aes256.decrypt(
                      hashedPass,
                      item.password
                    ));
                  });
                  results.map((item, index) => {
                    if (item.id === items[index].id) {
                      item.decrypted = goodPass[index].password;
                    }
                  });
                  console.log(results);
                  return res.redirect("/login");
                } else {
                  return res.render("dashboard", {
                    user,
                  });
                }
              });
            }
          );
        }
      }
    );
  } catch (e) {
    console.log(e);
  }
};
