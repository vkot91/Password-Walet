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
// 1 -SHA512
// 0  - HMAC
//------------------------------------Create HMAC hash functionality----------------------------------------------
const hmacPassGenerator = (password, salt) => {
  let hashedPass = null;
  hashedPass = sha512.hmac(salt, password);
  return hashedPass;
};
//------------------------------------Create SHA512 hash functionality----------------------------------------------
const sha512PassGenerator = (password, salt) => {
  let hashedPass = null;
  let hash = sha512.update(password);
  hash.update(salt);
  hashedPass = hash.hex();
  return hashedPass;
};
//------------------------------------Create SALT functionality----------------------------------------------
const genRandomString = (length) => {
  return crypto
    .randomBytes(Math.ceil(length / 2))
    .toString("hex") /** convert to hexadecimal format */
    .slice(0, length); /** return required number of characters */
};
//----------Check what type of paassword user selected----------
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
//------------------------------------ Register functionality----------------------------------------------
exports.register = (req, res) => {
  //take data from form
  const { name, email, password, passwordConfirm, hashSelect } = req.body;
  //check if user allready exists
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
      //Get hashed pass, salt and type of password
      const { boolType, hashedPass, salt } = checkPasswordType(
        hashSelect,
        password
      );
      //send data to DB.
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
            console.log(error);
          } else {
            return res.render("register", {
              message: "User succesfully created!!",
            });
          }
        }
      );
    }
  );
};
//------------------------------------ Login functionality----------------------------------------------
exports.login = async (req, res) => {
  try {
    //Get data from form
    const { email, password } = req.body;
    if (!email || !password) {
      return res.status(400).render("login", {
        message: "Please provide an email or password",
      });
    }
    //Take password and salt from database
    //Hash new password with old salt
    //Use two methods and compare passwords
    db.query(
      "SELECT * FROM users where email = ?",
      [email],
      async (error, results) => {
        const salt = await results[0].salt;
        const passwordType = await results[0].isPasswordKeptAsHash;
        let truePass = null;
        if (passwordType == 0) {
          truePass = hmacPassGenerator(password, salt);
        } else if (passwordType == 1) {
          truePass = sha512PassGenerator(password, salt);
        }
        const userPassword = await results[0].password;
        if (error) {
          console.log(error);
        }
        if (truePass != userPassword) {
          res.status(401).render("login", {
            message: "Email or password is incorect",
          });
        } else {
          //If status = OK, send data to session and redirect to user page
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
//------------------------------------ Dashboard functionality----------------------------------------------
exports.dashboard = async (req, res) => {
  try {
    //Get user from session
    const user = req.session.user,
      userId = req.session.userId;
    const userMasterPass = req.session.user.password;
    const sql = "SELECT * FROM `passwords` WHERE `user_id`='" + userId + "'";
    //If user has some notes in his wallet  - show them
    db.query(sql, function (err, results) {
      if (results.length > 0) {
        results.map((item, index) => {
          const notePass = item.password;
          //Decrypt user password with his password from account and aes256 function
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
//------------------------------------Logout functionality----------------------------------------------
exports.logout = function (req, res) {
  req.session.destroy(function (err) {
    return res.redirect("/login");
  });
};
//------------------------------------Reset password functionality----------------------------------------------
exports.resetPassword = async (req, res) => {
  try {
    //Take data from html form
    const { passwordOld, passwordNew, passwordConfirm, hashSelect } = req.body;
    //Take data from cookies,session
    const user = req.session.user,
      userId = req.session.userId;
    const salt = user.salt;
    //Select user to compare password
    db.query(
      "SELECT * FROM users where id = ?",
      [userId],
      async (error, results) => {
        let truePassword = null;
        const passwordType = await results[0].isPasswordKeptAsHash;
        if (passwordType == 0) {
          truePass = hmacPassGenerator(passwordOld, salt);
        } else if (passwordType == 1) {
          truePass = sha512PassGenerator(passwordOld, salt);
        }
        const userPassword = await results[0].password;

        if (truePass != userPassword) {
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
              //Select all active users passwords
              const sql =
                "SELECT * FROM `passwords` WHERE `user_id`='" + userId + "'";
              db.query(sql, function (err, results) {
                if (results.length > 0) {
                  //Decrypt all passwords
                  const decrypted = results.map((item) => {
                    return (item.password = aes256.decrypt(
                      userPassword,
                      item.password
                    ));
                  });
                  //And encrypt passwords again with new main user password
                  const encrypted = decrypted.map((item) => {
                    return aes256.encrypt(hashedPass, item);
                  });

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
                  //Update all passports from wallet in database
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
