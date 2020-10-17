const aes256 = require("aes256");
const { request } = require("express");
const mysql = require("mysql");
const db = mysql.createConnection({
  host: process.env.DATABASE_HOST,
  user: process.env.DATABASE_USER,
  database: process.env.DATABASE,
});
exports.register = (req, res) => {
  const { name, webAdress, password, passwordConfirm, descr } = req.body;
  const user = req.session.user;
  const mainUserId = req.session.userId;
  if (mainUserId == null || mainUserId == undefined) {
    return res.render("login", {
      message: "Please login",
    });
  }
  if (!mainUserId) {
    return res.render("login", {
      message: "Please login",
    });
  }
  const mainUserPassword = req.session.user.password;
  if (password !== passwordConfirm) {
    return res.render("createUser", {
      message: "Password not match",
    });
  }
  // const plaintext = password;
  // const key = mainUserPassword;
  const encrypted = aes256.encrypt(mainUserPassword, password);
  const decrypted = aes256.decrypt(mainUserPassword, encrypted);

  db.query(
    "INSERT INTO passwords SET ?",
    {
      password: encrypted,
      web_address: webAdress,
      description: descr,
      login: name,
      user_id: mainUserId,
    },
    (error, results) => {
      if (error) {
        console.log(error);
      } else {
        return res.redirect("/dashboard");
      }
    }
  );
};
exports.delete = (req, res) => {
  const id = req.params.id;
  db.query("DELETE from passwords where id=?", [id], (err, results) => {
    if (err) {
      console.log(err);
    }
    return res.redirect("/dashboard");
  });
};
