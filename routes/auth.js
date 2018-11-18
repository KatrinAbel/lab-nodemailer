const express = require("express");
const passport = require('passport');
const router = express.Router();
const nodemailer = require("nodemailer")
const User = require("../models/User")
const randomstring = require("randomstring")

/* Bcrypt to encrypt passwords */
const bcrypt = require("bcryptjs");
const bcryptSalt = 10;

/* Transporter = use Gmail server and stated user credentials for sending e-mails */
let transporter = nodemailer.createTransport({
  service: 'Gmail',
  auth: {
    user: process.env.GMAIL_EMAIL,
    pass: process.env.GMAIL_PASSWORD, 
  }
});

router.get("/login", (req, res, next) => {
  res.render("auth/login", { "message": req.flash("error") });
});

router.post("/login", passport.authenticate("local", {
  successRedirect: "/",
  failureRedirect: "/auth/login",
  failureFlash: true,
  passReqToCallback: true
}));

router.get("/signup", (req, res, next) => {
  res.render("auth/signup");
});

router.post("/signup", (req, res, next) => {
  const username = req.body.username;
  const password = req.body.password;
  const email = req.body.email;

  if (username === "" || password === "" || email === "") {
    res.render("auth/signup", { message: "Indicate username and password" });
    return;
  }

  User.findOne({ username }, "username", (err, user) => {
    if (user !== null) {
      res.render("auth/signup", { message: "The username already exists" });
      return;
    }

    const salt = bcrypt.genSaltSync(bcryptSalt);
    const hashPass = bcrypt.hashSync(password, salt);
    const hashCode = randomstring.generate(30)

    const newUser = new User({
      username,
      email,
      password: hashPass,
      confirmationCode: hashCode,
    });
    console.log("Debug new User", newUser)

    newUser.save()
    .then(() => {

        transporter.sendMail({
          from: '"Ironhack Project 👻" <lab-nodemailer@project.com>',
          to: email, 
          subject: "Please confirm your signup", 
          text: "Please confirm your signup via the following link: http://localhost:3000/auth/confirm/"+ hashCode,
          html:
          `
          <b>Hi ${username}, please confirm your signup via the following link</b>
          <a href:"http://localhost:3000/auth/confirm/${hashCode}">here</a>.
          If the link doesn't work you can go here http://localhost:3000/auth/confirm/${hashCode}
          `,
        })
        .then(info => 
          res.render('auth/login')
          )
        .catch(error => console.log("Error sending mail", error))
      });

      // res.redirect("/");
    })
    .catch(err => {
      res.render("auth/signup", { message: "Something went wrong" }, err);
    })
});

router.get("/confirm/:confirmCode", (req, res) => {
  let confirmationCode = req.params.confirmCode 
  User.findOneAndUpdate({confirmationCode}, {Status: "Active"})
  .then(user => {
    if (user) {
      res.redirect ("/confirmation", {user})
    }
    else {
      next("No user found")
    }
  })
})

  router.get("/confirmation", (req, res) => {
    res.render("auth/confirmation")
  })


router.get("/logout", (req, res) => {
  req.logout();
  res.redirect("/");
});

module.exports = router;
