const express = require("express");
const SHA256 = require("crypto-js/sha256");
const encBase64 = require("crypto-js/enc-base64");
const uid2 = require("uid2");

const User = require("../models/User");

const router = express.Router();

router.post("/user/signup", async (req, res) => {
  try {
    const user = await User.findOne({ email: req.fields.email });
    if (!user) {
      const salt = uid2(16);
      const hash = SHA256(req.fields.password + salt).toString(encBase64);
      const token = uid2(16);

      const newUser = new User({
        email: req.fields.email,
        username: req.fields.username,
        token: token,
        hash: hash,
        salt: salt,
      });

      await newUser.save();

      res.status(200).json({
        _id: newUser._id,
        token: newUser.token,
        message: "New User successfully created",
      });
    } else {
      res.status(409).json({
        message: "An account has already been created with this email address",
      });
    }
  } catch (error) {
    res.status(400).json({ message: error.message });
    console.log(error.message);
  }
});

router.post("/user/login", async (req, res) => {
  try {
    const user = await User.findOne({ email: req.fields.email });
    if (user) {
      const newHash = SHA256(req.fields.password + user.salt).toString(
        encBase64
      );
      if (newHash === user.hash) {
        res.status(200).json({
          _id: user._id,
          token: user.token,
          message: "User successfully logged in",
        });
      } else {
        res
          .status(401)
          .json({ message: "Incorrect email address and/or password" });
      }
    } else {
      res
        .status(401)
        .json({ message: "Incorrect email address and/or password" });
    }
  } catch (error) {
    res.status(400).json({ message: error.message });
  }
});

module.exports = router;
