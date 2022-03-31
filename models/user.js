const mongoose = require("mongoose");
const Schema = mongoose.Schema;
const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");
const crypto = require('crypto');

const userSchema = new Schema({
  name: {
    type: String,
    unique: true,
  },
  password: {
    type: String,
  },
  joined: {
    type: Date,
    default: Date.now(),
  },
  resetPasswordToken: {
    type: String,
  },
  resetPasswordTokenExpire: {
    type: Date,
  }
});

userSchema.pre("save", async function (next) {
  const salt = await bcrypt.genSalt(10);

  if (!this.isModified("password")) {
    next();
  }

  this.password = await bcrypt.hash(this.password, salt);
});

userSchema.methods.getsignJwt = function () {
  return jwt.sign({ id: this._id }, process.env.JWT_SECRET, {
    expiresIn: process.env.JWT_EXPIRY_DATA,
  });
};

userSchema.methods.getResetPasswordToken = function () {
  const resetToken = crypto.randomBytes(20).toString('hex');

  this.resetPasswordToken = crypto.createHash('sha256').update(resetToken).digest('hex');

  this.resetPasswordTokenExpire = new Date(Date.now() + 2 * 60 * 60 * 1000);

  return resetToken;
}

userSchema.methods.matchPass = async function (password) {
  return await bcrypt.compare(password, this.password);
};

const User = mongoose.model("User", userSchema);
module.exports = User;
