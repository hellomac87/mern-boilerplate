const mongoose = require("mongoose");
const bcrypt = require("bcrypt");
const saltRounds = 10;
const someOtherPlaintextPassword = "not_bacon";

const userSchema = mongoose.Schema({
  name: {
    type: String,
    maxlength: 50
  },
  email: {
    type: String,
    trim: true, // 빈칸을 없애주는 역할
    unique: 1
  },
  password: {
    type: String,
    minlength: 3
  },
  lastname: {
    type: String,
    maxlength: 50
  },
  role: {
    type: Number,
    default: 0
  },
  image: String,
  token: {
    type: String
  },
  tokenExp: {
    type: Number
  }
});

// 유저 정보를 저장하기 전에
userSchema.pre("save", function(next) {
  var user = this; // <-- 유저스키마를 가르킴

  // 패스워드가 변환될떄만
  if (user.isModified("password")) {
    // 비밀번호를 암호화시긴다.
    bcrypt.genSalt(saltRounds, function(err, salt) {
      if (err) return next(err);

      bcrypt.hash(user.password, salt, function(err, hash) {
        if (err) return next(err);
        user.password = hash;
        next();
      });
    });
  } else {
    next();
  }
});

const User = mongoose.model("User", userSchema);

module.exports = { User };
