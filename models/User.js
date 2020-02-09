const mongoose = require("mongoose");
const bcrypt = require("bcrypt");
const saltRounds = 10;
const jwt = require("jsonwebtoken");

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

userSchema.methods.comparePassword = function(plainPassword, cb) {
  // ex) plainPassword: 1234, 암호화된 비밀번호: $2b$10$hys1vfMrAl6dFKs6oPkV5uIIpy1nwXiTGJg/OCdFVA9Aw5AaLHYV.
  bcrypt.compare(plainPassword, this.password, function(err, isMatch) {
    if (err) return cb(err);
    cb(null, isMatch);
  });
};

userSchema.methods.generateToken = function(cb) {
  var user = this;
  // jsonWebToken 을 이용해서 token 을 사용하기

  var token = jwt.sign(user._id.toHexString(), "secretToken");
  // user._id + 'secretToken' = token;
  // ->
  // "secretToken" -> user._id

  user.token = token;
  user.save(function(err, user) {
    if (err) return cb(err);
    cb(null, user);
  });
};

userSchema.statics.findByToken = function(token, cb) {
  var user = this;

  // user._id + '' = token;
  // token 을 decode 한다.
  jwt.verify(token, "sercetToken", function(err, dcoded) {
    // 유저 아이디를 이용해서 유저를 찾은 다음에
    // 클라이언트에서 가져온 token 과 DB 에 보관된 토큰이 일치하는지 확인

    user.findOne({ _id: dcoded, token: token }, function(err, user) {
      if (err) return cb(err);
      cb(null, user);
    });
  });
};

const User = mongoose.model("User", userSchema);

module.exports = { User };
