const { User } = require("../models/User");
let auth = (req, res, next) => {
  // 인증 처리를 하는 곳

  // client cookie 에서 token 을 가져온다.
  let token = req.cookie.x_auth;
  // token 을 복호화 한 후, 유저를 찾는다
  User.findByToken(token, (err, user) => {
    if (err) throw err;
    if (!user) return res.json({ isAuth: false, error: true });

    req.token = token;
    req.user = user;

    next();
  });
};

module.exports = { auth };
