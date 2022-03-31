const router = require("express").Router();
const {
  signup,
  login,
  logout,
  forgotPass,
  deleteUser,
  myProfile,
  allUsers,
  resetPasword
} = require('../controllers/controller.js');

router.post("/signup", signup)

router.post("/login", login);

router.get("/logout", logout);

router.post('/forgot-password', forgotPass)

router.delete('/delete/:id', deleteUser)

router.get('/my-profile', myProfile)

router.get('/all-users', allUsers)

router.post('/reset-password/:token', resetPasword)

module.exports = router;
