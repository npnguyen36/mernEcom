const router = require('express').Router()
const ctrls = require('../controllers/user')
const {verifyAccessToken} = require('../middlewares/verifyToken')

router.post('/register', ctrls.register)
router.post('/login', ctrls.login)
router.get('/current', verifyAccessToken, ctrls.getCurrent)
router.post('/refreshtoken', ctrls.refreshAccessToken)
router.post('/logout', ctrls.logout)
router.get('/forgotpassword', ctrls.forgotPassword)
router.get('/resetpassword', ctrls.resetPassword)
module.exports = router