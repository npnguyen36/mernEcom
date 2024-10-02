const User = require('../models/user')
const asyncHandler = require('express-async-handler')
const {generateAccessToken, generateRefreshToken} = require('../middlewares/jwt')
const jwt = require('jsonwebtoken')
const sendMail = require('../ultils/sendMail')
const crypto = require('crypto')

// User Register controler
const register = asyncHandler(async(req, res) => {
    const {email, password, firstname, lastname} = req.body
    if(!email || !password || !firstname || !lastname)
    return res.status(400).json({
        sucess: false,
        mes: 'Missing inputs'
    })

    const user = await User.findOne({ email })
    if(user) throw new Error('User existed')
    else {
        const newUser = await User.create(req.body)
        return res.status(200).json({
            sucess: newUser ? true: false,
            mes: newUser ? 'Register is sucessfully. Please go login' : 'Something wrong'
        })
    }
})

// User Login Controller
const login = asyncHandler(async(req, res) => {
    const {email, password} = req.body
    if(!email || !password)
    return res.status(400).json({
        sucess: false,
        mes: 'Missing inputs'
    })

    const response = await User.findOne({ email })
    if(response && await response.isCorrectPassword(password)){
        const { password, role, ...userData} = response.toObject()
        const accessToken = generateAccessToken(response._id, role)
        const refreshToken = generateRefreshToken(response._id)
        await User.findByIdAndUpdate(response._id, {refreshToken}, {new: true})
        res.cookie('refreshToken', refreshToken, {httpOnly: true, maxAge: 7*24*60*60*1000 })
        return res.status(200).json({
            sucess: true,
            accessToken,
            userData
        })
    } else {
        throw new Error('Invalid credential')
    }
})

//get user
const getCurrent = asyncHandler(async(req, res) => {
    const { _id} = req.user
    const user = await User.findById(_id).select('-refreshToken -password -role')
    
    return res.status(200).json({
        sucess: user ? true : false,
        rs: user ? user : 'User not found'
    })
})

//refresh access token
const refreshAccessToken = asyncHandler(async(req, res) => {
    const cookie = req.cookies

    if(!cookie && !cookie.refreshToken) throw new Error('No refresh token in cookies')
    
    const rs = await jwt.verify(cookie.refreshToken, process.env.JWT_SECRET)
    console.log(rs);
    
    const response = await User.findOne({_id: rs._id, refreshToken: cookie.refreshToken})
    console.log(response);
    
    return res.status(200).json({
        sucess: response ? true : false,
        newAccessToken: response ? generateAccessToken(response._id, response.role) : 'Refresh token not matched'
    })

})

const logout = asyncHandler(async (req, res) => { 
    const cookie = req.cookies
    if(!cookie & !cookie.refreshToken) throw new Error('No refresh token in cookies')
    await User.findOneAndUpdate({refreshToken: cookie.refreshToken}, {refreshToken: ''},  {new: true})
    res.clearCookie('refreshToken', {
        httpOnly: true,
        secure: true
    })
    return res.status(200).json({
        sucess: true,
        mes: 'Logout is done'
    })
 })

 const forgotPassword = asyncHandler(async (req, res) => {
    const {email} = req.query
    if (!email) throw new Error('Missing email')
    const user = await User.findOne({email})
    if (!user) throw new Error('User not found')
    const resetToken = user.createPasswordTokenChange()
    await user.save()
    
    const html = `Please click the link below to change your password. The link will expire in 15 minutes <a href=${process.env.URL_SERVER}/api/user/reset-password/${resetToken}>Click here</a>`

    const data = {
        email,
        html
    }

    const rs = await sendMail(data)

    return res.status(200).json({
        success: true,
        rs
    })
 })

 const resetPassword = asyncHandler(async (req, res) => { 
    const {password, token} = req.body
    const passwordResetToken = crypto.createHash('sha256').update(token).digest('hex')
    const user = await User.findOne({passwordResetToken, passwordResetExpires: {$gt: Date.now()}})
    if(!user) throw new Error('Invalid reset Token')
    user.password = password
    user.passwordResetToken = undefined
    user.passwordChangeAt = Date.now()
    user.passwordResetExpires = undefined
    await user.save()
    return res.status(200).json({
        sucess: user? true: false,
        mes: user? 'Update password' : 'Can not update password'
    })
  })

module.exports = {
    register,
    login,
    getCurrent,
    refreshAccessToken,
    logout,
    forgotPassword,
    resetPassword
}