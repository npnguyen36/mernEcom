const asyncHandler = require('express-async-handler')
const nodemailer = require('nodemailer')

const sendMail = asyncHandler( async({email, html}) => { 
    const transporter = nodemailer.createTransport({
        host: "smtp.gmail.com",
        port: 587,
        secure: false, // true for port 465, false for other ports
        auth: {
          user: process.env.EMAIL_NAME,
          pass: process.env.EMAIL_APP_PASSWORD,
        },
      });
      
      // async..await is not allowed in global scope, must use a wrapper
      
        // send mail with defined transport object
        const info = await transporter.sendMail({
          from: '"Ecommerce" <noreply@ecommerce.com>', // sender address
          to: email, // list of receivers
          subject: "Forgot Password", // Subject line
          html: html, // html body
        });

        console.log("Message sent: %s", info.messageId);
        // Message sent: <d786aa62-4e0a-070a-47ed-0b0666549519@ethereal.email>
        return info
 })

 module.exports = sendMail