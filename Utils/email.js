const nodemailer = require("nodemailer");

async function sendEmail(options) {
  let transporter = nodemailer.createTransport({
    host: process.env.SMTP_HOST,
    port: process.env.SMTP_PORT,
    secure: false,
    auth: {
      user: process.env.USER,
      pass: process.env.PASS,
    },
  });

  let info = await transporter.sendMail({
    from: '"Test" <test@example.com>',
    to: options.email,
    subject: "Password reset link ✔",
    text: options.text,
  });

  console.log("Message sent: %s", info.messageId);
}

module.exports = sendEmail
