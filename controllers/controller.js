const ErrorResponse = require("../Utils/errorResponse.js");
const User = require("../models/user.js");
const jwt = require("jsonwebtoken");
const sendEmail = require('../Utils/email.js')
const mongoose = require('mongoose');
const crypto = require('crypto');

function sendTokenResponse(res, user, _statusCode) {
    const token = user.getsignJwt();

    res.cookie("jwt_cookie", token, {
        expires: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000),
    });

    res.status(200).json({
        success: true,
        token: token,
        message: `Welcome ${ user.name }`,
    });
}

module.exports.signup = async function (req, res, next) {
    try {
        const { name, password } = req.body;

        if (!name && !password) {
            return next(new ErrorResponse("Please enter a name and password"));
        }

        if (!name) {
            return next(new ErrorResponse("Please enter a name", 400));
        }

        if (!password) {
            return next(new ErrorResponse("Please enter a password", 400));
        }

        if (password && password.trim().length < 8) {
            return next(
                new ErrorResponse(
                    "Please enter a password of 8 characters and above",
                    400
                )
            );
        }

        const user = await User.create({
            name,
            password,
        });

        if (req.cookies.jwt_cookie) {
            return next(new ErrorResponse("Already logged in", 400))
        }

        sendTokenResponse(res, user, 200);
    } catch (err) {
        if (err.code == 11000) {
            return next(new ErrorResponse("That name already exists", 400));
        }
    }
};

module.exports.login = async function (req, res, next) {
    const { name, password } = req.body;

    if (!name && !password) {
        return next(new ErrorResponse("Please enter a name and password", 400));
    }

    if (!name) {
        return next(new ErrorResponse("Please enter a name", 400));
    }

    if (!password) {
        return next(new ErrorResponse("Please enter a password", 400));
    }

    const user = await User.findOne({ name: name });

    if (!user) {
        return next(new ErrorResponse("User not found", 404));
    }

    const isMatch = await user.matchPass(password);

    if (!isMatch) {
        return next(new ErrorResponse("Incorrect password", 400));
    }

    if (req.cookies.jwt_cookie) {
        return next(new ErrorResponse("Already logged in", 400))
    }

    sendTokenResponse(res, user, 200);
}

module.exports.logout = async function (req, res, next) {
    if (!req.cookies.jwt_cookie) {
        return next(new ErrorResponse("Already logged out", 400));
    }

    res.cookie("jwt_cookie", "none", {
        expires: new Date(Date.now()),
    });

    res.status(200).json({
        success: true,
        message: "Logged out",
    });
}

module.exports.forgotPass = async function (req, res, next) {
    try {
        const { name, email } = req.body;

        if (!email) {
            return next(new ErrorResponse("Please enter an email", 400));
        }

        if (!name) {
            return next(new ErrorResponse("Please enter a name", 400));
        }

        if (!email && !name) {
            return next(new ErrorResponse("Please enter a name and email", 400));
        }

        if (req.cookies.jwt) {
            return next(new ErrorResponse("Already logged in", 400));
        }

        const user = await User.findOne({ name: name }, { password: 0 });

        if (!user) {
            return next(new ErrorResponse("User not found", 404));
        }

        const resetToken = user.getResetPasswordToken();

        await user.save({ validateBeforeSave: false });
        const message = `Here is your password reset link: ${ req.protocol }://${ req.get('host') }/reset-password/${ resetToken }`

        const options = {
            email: email,
            text: message,
        }
        await sendEmail(options)

        res.status(200).json({
            success: true,
            message: 'Email sent'
        })
    } catch (err) {
        next(err)
        console.log(err);
        user.resetPasswordToken = undefined
        user.resetPasswordExpire = undefined
        await user.save({ validateBeforeSave: false })
    }
}

module.exports.deleteUser = async (req, res, next) => {
    const id = req.params.id;

    if (!id) {
        return next(new ErrorResponse("Please enter an id", 400))
    }

    if (!mongoose.isValidObjectId(id)) {
        return next(new ErrorResponse("Badly formatted id", 400))
    }

    const user = await User.findById(id);

    if (!user) {
        return next(new ErrorResponse("User not found", 404))
    }

    await User.findByIdAndDelete(id);

    res.json({
        success: true,
        message: "User deleted"
    })
}

module.exports.myProfile = async (req, res, next) => {
    const token = req.cookies.jwt_cookie;

    if (!token) {
        return next(new ErrorResponse("You are logged out", 400));
    }

    const decoded = jwt.verify(token, process.env.JWT_SECRET);

    req.user = await User.findById(decoded.id).select('-password');

    if (!req.user) {
        return next(new ErrorResponse("Invalid token", 400));
    }
    console.log(new Date(req.user.joined).toDateString());

    res.json({
        success: true,
        data: req.user,
    })
}

module.exports.allUsers = async (req, res, next) => {
    const users = await User.find().select("-password");

    if (!users) {
        return next(new ErrorResponse("Empty DB", 404));
    }

    res.status(200).json({
        success: true,
        data: users
    })
}

module.exports.resetPasword = async (req, res, next) => {
    const token = req.params.token;
    const { password } = req.body;

    if (!password) {
        return next(new ErrorResponse(`Please enter a password`, 400))
    }

    if (!token) {
        return next(new ErrorResponse(`User not found with token: ${ token }`, 404))
    }

    const hashedResetToken = crypto.createHash('sha256').update(token).digest('hex');

    const user = await User.findOne({
        resetPasswordToken: hashedResetToken,
        resetPasswordTokenExpire: { $gt: Date.now() }
    })

    if (!user) {
        return next(new ErrorResponse(`Invalid token`, 404))
    }

    user.password = password;
    user.resetPasswordToken = undefined;
    user.resetPasswordTokenExpire = undefined;

    await user.save();

    sendTokenResponse(res, user, 200)
}