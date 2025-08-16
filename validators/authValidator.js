// validators/authValidator.js
const { body } = require('express-validator');

// Password regex: min 12 chars, at least 1 uppercase, 1 lowercase, 1 number, 1 symbol
const passwordRegex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[\W_]).{12,}$/;

const registerValidator = [
  body('fullName')
    .notEmpty()
    .withMessage('Full name is required')
    .isLength({ min: 2 })
    .withMessage('Full name must be at least 2 characters'),
  body('email')
    .isEmail()
    .withMessage('Valid email is required'),
  body('phone')
    .notEmpty()
    .withMessage('Phone number is required'),
  body('password')
    .matches(passwordRegex)
    .withMessage('Password must be at least 12 characters long and include uppercase, lowercase, number, and symbol'),
];

const loginValidator = [
  body('phone')
    .notEmpty()
    .withMessage('Phone number is required'),
  body('password')
    .notEmpty()
    .withMessage('Password is required'),
];

const changePasswordValidator = [
  body('oldPassword')
    .notEmpty()
    .withMessage('Existing password is required'),
  body('newPassword')
    .matches(passwordRegex)
    .withMessage('New password must be at least 12 characters long and include uppercase, lowercase, number, and symbol'),
];

const forgotPasswordValidator = [
  body('phone')
    .notEmpty()
    .withMessage('Phone number is required'),
  body('newPassword')
    .matches(passwordRegex)
    .withMessage('New password must be at least 12 characters long and include uppercase, lowercase, number, and symbol'),
];

module.exports = {
  registerValidator,
  loginValidator,
  changePasswordValidator,
  forgotPasswordValidator,
};
