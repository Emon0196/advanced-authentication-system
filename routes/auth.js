const express = require('express');
const router = express.Router();
const authController = require('../controllers/authController');
const { registerValidator } = require('../validators/authValidator');
const validateRequest = require('../middlewares/validateRequest');
const { loginValidator } = require('../validators/authValidator');
const { changePasswordValidator, forgotPasswordValidator } = require('../validators/authValidator');
const { protect } = require('../middlewares/authMiddleware');

// Registration
router.post('/register', registerValidator, validateRequest, authController.register);

// Phone verification
router.post('/verify-phone', authController.verifyPhone);

// Email verification
router.get('/verify-email', authController.verifyEmail);

//Login
router.post('/login', loginValidator, validateRequest, authController.login);

// Forgot password
router.post('/forgot-password/request', validateRequest, authController.forgotPasswordRequest);
router.post('/forgot-password/reset', forgotPasswordValidator, validateRequest, authController.forgotPasswordReset);

// Change password (after login)
router.post('/change-password', protect, changePasswordValidator, validateRequest, authController.changePassword);

//Get Profile
router.get('/profile', protect, authController.getProfile);

module.exports = router;
