// controllers/authController.js
const User = require('../models/User');
const OTP = require('../models/OTP');
const generateOTP = require('../utils/generateOTP');
const sendSms = require('../utils/sendSms');
const sendEmail = require('../utils/sendEmail');
const jwt = require('jsonwebtoken');
const dayjs = require('dayjs');

// ---------------------- Registration ----------------------
const register = async (req, res) => {
  const { fullName, email, phone, password } = req.body;

  try {
    // Check if phone is taken by another verified user
    const phoneTaken = await User.findOne({
      phone,
      phoneVerified: true,
    });
    if (phoneTaken) {
      return res.status(400).json({ message: 'Phone number already verified by another user' });
    }

    // Check if email is taken by another verified user
    const emailTaken = await User.findOne({
      email,
      emailVerified: true,
    });
    if (emailTaken) {
      return res.status(400).json({ message: 'Email already verified by another user' });
    }

    // Create new user
    const newUser = await User.create({ fullName, email, phone, password });

    // Generate phone verification OTP (expires in 5 minutes)
    const otpCode = generateOTP();
    const otpExpiry = dayjs().add(5, 'minute').toDate();

    await OTP.create({
      userId: newUser._id,
      otp: otpCode,
      type: 'phoneVerification',
      expiresAt: otpExpiry,
    });

    // Send fake SMS
    sendSms(phone, `Your OTP code is: ${otpCode}`);

    // Generate email verification token (JWT, 24h expiry)
    const emailToken = jwt.sign(
      { id: newUser._id, email: newUser.email },
      process.env.JWT_SECRET,
      { expiresIn: '24h' }
    );

    const verificationUrl = `http://localhost:5000/api/auth/verify-email?token=${emailToken}`;
    sendEmail(email, `Click here to verify your email: ${verificationUrl}`);

    res.status(201).json({
      message: 'User registered successfully. Verify your phone and email.',
      userId: newUser._id,
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Server error' });
  }
};

// ---------------------- Phone Verification ----------------------
const verifyPhone = async (req, res) => {
  const { userId, otp } = req.body;

  try {
    const record = await OTP.findOne({
      userId,
      otp,
      type: 'phoneVerification',
    });

    if (!record) {
      return res.status(400).json({ message: 'Invalid OTP' });
    }

    if (dayjs().isAfter(dayjs(record.expiresAt))) {
      return res.status(400).json({ message: 'OTP expired' });
    }

    // Mark phone as verified
    await User.findByIdAndUpdate(userId, { phoneVerified: true });

    // Delete OTP after successful verification
    await OTP.findByIdAndDelete(record._id);

    res.status(200).json({ message: 'Phone verified successfully' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Server error' });
  }
};

// ---------------------- Email Verification ----------------------
const verifyEmail = async (req, res) => {
  const { token } = req.query;

  if (!token) {
    return res.status(400).json({ message: 'Missing token' });
  }

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    const user = await User.findById(decoded.id);

    if (!user) {
      return res.status(400).json({ message: 'User not found' });
    }

    // Mark email as verified
    if (!user.emailVerified) {
      user.emailVerified = true;
      await user.save();
    }

    res.status(200).json({ message: 'Email verified successfully' });
  } catch (err) {
    console.error(err);
    res.status(400).json({ message: 'Invalid or expired token' });
  }
};

// controllers/authController.js (add below previous exports)
const login = async (req, res) => {
  const { phone, password } = req.body;

  try {
    const user = await User.findOne({ phone });

    if (!user) {
      return res.status(400).json({ message: 'Invalid phone or password' });
    }

    // Check password
    const isMatch = await user.matchPassword(password);
    if (!isMatch) {
      return res.status(400).json({ message: 'Invalid phone or password' });
    }

    // Check phone verification
    if (!user.phoneVerified) {
      return res.status(403).json({ message: 'Phone number not verified. Cannot login.' });
    }

    // At this point, user can login regardless of email verification
    // Generate JWT token (e.g., 24h expiry)
    const token = jwt.sign(
      { id: user._id },
      process.env.JWT_SECRET,
      { expiresIn: '24h' }
    );

    res.status(200).json({
      message: 'Login successful',
      token,
      user: {
        id: user._id,
        fullName: user.fullName,
        email: user.email,
        phone: user.phone,
        emailVerified: user.emailVerified,
        phoneVerified: user.phoneVerified,
      },
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Server error' });
  }
};

// controllers/authController.js
const forgotPasswordRequest = async (req, res) => {
  const { phone } = req.body;

  try {
    const user = await User.findOne({ phone });

    if (!user) {
      return res.status(400).json({ message: 'User with this phone not found' });
    }

    // Generate OTP (expires in 5 minutes)
    const otpCode = generateOTP();
    const otpExpiry = dayjs().add(5, 'minute').toDate();

    await OTP.create({
      userId: user._id,
      otp: otpCode,
      type: 'forgotPassword',
      expiresAt: otpExpiry,
    });

    sendSms(phone, `Your password reset OTP is: ${otpCode}`);

    res.status(200).json({ message: 'OTP sent successfully' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Server error' });
  }
};

const forgotPasswordReset = async (req, res) => {
  const { phone, otp, newPassword } = req.body;

  try {
    const user = await User.findOne({ phone });
    if (!user) {
      return res.status(400).json({ message: 'User not found' });
    }

    const record = await OTP.findOne({
      userId: user._id,
      otp,
      type: 'forgotPassword',
    });

    if (!record) {
      return res.status(400).json({ message: 'Invalid OTP' });
    }

    if (dayjs().isAfter(dayjs(record.expiresAt))) {
      return res.status(400).json({ message: 'OTP expired' });
    }

    // Update password (pre-save hook will hash it)
    user.password = newPassword;
    await user.save();

    // Delete OTP after use
    await OTP.findByIdAndDelete(record._id);

    res.status(200).json({ message: 'Password reset successfully' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Server error' });
  }
};

const changePassword = async (req, res) => {
  const { oldPassword, newPassword } = req.body;
  const user = req.user; // from authMiddleware

  try {
    // Validate old password
    const isMatch = await user.matchPassword(oldPassword);
    if (!isMatch) {
      return res.status(400).json({ message: 'Existing password is incorrect' });
    }

    // Update password (pre-save hook will hash it)
    user.password = newPassword;
    await user.save();

    res.status(200).json({ message: 'Password changed successfully' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Server error' });
  }
};

// controllers/authController.js
const getProfile = async (req, res) => {
  try {
    const user = req.user; // from authMiddleware

    res.status(200).json({
      id: user._id,
      fullName: user.fullName,
      email: user.email,
      phone: user.phone,
      emailVerified: user.emailVerified,
      phoneVerified: user.phoneVerified,
      createdAt: user.createdAt,
      updatedAt: user.updatedAt,
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Server error' });
  }
};

module.exports = {
  register,
  verifyPhone,
  verifyEmail,
  login,
  forgotPasswordRequest,
  forgotPasswordReset,
  changePassword,
  getProfile
};
