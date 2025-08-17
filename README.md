# Advanced Authentication System (Express + MongoDB)

A secure and scalable authentication system built using **Express.js**, **MongoDB (Mongoose)**, and **JWT**.  
It supports **user registration**, **login**, **phone & email verification (via OTP + email link)**, and **forgot/change password flows**.

---

## 🚀 Features

- User Registration with phone & email uniqueness checks
- Phone verification via OTP
- Email verification via secure JWT link
- Secure login with JWT authentication
- Forgot Password (OTP/Token flow)
- Change Password (from forgot password)
- Profile API to get logged-in user details
- Centralized error handling
- Modular & clean project structure
- Environment-based configuration

---

## 🛠️ Tech Stack

- **Backend Framework:** Express.js  
- **Database:** MongoDB with Mongoose ODM  
- **Authentication:** JWT (JSON Web Token)  
- **OTP & Expiry:** Generated & stored with expiry validation  
- **Utilities:**  
  - `dayjs` → Date/time handling  
  - `bcryptjs` → Password hashing  
  - `nodemailer` → Email sending  
  - `jsonwebtoken` → Token generation & verification  

---

## ⚙️ Setup & Installation

### 1. Clone the Repository
```bash
git clone https://github.com/Emon0196/advanced-authentication-system.git
cd advanced-auth-system
npm install
