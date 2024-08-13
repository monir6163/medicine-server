import { Router } from "express";
import {
  changePassword,
  forgotPassword,
  getProfile,
  loginUser,
  logoutUser,
  refreshAccessToken,
  register,
  resendOtp,
  resetPassword,
  updateUserStatus,
  verifyOtp,
} from "../controllers/user.controller.js";
import { jwtVerify } from "../middlewares/auth.middleware.js";
import { upload } from "../middlewares/multer.middleware.js";
const router = Router();

router.route("/register").post(upload.single("avatar"), register);
router.route("/login").post(loginUser);
router.route("/logout").post(jwtVerify, logoutUser);
router.route("/refresh-token").post(refreshAccessToken);
router.route("/profile").get(jwtVerify, getProfile);
// user satus update
router.route("/status").post(jwtVerify, updateUserStatus);
//change password
router.route("/change-password").post(jwtVerify, changePassword);
//forgot password
router.route("/forgot-password").post(forgotPassword);
//reset password
router.route("/reset-password").post(resetPassword);
// otp verification
router.route("/verify-otp").post(verifyOtp);
//resend otp
router.route("/resend-otp").post(resendOtp);

export default router;
