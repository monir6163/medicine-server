import { Router } from "express";
import {
  loginUser,
  logoutUser,
  refreshAccessToken,
  register,
  resendOtp,
  verifyOtp,
} from "../controllers/user.controller.js";
import { jwtVerify } from "../middlewares/auth.middleware.js";
import { upload } from "../middlewares/multer.middleware.js";
const router = Router();

router.route("/register").post(upload.single("avatar"), register);
router.route("/login").post(loginUser);
router.route("/logout").post(jwtVerify, logoutUser);
router.route("/refresh-token").post(refreshAccessToken);

// otp verification
router.route("/verify-otp").post(verifyOtp);
//resend otp
router.route("/resend-otp").post(resendOtp);

export default router;
