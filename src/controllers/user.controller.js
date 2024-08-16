import crypto from "crypto";
import jwt from "jsonwebtoken";
import { Otp } from "../models/otp.model.js";
import { ResetOtp } from "../models/resetOtp.model.js";
import { User } from "../models/user.model.js";
import { ApiError } from "../utils/ApiError.js";
import { ApiResponse } from "../utils/ApiResponse.js";
import { asyncHandler } from "../utils/asyncHandler.js";
import { cloudinaryUpload } from "../utils/cloudinary.js";
import { sendMail } from "../utils/NodeMailer.Config.js";
import {
  accessTokenOption,
  generateAccessTokenAndRefreshToken,
  refreshTokenOption,
} from "../utils/TokenHelper.js";
import {
  avatarSchema,
  createUserSchema,
} from "../validations/Users.validation.js";

// generateAccessToken and generateRefreshToken

//register user
const register = asyncHandler(async (req, res) => {
  const validedUser = createUserSchema.parse(req.body);
  const existUser = await User.findOne({
    $or: [{ email: validedUser.email }],
  });
  if (existUser) {
    throw new ApiError(409, "User Already Exist by email");
  }

  const avatarLoacalPath = req.file?.path;
  const avatar = await cloudinaryUpload(avatarLoacalPath, "ecom/user");
  const validedAvatar = avatarSchema.parse(avatar);

  const user = await User.create({
    ...validedUser,
    avatar: validedAvatar,
  });
  // Generate OTP
  const otp = crypto.randomInt(100000, 999999).toString(); // 6-digit OTP
  const otpExpires = Date.now() + 5 * 60 * 1000; // Expires in 5 minutes

  await Otp.create({
    userId: user._id,
    otp,
    otpExpires,
  });

  // Send OTP email
  await sendMail(
    user.email,
    "Your Verification Code",
    `Your verification code is ${otp}. It expires in 5 minutes.`
  );
  const createdUser = await User.findById(user._id).select(
    "-password -refreshToken"
  );
  if (!createdUser) {
    throw new ApiError(500, "Server Error user register");
  }
  return res
    .status(201)
    .json(
      new ApiResponse(
        200,
        createdUser,
        "OTP sent to your email for verification"
      )
    );
});

//otp verification
const verifyOtp = asyncHandler(async (req, res) => {
  const { userId, otp } = req.body;

  const findOtp = await Otp.findOne({
    userId,
    otp,
    otpExpires: { $gt: Date.now() }, // Check if OTP is still valid
  });

  if (!findOtp) {
    throw new ApiError(400, "Invalid or expired OTP");
  }

  await User.findByIdAndUpdate(userId, { email_verified: true });
  await Otp.deleteOne({ userId, otp }); // Delete the token after verification

  // Send email notification of email verification
  await sendMail(
    findOtp.email,
    "Email Verification Successful",
    "Your email has been successfully verified."
  );

  return res
    .status(200)
    .json(new ApiResponse(200, null, "Email successfully verified"));
});

//resend otp verification
const resendOtp = asyncHandler(async (req, res) => {
  const { userId } = req.body;

  const user = await User.findById(userId);
  if (!user) {
    throw new ApiError(404, "User not found");
  }

  if (user.email_verified) {
    throw new ApiError(400, "Email already verified");
  }

  const otp = crypto.randomInt(100000, 999999).toString(); // Generate a new OTP
  const otpExpires = Date.now() + 5 * 60 * 1000; // Expires in 5 minutes

  await Otp.updateOne(
    { userId },
    { otp, otpExpires },
    { upsert: true } // Update if exists, insert if not
  );

  await sendMail(
    user.email,
    "Your New Verification Code",
    `Your new verification code is ${otp}. It expires in 5 minutes.`
  );

  return res
    .status(200)
    .json(new ApiResponse(200, null, "New OTP sent to your email"));
});

//login user
const loginUser = asyncHandler(async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email?.trim()) {
      throw new ApiError(400, "Email is required");
    }

    const user = await User.findOne({ $or: [{ email }] });
    if (!user) {
      throw new ApiError(404, "User not found");
    }

    const isPasswordValid = await user.isPasswordCorrect(password);
    if (!isPasswordValid) {
      throw new ApiError(401, "Invalid credentials");
    }

    if (!user.email_verified) {
      throw new ApiError(401, "Email not verified");
    }

    const { accessToken, refreshToken } =
      await generateAccessTokenAndRefreshToken(user._id);

    const loggedInUser = await User.findById(user._id).select(
      "-password -refreshToken"
    );

    return res
      .status(200)
      .cookie("accessToken", accessToken, accessTokenOption)
      .cookie("refreshToken", refreshToken, refreshTokenOption)
      .json(
        new ApiResponse(
          200,
          { user: loggedInUser, accessToken, refreshToken },
          "Login Success"
        )
      );
  } catch (error) {
    throw new ApiError(500, error?.message);
  }
});

//refresh token
const refreshAccessToken = asyncHandler(async (req, res) => {
  try {
    const incomingRefreshToken =
      req.cookies?.refreshToken || req.body?.refreshToken;
    if (!incomingRefreshToken) {
      return res.status(401).json({ message: "Unauthorized controller" });
    }

    const decodedToken = jwt.verify(
      incomingRefreshToken,
      process.env.REFRESH_TOKEN_SECRET
    );

    const user = await User.findById(decodedToken?._id).select("-password");
    if (!user) {
      return res
        .status(401)
        .json({ message: "Invalid refresh token", status: 401 });
    }

    if (user?.refreshToken !== incomingRefreshToken) {
      return res
        .status(401)
        .json({ message: "Refresh token revoked", status: 401 });
    }

    const { accessToken, refreshToken: newRefreshToken } =
      await generateAccessTokenAndRefreshToken(user._id);

    return res
      .status(200)
      .cookie("accessToken", accessToken, accessTokenOption)
      .cookie("refreshToken", newRefreshToken, refreshTokenOption)
      .json(
        new ApiResponse(
          200,
          { accessToken, refreshToken: newRefreshToken },
          "Access Token Refresh"
        )
      );
  } catch (error) {
    return res.status(500).json({ message: error?.message });
  }
});

//logout user
const logoutUser = asyncHandler(async (req, res) => {
  try {
    const id = req?.user?._id;
    await User.findByIdAndUpdate(
      id,
      {
        $set: { refreshToken: undefined },
      },
      {
        new: true,
        select: "-password -refreshToken",
      }
    );
    const options = {
      httpOnly: true,
      secure: true,
    };

    return res
      .status(200)
      .clearCookie("accessToken", options)
      .clearCookie("refreshToken", options)
      .json(new ApiResponse(200, {}, "Logout Success"));
  } catch (error) {
    throw new ApiError(500, error?.message);
  }
});

//change password
const changePassword = asyncHandler(async (req, res) => {
  try {
    const { oldPassword, newPassword } = req.body;
    const user = await User.findById(req?.user?._id);
    if (!oldPassword || !newPassword) {
      throw new ApiError(400, "Old and new password is required");
    }

    const isPasswordValid = await user.isPasswordCorrect(oldPassword);
    if (!isPasswordValid) {
      throw new ApiError(401, "Invalid old password");
    }

    user.password = newPassword;

    await user.save();

    return res
      .status(200)
      .json(new ApiResponse(200, {}, "Password Changed Successfully"));
  } catch (error) {
    throw new ApiError(500, error?.message);
  }
});

//forgot password
const forgotPassword = asyncHandler(async (req, res) => {
  try {
    const { email } = req.body;
    if (!email) {
      throw new ApiError(400, "Email is required");
    }

    const user = await User.findOne({ email });
    if (!user) {
      throw new ApiError(404, "User not found");
    }

    // Generate OTP
    const otp = crypto.randomInt(100000, 999999).toString(); // 6-digit OTP
    const otpExpires = Date.now() + 5 * 60 * 1000; // Expires in 5 minutes

    // Save OTP to the database
    await ResetOtp.create({
      userId: user._id,
      reset_otp: otp,
      reset_otp_expires: otpExpires,
    });

    // Send OTP email
    await sendMail(
      user.email,
      "Password Reset Code",
      `Your password reset code is ${otp}. It expires in 5 minutes.`
    );

    return res
      .status(200)
      .json(new ApiResponse(200, {}, "Password reset code sent to your email"));
  } catch (error) {
    throw new ApiError(500, error?.message);
  }
});

//reset otp verification
const resetPassword = asyncHandler(async (req, res) => {
  try {
    const { userId, otp, password } = req.body;

    const resetOtp = await ResetOtp.findOne({
      userId,
      reset_otp: otp,
      reset_otp_expires: { $gt: Date.now() }, // Check if OTP is still valid
    });

    if (!resetOtp) {
      throw new ApiError(400, "Invalid or expired OTP");
    }

    const user = await User.findById(userId);
    user.password = password;
    await user.save();

    await ResetOtp.deleteOne({ userId, reset_otp: otp }); // Delete the token after verification

    // Send email notification of password change
    await sendMail(
      user.email,
      "Password Reset Successful",
      "Your password has been successfully reset."
    );

    return res
      .status(200)
      .json(new ApiResponse(200, {}, "Password reset successful"));
  } catch (error) {
    throw new ApiError(500, error?.message);
  }
});

//get user profile
const getProfile = asyncHandler(async (req, res) => {
  // console.log(req?.user);
  const user = await User.findById(req?.user?._id).select(
    "-password -refreshToken"
  );
  if (!user) {
    throw new ApiError(404, "User not found");
  }

  if (!user.is_active) {
    throw new ApiError(401, "User account is deactivated");
  }
  if (!user.email_verified) {
    throw new ApiError(401, "Email not verified");
  }

  return res.status(200).json(new ApiResponse(200, user, "User Profile"));
});

// user status update
const updateUserStatus = asyncHandler(async (req, res) => {
  const { userId, status } = req.body;
  const user = await User.findById(userId);
  if (!user) {
    throw new ApiError(404, "User not found");
  }

  user.is_active = status;
  await user.save();

  return res
    .status(200)
    .json(new ApiResponse(200, {}, "User status updated successfully"));
});

//user profile data update
const updateUserProfile = asyncHandler(async (req, res) => {
  const { userId } = req.body;
});

export {
  changePassword,
  forgotPassword,
  getProfile,
  loginUser,
  logoutUser,
  refreshAccessToken,
  register,
  resendOtp,
  resetPassword,
  updateUserProfile,
  updateUserStatus,
  verifyOtp,
};
