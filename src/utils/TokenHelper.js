import crypto from "crypto";
import { User } from "../models/user.model.js";
import { ApiError } from "./ApiError.js";

const refreshTokenOption = {
  httpOnly: true,
  secure: true,
  maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
  sameSite: "None",
};

const accessTokenOption = {
  httpOnly: true,
  secure: true,
  maxAge: 60 * 60 * 1000, // 1 hour
  sameSite: "None",
};

const generateAccessTokenAndRefreshToken = async (userId) => {
  try {
    const user = await User.findById(userId);
    const accessToken = user.generateAccessToken();
    const refreshToken = user.generateRefreshToken();
    user.refreshToken = refreshToken;
    await user.save({ validateBeforeSave: false });
    return { accessToken, refreshToken };
  } catch (error) {
    throw new ApiError(500, "something went wrong while generating token");
  }
};

// csrf token for security purpose to prevent csrf attack in the application
const generateCsrfToken = () => {
  return crypto.randomBytes(64).toString("hex");
};

export {
  accessTokenOption,
  generateAccessTokenAndRefreshToken,
  generateCsrfToken,
  refreshTokenOption,
};
