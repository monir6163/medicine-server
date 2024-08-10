import jwt from "jsonwebtoken";
import { User } from "../models/user.model.js";
import { ApiError } from "../utils/ApiError.js";
import { ApiResponse } from "../utils/ApiResponse.js";
import { asyncHandler } from "../utils/asyncHandler.js";
import { cloudinaryUpload } from "../utils/cloudinary.js";
import { sendMail } from "../utils/NodeMailer.Config.js";
import {
  avatarSchema,
  createUserSchema,
} from "../validations/Users.validation.js";

// generateAccessToken and generateRefreshToken
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

  //email verification
  const otp = Math.floor(100000 + Math.random() * 900000);
  //send email

  await sendMail(
    validedUser.email,
    "Email Verification",
    `Your OTP is ${otp}`,
    `<h1>Your OTP is ${otp}</h1>`
  );

  const user = await User.create({
    ...validedUser,
    avatar: validedAvatar,
  });
  const createdUser = await User.findById(user._id).select(
    "-password -refreshToken"
  );
  if (!createdUser) {
    throw new ApiError(500, "Server Error user register");
  }
  return res
    .status(201)
    .json(new ApiResponse(200, createdUser, "User Create Success"));
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

    const { accessToken, refreshToken } =
      await generateAccessTokenAndRefreshToken(user._id);

    const loggedInUser = await User.findById(user._id).select(
      "-password -refreshToken"
    );

    const options = {
      httpOnly: true,
      secure: true,
    };

    return res
      .status(200)
      .cookie("accessToken", accessToken, options)
      .cookie("refreshToken", refreshToken, options)
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

const refreshAccessToken = asyncHandler(async (req, res) => {
  try {
    const incomingRefreshToken =
      req.cookies?.refreshToken || req.body?.refreshToken;
    if (!incomingRefreshToken) {
      throw new ApiError(401, "Unauthorized");
    }

    const decodedToken = jwt.verify(
      incomingRefreshToken,
      process.env.REFRESH_TOKEN_SECRET
    );

    const user = await User.findById(decodedToken?._id);
    if (!user) {
      throw new ApiError(401, "Invalid refresh token");
    }

    if (user?.refreshToken !== incomingRefreshToken) {
      throw new ApiError(401, "Refresh token revoked");
    }

    const { accessToken, newRefreshToken } =
      await generateAccessTokenAndRefreshToken(user._id);

    const options = {
      httpOnly: true,
      secure: true,
    };

    return res
      .status(200)
      .cookie("accessToken", accessToken, options)
      .cookie("refreshToken", newRefreshToken, options)
      .json(
        new ApiResponse(
          200,
          { accessToken, refreshToken: newRefreshToken },
          "Access Token Refresh"
        )
      );
  } catch (error) {
    throw new ApiError(500, error?.message);
  }
});
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

const changePassword = asyncHandler(async (req, res) => {
  try {
    const { oldPassword, newPassword } = req.body;
    const user = await User.findById(req?.user?._id);
    if (!oldPassword || !newPassword) {
      throw new ApiError(400, "Old and new password is required");
    }

    return res
      .status(200)
      .json(new ApiResponse(200, {}, "Password Changed Successfully"));
  } catch (error) {
    throw new ApiError(500, error?.message);
  }
});

const forgotPassword = asyncHandler(async (req, res) => {
  try {
    const { email } = req.body;
    if (!email) {
      throw new ApiError(400, "Email is required");
    }

    return res
      .status(200)
      .json(new ApiResponse(200, {}, "Password reset link sent to email"));
  } catch (error) {
    throw new ApiError(500, error?.message);
  }
});

export {
  changePassword,
  forgotPassword,
  loginUser,
  logoutUser,
  refreshAccessToken,
  register,
};
