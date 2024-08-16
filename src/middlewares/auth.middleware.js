import jwt from "jsonwebtoken";
import { User } from "../models/user.model.js";
import { asyncHandler } from "../utils/asyncHandler.js";

export const jwtVerify = asyncHandler(async (req, res, next) => {
  try {
    const token =
      req.cookies?.accessToken ||
      req.headers?.authorization?.split(" ")[1] ||
      req.body?.refreshToken;
    if (!token) {
      return res
        .status(401)
        .json({ message: "Unauthorized Token", status: 401 });
    }

    const decodedToken = jwt.verify(token, process.env.ACCESS_TOKEN_SECRET);

    const user = await User.findById(decodedToken?._id).select(
      "-password -refreshToken"
    );
    if (!user) {
      return res.status(401).json({ message: "Invalid Token" });
    }

    req.user = user;
    next();
  } catch (error) {
    return res.status(500).json({ message: "catch error" });
  }
});
