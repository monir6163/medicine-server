import { asyncHandler } from "../utils/asyncHandler.js";

export const csrfProtection = asyncHandler(async (req, res, next) => {
  const csrfTokenFromHeader = req.cookies.csrfToken; // Or from request body
  const csrfTokenFromServer = req.cookies.csrfToken; // Or from session

  if (!csrfTokenFromHeader || csrfTokenFromHeader !== csrfTokenFromServer) {
    return res.status(403).json({ message: "Invalid CSRF token" });
  }

  next();
});
