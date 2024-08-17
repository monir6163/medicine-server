import cookieParser from "cookie-parser";
import cors from "cors";
import express from "express";
import helmet from "helmet";
const app = express();
app.use(
  cors({
    origin:
      process.env.NODE_ENV === "production"
        ? process.env.CORS_ORIGIN
        : "http://localhost:3000",
    credentials: true,
  })
);
app.use(express.json({ limit: "16kb" }));
app.use(express.urlencoded({ extended: true, limit: "16kb" }));
app.use(express.static("public"));
app.use(cookieParser());
app.use(helmet());
app.use(helmet.contentSecurityPolicy());
app.use(helmet.referrerPolicy({ policy: "same-origin" }));
app.use(helmet.permittedCrossDomainPolicies());
app.use(helmet.hidePoweredBy());
app.use(helmet.hsts());
app.use(helmet.ieNoOpen());
app.use(helmet.noSniff());

import { generateCsrfToken } from "./utils/TokenHelper.js";
//csrf token middleware
app.use((req, res, next) => {
  if (!req.cookies.csrfToken) {
    const token = generateCsrfToken();
    res.cookie("csrfToken", token, {
      httpOnly: true,
      secure: true,
      sameSite: "None",
      maxAge: 30 * 60 * 1000, //30 minutes
    });
    req.csrfToken = token;
  } else {
    req.csrfToken = req.cookies.csrfToken;
  }
  next();
});

//route imports
import userRoutes from "./routes/user.route.js";

app.get("/", (req, res) => {
  res.send("Welcome to the API");
});
//routes declaration
app.use("/api/v1/users", userRoutes);

export { app };
