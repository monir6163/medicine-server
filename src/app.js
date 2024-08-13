import cookieParser from "cookie-parser";
import cors from "cors";
import express from "express";
import helmet from "helmet";
const app = express();
app.use(
  cors({
    origin: process.env.CORS_ORIGIN,
    credentials: true,
  })
);
app.use(express.json({ limit: "16kb" }));
app.use(express.urlencoded({ extended: true, limit: "16kb" }));
app.use(express.static("public"));
app.use(cookieParser());
app.use(helmet());

//route imports
import userRoutes from "./routes/user.route.js";

app.get("/", (req, res) => {
  res.send("Welcome to the API");
});
//routes declaration
app.use("/api/v1/users", userRoutes);

export { app };
