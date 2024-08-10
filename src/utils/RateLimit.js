import rateLimit from "express-rate-limit";

const limiter = rateLimit({
  windowMs: 1000,
  limit: 10,
  standardHeaders: "draft-7",
  legacyHeaders: false,
  message: {
    status: 429,
    message: "To many request from this ip, please try again later",
  },
});

export { limiter };
