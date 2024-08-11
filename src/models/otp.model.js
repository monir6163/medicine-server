import mongoose, { Schema } from "mongoose";

const otpSchema = new Schema(
  {
    userId: {
      type: Schema.Types.ObjectId,
      ref: "User",
      unique: true,
      required: true,
    },
    otp: {
      type: String,
      required: true,
    },
    otpExpires: {
      type: Number,
      required: true,
    },
  },
  { versionKey: false }
);

export const Otp = mongoose.model("Otp", otpSchema);
