import mongoose, { Schema } from "mongoose";

const resetOtpSchema = new Schema(
  {
    userId: {
      type: Schema.Types.ObjectId,
      ref: "User",
      unique: true,
      required: true,
    },
    reset_otp: {
      type: String,
      required: true,
    },
    reset_otp_expires: {
      type: Number,
      required: true,
    },
  },
  { versionKey: false }
);

export const ResetOtp = mongoose.model("ResetOtp", resetOtpSchema);
