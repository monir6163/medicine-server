import mongoose, { Schema } from "mongoose";

const tokenSchema = new Schema(
  {
    userId: {
      type: Schema.Types.ObjectId,
      ref: "User",
      unique: true,
      required: true,
    },
    verify_token: {
      type: String,
      required: true,
    },

    createdAt: {
      type: Date,
      default: Date.now,
      expires: 3600,
    },
  },
  { versionKey: false }
);

export const Token = mongoose.model("Token", tokenSchema);
