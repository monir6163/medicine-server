import { v2 as cloudinary } from "cloudinary";
import fs from "fs";

cloudinary.config({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
  api_key: process.env.CLOUDINARY_API_KEY,
  api_secret: process.env.CLOUDINARY_API_SECRET,
});

const cloudinaryUpload = async (localFilePath, folderName) => {
  try {
    if (!localFilePath) return null;
    const result = await cloudinary.uploader.upload(localFilePath, {
      folder: folderName,
      resource_type: "auto",
    });
    fs.unlinkSync(localFilePath);
    return {
      public_id: result.public_id,
      url: result.secure_url,
    };
  } catch (error) {
    fs.unlinkSync(localFilePath);
    return null;
  }
};
const deleteOnCloudinary = (publicId) => {
  return cloudinary.uploader.destroy(publicId);
};
export { cloudinaryUpload, deleteOnCloudinary };
