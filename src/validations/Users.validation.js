import z from "zod";

//register schema
export const createUserSchema = z.object({
  fullname: z
    .string()
    .trim()
    .min(2, {
      message: "Name must be atleast 2 characters",
    })
    .max(100, { message: "Invalid fullname" }),
  email: z.string().trim().email({ message: "Invalid email address" }),
  password: z
    .string()
    .trim()
    .min(6, {
      message: "Password must be atleast 6 characters",
    })
    .max(100, { message: "Invalid password" }),
});

//avatarSchema
export const avatarSchema = z.object({
  public_id: z.string().optional(),
  url: z.string().optional(),
});
