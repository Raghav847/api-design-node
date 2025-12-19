import { Router } from "express";
import { validateBody } from "../middleware/validation.ts";
import { insertUserSchema } from "../db/schema.ts";
import { login, register } from "../controllers/authController.ts";
import {z} from 'zod'

const loginSchema = z.object({
    email: z.email('Invalid Email'),
    password: z.string().min(1, 'Password Required')
})

const router = Router()

router.post("/register", validateBody(insertUserSchema), register) 

router.post("/login", validateBody(loginSchema), login)

export default router 