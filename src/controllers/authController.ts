import type { Request, Response } from "express";
import { db } from '../db/connection.ts'
import { users, type NewUser } from "../db/schema.ts";
import { generateToken } from "../utils/jwt.ts";
import { comparePasswords, hashPassword } from "../utils/passwords.ts";
import { eq } from "drizzle-orm";


export const register = async (
    req: Request <any, any, NewUser>, 
    res: Response
) => {
    try {
        const hashedPassword = await hashPassword(req.body.password)

        const [user] = await db
            .insert(users)
            .values({
                ...req.body,
                password: hashedPassword,
            })
            .returning({
                id: users.id,
                email: users.email,
                username: users.username,
                firstName: users.firstName,
                lastName: users.lastName,
                createdAt: users.createdAt,
            })
        
        const token = await generateToken({
            id: user.id,
            email: user.email,
            username: user.username,
        })

        return res.status(201).json({
            message: 'User Created',
            user,
            token,
        })
    } catch (e: any) {
        console.error(`Registration error`, e)
        
        // Handle database constraint violations (unique email/username)
        if (e?.code === '23505') {
            const field = e?.detail?.includes('email') ? 'email' : 'username'
            return res.status(409).json({ 
                error: `User with this ${field} already exists` 
            })
        }
        
        // Handle other database errors
        if (e?.code) {
            return res.status(500).json({ 
                error: 'Database error',
                details: e.message 
            })
        }
        
        // Handle validation or other errors
        res.status(500).json({ 
            error: 'Failed to create user',
            details: e?.message || 'Unknown error'
        })
    }
}

export const login = async (req: Request, res: Response) => {
    try {
        const { email, password } = req.body
        const user = await db.query.users.findFirst({
            where: eq(users.email, email)
        })

        if (!user) {
            return res.status(401).json({ error: 'Invalid Credentials'})
        }
        
        const isValidPassword = await comparePasswords(password, user.password)

        if (!isValidPassword) {
            return res.status(401).json({ error: 'Invalid Credentials' })
        }

        const token = await generateToken({
            id: user.id,
            email: user.email,
            username: user.username,
        })

        return res
            .json({
                message: 'Login Success',
                user: {
                    id: user.id,
                    email: user.email,
                    username: user.username,
                    firstName: user.firstName,
                    lastname: user.lastName,
                    createdAt: user.createdAt,
                },
                token,
            })
            .status(201)
    } catch (e) {
        console.error('Login Error', e)
        res.status(500).json({ error: 'Failed to Login' })
    }
}