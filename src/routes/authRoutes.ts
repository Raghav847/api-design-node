import { Router } from "express";

const router = Router()

router.post("/register", (req, res) => {
    res.status(201).json({ message: 'User signed up'})
})

router.post("/login", (req, res) => {
    res.status(201).json({ message: 'User signed in'})
})

export default router