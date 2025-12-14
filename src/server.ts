import express from 'express'
import authRoutes from './routes/authRoutes.ts'
import userRoutes from './routes/userRoutes.ts'
import habitRoutes from './routes/habitRoutes.ts'

const app = express()

app.get("/health", (req, res) => {
    res.json({message: "hello"}).status(200)
})

app.use("/api/auth", authRoutes)
app.use("/api/users", userRoutes)
app.use("/api/habits", habitRoutes)


export { app }

export default app
