import express from 'express'
import env from 'dotenv'
import helmet from 'helmet'
import cors from "cors"
import morgan from 'morgan'
import allPost from './routes/allpost.route.js'
import categoryRoutes from './routes/categories.route.js'
import commentRoutes from './routes/comments.route.js'
import subscriberRoutes from './routes/subscribers.route.js'
import userRoutes from './routes/users.route.js'
import adminRoutes from './routes/admin.route.js'
env.config()
const app = express()

app.use(express.json())
app.use(express.urlencoded({extended: true}))
app.use(morgan('dev'))
app.use(helmet())
app.use(cors({
  origin: ["http://localhost:5173","https://seo-blog-sigma.vercel.app"], 
  credentials: true, 
}));

const PORT = process.env.PORT

// Routes
app.use('/api/v1', allPost)
app.use('/api/v1/categories', categoryRoutes)
app.use('/api/v1/comments', commentRoutes)
app.use('/api/v1/subscribers', subscriberRoutes)
app.use('/api/v1/users', userRoutes)
app.use('/api/admin', adminRoutes)

// 404 handler
// app.use('/*', (req, res) => {
//   res.status(404).json({
//     success: false,
//     message: 'API endpoint not found'
//   })
// })

// Global error handler
app.use((err, req, res, next) => {
  console.error(err.stack)
  res.status(500).json({
    success: false,
    message: 'Internal server error',
    error: process.env.NODE_ENV === 'development' ? err.message : undefined
  })
})

app.listen(PORT, () => {
  console.log(`Server is listening on the port ${PORT}`)
})