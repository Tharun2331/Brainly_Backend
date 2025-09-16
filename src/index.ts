// src/index.ts
declare global {
  namespace Express {
    export interface Request {
      userId?: string;
    }
  }
}

import express, { Request, Response, NextFunction } from "express";
import mongoose from "mongoose";
import dotenv from "dotenv";
import cors from "cors";
import { router } from "./Routes/BrainlyRouter";
import { errorHandlerMiddleware } from "./utils/errorHandler";
import job from "./cron";

dotenv.config();

const port = process.env.PORT || 3000;
const app = express();

// Middleware
app.use(express.json());
app.use(cors({
  origin: process.env.FRONTEND_URL || "http://localhost:5173",
  credentials: true,
}));

// Request logging middleware (optional but useful)
app.use((req: Request, res: Response, next: NextFunction) => {
  console.log(`${new Date().toISOString()} - ${req.method} ${req.path}`);
  next();
});

// Routes
app.use("/api/v1", router);

// Health check endpoint
app.get("/api/v1/health", (req: Request, res: Response) => {
  res.status(200).json({ 
    success: true,
    message: "Server is running",
    timestamp: new Date().toISOString(),
  });
});

// Token verification endpoint (add to your router instead if preferred)
app.get("/api/v1/verify", (req: Request, res: Response, next: NextFunction) => {
  try {
    const token = req.headers.authorization;
    if (!token) {
      return res.status(401).json({
        success: false,
        message: "No token provided",
        code: "NO_TOKEN",
      });
    }
    
    // Verify token (you'll need to import jwt and USER_JWT_SECRET)
    // This is just a placeholder - implement proper verification
    res.status(200).json({
      success: true,
      message: "Token is valid",
      data: { username: "user" }, // Get from decoded token
    });
  } catch (error) {
    next(error);
  }
});

// 404 handler
app.use((req: Request, res: Response) => {
  res.status(404).json({
    success: false,
    message: "Endpoint not found",
    code: "NOT_FOUND",
  });
});

// Global error handler (must be last)
app.use(errorHandlerMiddleware);

// Start cron job in production
if (process.env.NODE_ENV === "production") {
  job.start();
  console.log("Cron job started");
}

// Start server
app.listen(port, () => {
  console.log(`Server running on port ${port}`);
  console.log(`Environment: ${process.env.NODE_ENV || 'development'}`);
});