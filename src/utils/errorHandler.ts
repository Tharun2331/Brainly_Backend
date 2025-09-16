// src/utils/errorHandler.ts
import { Response } from "express";
import { ZodError } from "zod";

export interface StandardError {
  success: false;
  message: string;
  errors?: Record<string, string>;
  code?: string;
}

export interface StandardSuccess<T = any> {
  success: true;
  message: string;
  data?: T;
}

export type StandardResponse<T = any> = StandardError | StandardSuccess<T>;

/**
 * Format Zod validation errors into user-friendly messages
 */
export function formatZodError(error: ZodError): Record<string, string> {
  const formattedErrors: Record<string, string> = {};
  
  error.errors.forEach((err) => {
    const path = err.path.join(".");
    
    // Custom user-friendly messages based on validation type
    let message = err.message;
    
    if (err.code === "too_small") {
      if (path === "username") {
        message = `Username must be at least ${err.minimum} characters long`;
      } else if (path === "password") {
        message = `Password must be at least ${err.minimum} characters long`;
      }
    } else if (err.code === "too_big") {
      if (path === "username") {
        message = `Username cannot exceed ${err.maximum} characters`;
      } else if (path === "password") {
        message = `Password cannot exceed ${err.maximum} characters`;
      }
    } else if (err.code === "invalid_string" && err.validation === "regex") {
      if (path === "password") {
        message = "Password must contain at least one lowercase letter, one uppercase letter, and one special character (!@#$%^&*)";
      }
    }
    
    formattedErrors[path] = message;
  });
  
  return formattedErrors;
}

/**
 * Send standardized error response
 */
export function sendErrorResponse(
  res: Response,
  statusCode: number,
  message: string,
  errors?: Record<string, string>,
  code?: string
): Response {
  return res.status(statusCode).json({
    success: false,
    message,
    errors,
    code
  } as StandardError);
}

/**
 * Send standardized success response
 */
export function sendSuccessResponse<T = any>(
  res: Response,
  statusCode: number,
  message: string,
  data?: T
): Response {
  return res.status(statusCode).json({
    success: true,
    message,
    data
  } as StandardSuccess<T>);
}

/**
 * Global error handler middleware
 */
export function errorHandlerMiddleware(
  err: any,
  req: any,
  res: Response,
  next: any
): Response | void {
  console.error("Error:", err);

  // Handle Zod validation errors
  if (err instanceof ZodError) {
    return sendErrorResponse(
      res,
      400,
      "Validation failed",
      formatZodError(err),
      "VALIDATION_ERROR"
    );
  }

  // Handle MongoDB duplicate key error
  if (err.code === 11000) {
    const field = Object.keys(err.keyPattern)[0];
    return sendErrorResponse(
      res,
      409,
      `${field} already exists`,
      { [field]: `This ${field} is already taken` },
      "DUPLICATE_ERROR"
    );
  }

  // Handle JWT errors
  if (err.name === "JsonWebTokenError") {
    return sendErrorResponse(
      res,
      401,
      "Invalid authentication token",
      undefined,
      "AUTH_ERROR"
    );
  }

  if (err.name === "TokenExpiredError") {
    return sendErrorResponse(
      res,
      401,
      "Authentication token has expired",
      undefined,
      "TOKEN_EXPIRED"
    );
  }

  // Default error
  return sendErrorResponse(
    res,
    err.status || 500,
    err.message || "Internal server error",
    undefined,
    "SERVER_ERROR"
  );
}