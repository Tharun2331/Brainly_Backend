// src/controllers/authController.ts
import { Request, Response, NextFunction } from "express";
import { 
  sendErrorResponse, 
  sendSuccessResponse 
} from "../utils/errorHandler";
import { AuthService } from "../services/AuthService";

/**
 * User signup
 */
export async function signupUser(
  req: Request,
  res: Response,
  next: NextFunction
) {
  try {
    const { username, password } = req.body;

    const result = await AuthService.signup({ username, password });

    return sendSuccessResponse(
      res,
      201,
      "Account created successfully! Please sign in.",
      result
    );
  } catch (error: any) {
    if (error.message === 'Username already taken') {
      return sendErrorResponse(
        res,
        409,
        error.message,
        { username: "This username is already registered" },
        "DUPLICATE_USER"
      );
    }
    next(error);
  }
}

/**
 * User signin
 */
export async function signinUser(
  req: Request,
  res: Response,
  next: NextFunction
) {
  try {
    const { username, password } = req.body;

    const result = await AuthService.signin({ username, password });

    return sendSuccessResponse(
      res,
      200,
      "Signed in successfully!",
      result
    );
  } catch (error: any) {
    if (error.message === 'Invalid credentials') {
      return sendErrorResponse(
        res,
        401,
        error.message,
        { username: "Username or password is incorrect" },
        "AUTH_FAILED"
      );
    }
    next(error);
  }
}

/**
 * Verify token
 */
export async function verifyToken(
  req: Request,
  res: Response,
  next: NextFunction
) {
  try {
    const token = req.headers.authorization;

    if (!token) {
      return sendErrorResponse(
        res,
        401,
        "No token provided",
        undefined,
        "NO_TOKEN"
      );
    }

    const decoded = AuthService.verifyToken(token);
    const user = await AuthService.getUserById(decoded.id);

    return sendSuccessResponse(
      res,
      200,
      "Token is valid",
      { username: user.username, userId: user._id }
    );
  } catch (error: any) {
    if (error.message === 'Invalid or expired token') {
      return sendErrorResponse(
        res,
        401,
        error.message,
        undefined,
        "TOKEN_INVALID"
      );
    }
    next(error);
  }
}

/**
 * Change password
 */
export async function changePassword(
  req: Request,
  res: Response,
  next: NextFunction
) {
  try {
    const userId = req.userId!;
    const { currentPassword, newPassword } = req.body;

    await AuthService.changePassword(userId, currentPassword, newPassword);

    return sendSuccessResponse(
      res,
      200,
      "Password changed successfully!"
    );
  } catch (error: any) {
    if (error.message === 'Current password is incorrect') {
      return sendErrorResponse(
        res,
        400,
        error.message,
        { currentPassword: "Current password is incorrect" },
        "INVALID_PASSWORD"
      );
    }
    next(error);
  }
}

/**
 * Delete account
 */
export async function deleteAccount(
  req: Request,
  res: Response,
  next: NextFunction
) {
  try {
    const userId = req.userId!;
    const { password } = req.body;

    await AuthService.deleteAccount(userId, password);

    return sendSuccessResponse(
      res,
      200,
      "Account deleted successfully!"
    );
  } catch (error: any) {
    if (error.message === 'Password is incorrect') {
      return sendErrorResponse(
        res,
        400,
        error.message,
        { password: "Password is incorrect" },
        "INVALID_PASSWORD"
      );
    }
    next(error);
  }
}