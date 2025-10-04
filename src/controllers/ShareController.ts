// src/controllers/shareController.ts
import { Request, Response, NextFunction } from "express";
import { 
  sendErrorResponse, 
  sendSuccessResponse 
} from "../utils/errorHandler";
import { ShareService } from "../services/ShareService";

/**
 * Create or get share link
 */
export async function createHash(
  req: Request,
  res: Response,
  next: NextFunction
) {
  try {
    const userId = req.userId!;
    const { share } = req.body;

    // If share is false, remove the link
    if (share === false) {
      await ShareService.removeShareLink(userId);
      return sendSuccessResponse(
        res,
        200,
        "Share link removed successfully!"
      );
    }

    // Create or get share link
    const result = await ShareService.createShareLink(userId);

    return sendSuccessResponse(
      res,
      200,
      "Share link created successfully!",
      result
    );
  } catch (error: any) {
    if (error.message === 'No share link found to remove') {
      return sendErrorResponse(
        res,
        404,
        error.message,
        undefined,
        "NOT_FOUND"
      );
    }
    next(error);
  }
}

/**
 * Get shared content by hash
 */
export async function getLink(
  req: Request,
  res: Response,
  next: NextFunction
) {
  try {
    const { shareLink } = req.params;

    const result = await ShareService.getSharedContent(shareLink);

    return sendSuccessResponse(
      res,
      200,
      "Shared content fetched successfully!",
      result
    );
  } catch (error: any) {
    if (error.message === 'Share link not found') {
      return sendErrorResponse(
        res,
        404,
        error.message,
        undefined,
        "NOT_FOUND"
      );
    }
    if (error.message === 'User not found') {
      return sendErrorResponse(
        res,
        404,
        error.message,
        undefined,
        "USER_NOT_FOUND"
      );
    }
    next(error);
  }
}

/**
 * Get current user's share link
 */
export async function getMyShareLink(
  req: Request,
  res: Response,
  next: NextFunction
) {
  try {
    const userId = req.userId!;

    const result = await ShareService.getUserShareLink(userId);

    if (!result) {
      return sendSuccessResponse(
        res,
        200,
        "No share link found",
        { hasShareLink: false }
      );
    }

    return sendSuccessResponse(
      res,
      200,
      "Share link retrieved successfully!",
      { hasShareLink: true, ...result }
    );
  } catch (error) {
    next(error);
  }
}

/**
 * Regenerate share link
 */
export async function regenerateShareLink(
  req: Request,
  res: Response,
  next: NextFunction
) {
  try {
    const userId = req.userId!;

    const result = await ShareService.regenerateShareLink(userId);

    return sendSuccessResponse(
      res,
      200,
      "Share link regenerated successfully!",
      result
    );
  } catch (error) {
    next(error);
  }
}