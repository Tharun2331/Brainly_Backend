// src/controllers/tagController.ts
import { Request, Response, NextFunction } from "express";
import { 
  sendErrorResponse, 
  sendSuccessResponse 
} from "../utils/errorHandler";
import { TagService } from "../services/TagService";

/**
 * Create tags
 */
export async function createTags(
  req: Request,
  res: Response,
  next: NextFunction
) {
  try {
    const { tags } = req.body;

    const tagIds = await TagService.createTags(tags);

    return sendSuccessResponse(
      res,
      200,
      "Tags processed successfully!",
      { tagIds }
    );
  } catch (error: any) {
    if (error.message === 'Tags must be a non-empty array') {
      return sendErrorResponse(
        res,
        400,
        error.message,
        { tags: "Please provide at least one tag" },
        "VALIDATION_ERROR"
      );
    }
    if (error.message === 'No valid tags provided') {
      return sendErrorResponse(
        res,
        400,
        error.message,
        { tags: "No valid tags provided" },
        "VALIDATION_ERROR"
      );
    }
    next(error);
  }
}

/**
 * Get all user tags
 */
export async function getUserTags(
  req: Request,
  res: Response,
  next: NextFunction
) {
  try {
    const userId = req.userId!;

    const tags = await TagService.getUserTags(userId);

    return sendSuccessResponse(
      res,
      200,
      "Tags fetched successfully!",
      { tags }
    );
  } catch (error) {
    next(error);
  }
}

/**
 * Get popular tags
 */
export async function getPopularTags(
  req: Request,
  res: Response,
  next: NextFunction
) {
  try {
    const limit = req.query.limit 
      ? parseInt(req.query.limit as string, 10) 
      : 10;

    const tags = await TagService.getPopularTags(limit);

    return sendSuccessResponse(
      res,
      200,
      "Popular tags fetched successfully!",
      { tags }
    );
  } catch (error) {
    next(error);
  }
}

/**
 * Get content by tag
 */
export async function getContentByTag(
  req: Request,
  res: Response,
  next: NextFunction
) {
  try {
    const userId = req.userId!;
    const { tagName } = req.params;

    const content = await TagService.getContentByTag(userId, tagName);

    return sendSuccessResponse(
      res,
      200,
      "Content fetched successfully!",
      { content, tag: tagName }
    );
  } catch (error) {
    next(error);
  }
}

/**
 * Search tags
 */
export async function searchTags(
  req: Request,
  res: Response,
  next: NextFunction
) {
  try {
    const userId = req.userId!;
    const { prefix, limit } = req.query;

    if (!prefix || typeof prefix !== 'string') {
      return sendErrorResponse(
        res,
        400,
        "Prefix is required",
        { prefix: "Please provide a search prefix" },
        "VALIDATION_ERROR"
      );
    }

    const limitNum = limit 
      ? parseInt(limit as string, 10) 
      : 10;

    const tags = await TagService.searchTags(userId, prefix, limitNum);

    return sendSuccessResponse(
      res,
      200,
      "Tags found successfully!",
      { tags }
    );
  } catch (error) {
    next(error);
  }
}

/**
 * Rename tag
 */
export async function renameTag(
  req: Request,
  res: Response,
  next: NextFunction
) {
  try {
    const userId = req.userId!;
    const { oldTagName, newTagName } = req.body;

    if (!oldTagName || !newTagName) {
      return sendErrorResponse(
        res,
        400,
        "Both old and new tag names are required",
        undefined,
        "VALIDATION_ERROR"
      );
    }

    const result = await TagService.renameTag(userId, oldTagName, newTagName);

    return sendSuccessResponse(
      res,
      200,
      result.merged 
        ? "Tag merged successfully!" 
        : "Tag renamed successfully!",
      result
    );
  } catch (error: any) {
    if (error.message === 'Tag not found') {
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
 * Delete unused tags
 */
export async function deleteUnusedTags(
  req: Request,
  res: Response,
  next: NextFunction
) {
  try {
    const result = await TagService.deleteUnusedTags();

    return sendSuccessResponse(
      res,
      200,
      "Unused tags deleted successfully!",
      result
    );
  } catch (error) {
    next(error);
  }
}