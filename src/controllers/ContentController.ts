// src/controllers/BrainlyController.ts
import { Request, Response, NextFunction } from "express";
import { 
  sendErrorResponse, 
  sendSuccessResponse 
} from "../utils/errorHandler";
import { ContentService } from "../services/ContentService";

/**
 * Create new content
 */
export async function createContent(
  req: Request, 
  res: Response, 
  next: NextFunction
) {
  try {
    const userId = req.userId!;
    const contentData = req.body;

    const content = await ContentService.createContent(userId, contentData);

    return sendSuccessResponse(
      res,
      201,
      "Content created successfully!",
      content
    );
  } catch (error: any) {
    if (error.message === 'Link is required for non-note content types') {
      return sendErrorResponse(
        res,
        400,
        error.message,
        { link: "Please provide a valid link" },
        "VALIDATION_ERROR"
      );
    }
    next(error);
  }
}

/**
 * Update existing content
 */
export async function updateContent(
  req: Request,
  res: Response,
  next: NextFunction
) {
  try {
    const userId = req.userId!;
    const contentId = req.params.id;
    const updateData = req.body;

    const content = await ContentService.updateContent(
      contentId,
      userId,
      updateData
    );

    return sendSuccessResponse(
      res,
      200,
      "Content updated successfully!",
      content
    );
  } catch (error: any) {
    if (error.message === 'Invalid content ID format') {
      return sendErrorResponse(
        res,
        400,
        error.message,
        undefined,
        "INVALID_ID"
      );
    }
    if (error.message === 'Content not found or you do not have permission') {
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
 * Delete content
 */
export async function deleteContent(
  req: Request,
  res: Response,
  next: NextFunction
) {
  try {
    const userId = req.userId!;
    const contentId = req.params.id;

    await ContentService.deleteContent(contentId, userId);

    return sendSuccessResponse(
      res,
      200,
      "Content deleted successfully!"
    );
  } catch (error: any) {
    if (error.message === 'Invalid content ID format') {
      return sendErrorResponse(
        res,
        400,
        error.message,
        undefined,
        "INVALID_ID"
      );
    }
    if (error.message === 'Content not found or already deleted') {
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
 * Get all content for authenticated user
 */
export async function getContent(
  req: Request,
  res: Response,
  next: NextFunction
) {
  try {
    const userId = req.userId!;
    const filter = req.query.filter as string | undefined;

    const content = await ContentService.getUserContent(userId, filter);

    return sendSuccessResponse(
      res,
      200,
      "Content fetched successfully!",
      { content }
    );
  } catch (error) {
    next(error);
  }
}

/**
 * Get notes
 */
export async function getNotes(
  req: Request,
  res: Response,
  next: NextFunction
) {
  try {
    const userId = req.userId!;
    const notes = await ContentService.getContentByType(userId, 'note');

    return sendSuccessResponse(
      res,
      200,
      "Notes fetched successfully!",
      { notes }
    );
  } catch (error) {
    next(error);
  }
}

/**
 * Get articles
 */
export async function getArticles(
  req: Request,
  res: Response,
  next: NextFunction
) {
  try {
    const userId = req.userId!;
    const articles = await ContentService.getContentByType(userId, 'article');

    return sendSuccessResponse(
      res,
      200,
      "Articles fetched successfully!",
      { articles }
    );
  } catch (error) {
    next(error);
  }
}

/**
 * Get tweets
 */
export async function getTweets(
  req: Request,
  res: Response,
  next: NextFunction
) {
  try {
    const userId = req.userId!;
    const tweets = await ContentService.getContentByType(userId, 'twitter');

    return sendSuccessResponse(
      res,
      200,
      "Tweets fetched successfully!",
      { tweets }
    );
  } catch (error) {
    next(error);
  }
}

/**
 * Get YouTube videos
 */
export async function getVideos(
  req: Request,
  res: Response,
  next: NextFunction
) {
  try {
    const userId = req.userId!;
    const videos = await ContentService.getContentByType(userId, 'youtube');

    return sendSuccessResponse(
      res,
      200,
      "Videos fetched successfully!",
      { youtubeVideos: videos }
    );
  } catch (error) {
    next(error);
  }
}

/**
 * Semantic search
 */
export async function semanticSearch(
  req: Request,
  res: Response,
  next: NextFunction
) {
  try {
    const userId = req.userId!;
    const { query, limit, contentType, tags } = req.query;

    const result = await ContentService.semanticSearch(userId, {
      query: query as string,
      limit: limit ? parseInt(limit as string, 10) : undefined,
      contentType: contentType 
        ? (contentType as string).split(',') 
        : undefined,
      tags: tags 
        ? (tags as string).split(',') 
        : undefined,
    });

    return sendSuccessResponse(
      res,
      200,
      "Search completed successfully!",
      result
    );
  } catch (error: any) {
    if (error.message === 'Search query cannot be empty') {
      return sendErrorResponse(
        res,
        400,
        error.message,
        { query: "Please provide a valid search query" },
        "VALIDATION_ERROR"
      );
    }
    if (error.message === 'Limit must be between 1 and 50') {
      return sendErrorResponse(
        res,
        400,
        error.message,
        { limit: "Limit must be between 1 and 50" },
        "VALIDATION_ERROR"
      );
    }
    next(error);
  }
}

/**
 * Get search suggestions
 */
export async function getSearchSuggestions(
  req: Request,
  res: Response,
  next: NextFunction
) {
  try {
    const userId = req.userId!;
    const { prefix } = req.query;

    const suggestions = await ContentService.getSearchSuggestions(
      userId,
      prefix as string
    );

    return sendSuccessResponse(
      res,
      200,
      "Suggestions fetched successfully!",
      { suggestions }
    );
  } catch (error: any) {
    if (error.message === 'Prefix cannot be empty') {
      return sendErrorResponse(
        res,
        400,
        error.message,
        { prefix: "Please provide a search prefix" },
        "VALIDATION_ERROR"
      );
    }
    next(error);
  }
}

/**
 * Reindex user content (admin/maintenance endpoint)
 */
export async function reindexContent(
  req: Request,
  res: Response,
  next: NextFunction
) {
  try {
    const userId = req.userId!;

    const result = await ContentService.reindexUserContent(userId);

    return sendSuccessResponse(
      res,
      200,
      "Content reindexed successfully!",
      result
    );
  } catch (error) {
    next(error);
  }
}