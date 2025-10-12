// src/controllers/ContentController.ts
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

    const content = await ContentService.createContent(userId, contentData) as any;

    // Provide helpful message based on content type
    let message = "Content created successfully!";
    if (content.processingStatus === 'pending') {
      message = "Content created! Processing in background...";
    } else if (content.processingStatus === 'completed') {
      message = "Content created and ready!";
    }

    return sendSuccessResponse(
      res,
      201,
      message,
      {
        content,
        processingStatus: content.processingStatus,
        queueStatus: ContentService.getQueueStatus()
      }
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
 * Get single content by ID
 */
export async function getContentById(
  req: Request,
  res: Response,
  next: NextFunction
) {
  try {
    const userId = req.userId!;
    const contentId = req.params.id;

    const content = await ContentService.getContentById(contentId, userId);

    return sendSuccessResponse(
      res,
      200,
      "Content fetched successfully!",
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
    if (error.message === 'Content not found') {
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
 * Get notes
 */
export async function getNotes(
  req: Request,
  res: Response,
  next: NextFunction
) {
  try {
    const userId = req.userId!;
    const notes = await ContentService.getUserContent(userId, 'note');

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
    const articles = await ContentService.getUserContent(userId, 'article');

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
    const tweets = await ContentService.getUserContent(userId, 'twitter');

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
    const videos = await ContentService.getUserContent(userId, 'youtube');

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

// =====================================================
// NEW ENDPOINTS FOR APIFY INTEGRATION
// =====================================================

/**
 * Reprocess failed or pending content
 * Useful for retry functionality in the UI
 */
export async function reprocessContent(
  req: Request,
  res: Response,
  next: NextFunction
) {
  try {
    const userId = req.userId!;
    const contentId = req.params.id;

    const result = await ContentService.reprocessContent(contentId, userId);

    return sendSuccessResponse(
      res,
      200,
      result.message,
      {
        queueSize: result.queueSize
      }
    );
  } catch (error: any) {
    if (error.message === 'Content not found') {
      return sendErrorResponse(
        res,
        404,
        error.message,
        undefined,
        "NOT_FOUND"
      );
    }
    if (error.message === 'Content is already being processed') {
      return sendErrorResponse(
        res,
        409,
        error.message,
        undefined,
        "ALREADY_PROCESSING"
      );
    }
    if (error.message === 'Notes do not require reprocessing') {
      return sendErrorResponse(
        res,
        400,
        error.message,
        undefined,
        "INVALID_TYPE"
      );
    }
    next(error);
  }
}

/**
 * Get processing queue status
 * Useful for monitoring and debugging
 */
export async function getQueueStatus(
  req: Request,
  res: Response,
  next: NextFunction
) {
  try {
    const status = ContentService.getQueueStatus();

    return sendSuccessResponse(
      res,
      200,
      "Queue status fetched successfully!",
      status
    );
  } catch (error) {
    next(error);
  }
}

/**
 * Get processing statistics for user's content
 * Shows breakdown by processing status
 */
export async function getProcessingStats(
  req: Request,
  res: Response,
  next: NextFunction
) {
  try {
    const userId = req.userId!;

    const stats = await ContentService.getProcessingStats(userId);

    return sendSuccessResponse(
      res,
      200,
      "Processing statistics fetched successfully!",
      stats
    );
  } catch (error) {
    next(error);
  }
}

/**
 * Batch reprocess multiple content items
 * Useful for fixing multiple failed extractions at once
 */
export async function batchReprocessContent(
  req: Request,
  res: Response,
  next: NextFunction
) {
  try {
    const userId = req.userId!;
    const { contentIds } = req.body;

    if (!Array.isArray(contentIds) || contentIds.length === 0) {
      return sendErrorResponse(
        res,
        400,
        "Content IDs array is required",
        { contentIds: "Please provide an array of content IDs" },
        "VALIDATION_ERROR"
      );
    }

    if (contentIds.length > 50) {
      return sendErrorResponse(
        res,
        400,
        "Too many content IDs",
        { contentIds: "Maximum 50 content IDs allowed per batch" },
        "VALIDATION_ERROR"
      );
    }

    const results = {
      queued: [] as string[],
      failed: [] as { id: string; error: string }[]
    };

    // Process each content ID
    for (const contentId of contentIds) {
      try {
        await ContentService.reprocessContent(contentId, userId);
        results.queued.push(contentId);
      } catch (error: any) {
        results.failed.push({
          id: contentId,
          error: error.message || 'Unknown error'
        });
      }
    }

    return sendSuccessResponse(
      res,
      200,
      `Queued ${results.queued.length} items for reprocessing`,
      {
        queued: results.queued.length,
        failed: results.failed.length,
        details: results,
        queueStatus: ContentService.getQueueStatus()
      }
    );
  } catch (error) {
    next(error);
  }
}

/**
 * Get failed content items for user
 * Useful for showing what needs to be reprocessed
 */
export async function getFailedContent(
  req: Request,
  res: Response,
  next: NextFunction
) {
  try {
    const userId = req.userId!;
    const { limit = 20 } = req.query;

    // You'll need to add this method to ContentService
    const failedContent = await ContentService.getUserContent(userId) as any[];
    
    // Filter only failed items
    const failed = failedContent
      .filter(item => item.processingStatus === 'failed')
      .slice(0, parseInt(limit as string, 10));

    return sendSuccessResponse(
      res,
      200,
      "Failed content fetched successfully!",
      {
        failed,
        count: failed.length
      }
    );
  } catch (error) {
    next(error);
  }
}

/**
 * Get pending content items for user
 * Useful for monitoring what's in queue
 */
export async function getPendingContent(
  req: Request,
  res: Response,
  next: NextFunction
) {
  try {
    const userId = req.userId!;
    const { limit = 20 } = req.query;

    const allContent = await ContentService.getUserContent(userId) as any[];
    
    // Filter only pending items
    const pending = allContent
      .filter(item => item.processingStatus === 'pending' || item.processingStatus === 'processing')
      .slice(0, parseInt(limit as string, 10));

    return sendSuccessResponse(
      res,
      200,
      "Pending content fetched successfully!",
      {
        pending,
        count: pending.length,
        queueStatus: ContentService.getQueueStatus()
      }
    );
  } catch (error) {
    next(error);
  }
}

/**
 * Health check for content processing system
 * Useful for monitoring and alerts
 */
export async function processingHealthCheck(
  req: Request,
  res: Response,
  next: NextFunction
) {
  try {
    const queueStatus = ContentService.getQueueStatus();
    
    // Consider system unhealthy if queue is too large
    const isHealthy = queueStatus.queueSize < 100;
    const status = isHealthy ? 'healthy' : 'degraded';

    return res.status(isHealthy ? 200 : 503).json({
      success: true,
      status,
      queue: queueStatus,
      timestamp: new Date().toISOString()
    });
  } catch (error) {
    next(error);
  }
}

/**
 * Migrate content from description to fullContent field
 * Fixes the issue where extraction failed but content was stored in description
 */
export async function migrateContentFromDescription(
  req: Request,
  res: Response,
  next: NextFunction
) {
  try {
    const userId = req.userId!;

    const result = await ContentService.migrateContentFromDescription(userId);

    return sendSuccessResponse(
      res,
      200,
      `Migration completed: ${result.migrated} migrated, ${result.skipped} skipped, ${result.errors} errors`,
      result
    );
  } catch (error) {
    next(error);
  }
}

/**
 * Reprocess tweet content specifically
 * Enhanced reprocessing for tweets that failed extraction
 */
export async function reprocessTweetContent(
  req: Request,
  res: Response,
  next: NextFunction
) {
  try {
    const userId = req.userId!;
    const contentId = req.params.id;

    const result = await ContentService.reprocessTweetContent(contentId, userId);

    return sendSuccessResponse(
      res,
      200,
      result.message,
      {
        queueSize: result.queueSize
      }
    );
  } catch (error: any) {
    if (error.message === 'Tweet content not found') {
      return sendErrorResponse(
        res,
        404,
        error.message,
        undefined,
        "NOT_FOUND"
      );
    }
    if (error.message === 'Tweet is already being processed') {
      return sendErrorResponse(
        res,
        409,
        error.message,
        undefined,
        "ALREADY_PROCESSING"
      );
    }
    next(error);
  }
}