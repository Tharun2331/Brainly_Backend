// src/services/ContentService.ts
import { contentModel, tagModel } from '../db';
import {
  addContentToVector,
  updateContentInVector,
  deleteContentFromVector,
  searchContent,
} from './PineconeService';
import { ContentExtractorService } from './ContentExtractorService';
import mongoose from 'mongoose';

// Types
export interface CreateContentDTO {
  title?: string;
  link?: string;
  description: string;
  type: 'twitter' | 'youtube' | 'article' | 'note';
  tags: string[];
}

export interface UpdateContentDTO {
  title?: string;
  link?: string;
  description?: string;
  type?: 'twitter' | 'youtube' | 'article' | 'note';
  tags?: string[];
}

export interface SearchOptions {
  query: string;
  limit?: number;
  contentType?: string[];
  tags?: string[];
}

// Helper function to extract tag names safely
function extractTagNames(tags: any[]): string[] {
  if (!Array.isArray(tags)) return [];
  return tags
    .map(t => {
      if (typeof t === 'string') return t;
      if (t && typeof t === 'object' && 'tag' in t) return t.tag;
      return String(t);
    })
    .filter(Boolean);
}

// Helper to validate MongoDB ObjectId
function isValidObjectId(id: string): boolean {
  return mongoose.Types.ObjectId.isValid(id);
}

// =====================================================
// SIMPLE IN-MEMORY QUEUE
// For production, replace with Redis/Bull
// =====================================================
class ProcessingQueue {
  private queue: Array<{
    contentId: string;
    type: string;
    link: string;
    description: string;
    userId: string;
    retryCount?: number;
  }> = [];
  private processing = false;
  private maxRetries = 3;

  add(item: any) {
    this.queue.push({ ...item, retryCount: 0 });
    console.log(`📥 Added to queue: ${item.contentId} (Queue size: ${this.queue.length})`);
    this.process();
  }

  private async process() {
    if (this.processing || this.queue.length === 0) return;

    this.processing = true;

    while (this.queue.length > 0) {
      const item = this.queue.shift();
      if (!item) continue;

      try {
        console.log(`⚙️ Processing: ${item.contentId} (${item.type})`);
        await ContentService.processContentItem(
          item.contentId,
          item.type,
          item.link,
          item.description,
          item.userId
        );
      } catch (error) {
        console.error(`❌ Failed to process ${item.contentId}:`, error);

        // Retry logic
        const retryCount = (item.retryCount || 0) + 1;
        if (retryCount < this.maxRetries) {
          console.log(`🔄 Retrying ${item.contentId} (Attempt ${retryCount + 1}/${this.maxRetries})`);
          
          // Add back to queue with delay
          setTimeout(() => {
            this.add({ ...item, retryCount });
          }, 5000 * retryCount); // Exponential backoff: 5s, 10s, 15s
        } else {
          console.error(`💀 Max retries reached for ${item.contentId}`);
        }
      }
    }

    this.processing = false;
  }

  getQueueSize(): number {
    return this.queue.length;
  }

  isProcessing(): boolean {
    return this.processing;
  }
}

const processingQueue = new ProcessingQueue();

// =====================================================
// CONTENT SERVICE
// =====================================================
export class ContentService {
  /**
   * Create new content
   */
  static async createContent(
    userId: string,
    contentData: CreateContentDTO
  ) {
    const { link, type, title, tags, description } = contentData;

    // Business rule: Non-note content must have a link
    if (type !== 'note' && !link) {
      throw new Error('Link is required for non-note content types');
    }

    // Validate URL matches content type
    if (type !== 'note' && link) {
      const validatedType = this.validateUrlType(link);
      if (validatedType !== type) {
        throw new Error(`URL does not match content type. Expected ${type}, but URL appears to be ${validatedType}`);
      }
    }

    // Create tag references
    const tagIds = await this.processTags(tags);

    // Create content with pending status
    const content = await contentModel.create({
      link,
      title: title || (type === 'note' ? 'Untitled Note' : ''),
      description,
      type,
      userId,
      tags: tagIds,
      processingStatus: 'pending',
      // For notes, set fullContent immediately
      fullContent: type === 'note' ? description : undefined
    });

    console.log(`📝 Created content ${content._id} (${type})`);

    // Handle notes immediately (no extraction needed)
    if (type === 'note') {
      await contentModel.findByIdAndUpdate(content._id, {
        processingStatus: 'completed',
        contentMetadata: {
          wordCount: description.split(/\s+/).length,
          extractedAt: new Date(),
          extractionMethod: 'direct'
        }
      });

      // Get populated content for vector indexing
      const populatedContent = await contentModel
        .findById(content._id)
        .populate('tags', 'tag')
        .lean();

      if (populatedContent) {
        this.indexContentAsync(
          content._id.toString(),
          userId,
          {
            title: populatedContent.title,
            description: populatedContent.description,
            type: populatedContent.type,
            link: populatedContent.link ?? undefined,
            tags: extractTagNames(populatedContent.tags as any[]),
            fullContent: populatedContent.fullContent || ''
          }
        );
      }
    } else {
      // Queue for background processing (YouTube, Article, Twitter)
      processingQueue.add({
        contentId: content._id.toString(),
        type,
        link: link || '',
        description,
        userId
      });
    }

    // Return populated content immediately
    const populatedContent = await contentModel
      .findById(content._id)
      .populate('tags', 'tag')
      .populate('userId', 'username')
      .lean();

    if (!populatedContent) {
      throw new Error('Failed to retrieve created content');
    }

    return populatedContent;
  }

  /**
   * Process individual content item (called by queue)
   * Extracts full content using Apify and updates MongoDB + Pinecone
   */
  static async processContentItem(
    contentId: string,
    type: string,
    link: string,
    description: string,
    userId: string
  ) {
    try {
      console.log(`🔄 Processing content ${contentId} (${type})`);

      // Update status to processing
      await contentModel.findByIdAndUpdate(contentId, {
        processingStatus: 'processing'
      });

      // Extract content using Apify (or fallback methods)
      const { fullContent, metadata } = await ContentExtractorService.extractContent(
        type,
        link,
        description
      );

      console.log(`✅ Extracted ${metadata.wordCount} words from ${type}`);

      // Update MongoDB with extracted content
      await contentModel.findByIdAndUpdate(contentId, {
        fullContent,
        contentMetadata: {
          ...metadata,
          extractedAt: new Date()
        },
        processingStatus: 'completed'
      });

      // Get updated content with populated fields
      const content = await contentModel
        .findById(contentId)
        .populate('tags', 'tag')
        .lean();

      if (!content) {
        console.error(`❌ Content ${contentId} not found after update - may have been deleted`);
        throw new Error(`Content ${contentId} not found after update`);
      }

      // Create enhanced searchable text for vector DB
      // Include full content for better semantic search
      const searchableText = this.buildSearchableText(
        content.title,
        content.description,
        fullContent,
        content.type,
        extractTagNames(content.tags as any[])
      );

      // Update Pinecone with rich content
      await updateContentInVector(
        contentId,
        userId,
        {
          title: content.title,
          description: content.description, // Use original description, not enhanced text
          type: content.type,
          link: content.link ?? undefined,
          tags: extractTagNames(content.tags as any[]),
          fullContent: fullContent // Include extracted full content
        }
      );

      console.log(`✅ Successfully processed and indexed content ${contentId}`);

    } catch (error) {
      console.error(`❌ Failed to process content ${contentId}:`, error);

      // Update status to failed with error message
      await contentModel.findByIdAndUpdate(contentId, {
        processingStatus: 'failed',
        processingError: error instanceof Error ? error.message : 'Unknown error'
      });

      throw error; // Re-throw for queue retry logic
    }
  }

  /**
   * Validate URL and determine content type
   */
  private static validateUrlType(url: string): 'youtube' | 'twitter' | 'article' {
    const lowerUrl = url.toLowerCase();
    
    // Check for YouTube URLs
    if (lowerUrl.includes('youtube.com') || lowerUrl.includes('youtu.be')) {
      return 'youtube';
    }
    
    // Check for Twitter/X URLs
    if (lowerUrl.includes('twitter.com') || lowerUrl.includes('x.com')) {
      return 'twitter';
    }
    
    // Everything else is considered an article
    return 'article';
  }

  /**
   * Build enhanced searchable text for vector database
   * Combines title, description, full content, and tags
   */
  private static buildSearchableText(
    title: string,
    description: string,
    fullContent: string,
    type: string,
    tags: string[]
  ): string {
    // Truncate full content if too long (keep first 8000 chars)
    const truncatedContent = fullContent.length > 8000
      ? fullContent.substring(0, 8000) + '... [content truncated]'
      : fullContent;

    return `
Title: ${title}
Type: ${type}
Description: ${description}
Content: ${truncatedContent}
Tags: ${tags.join(', ')}
    `.trim();
  }

  /**
   * Reprocess failed or pending content
   * Useful for retry functionality in UI
   */
  static async reprocessContent(contentId: string, userId: string) {
    const content = await contentModel.findOne({
      _id: contentId,
      userId
    }) as any;

    if (!content) {
      throw new Error('Content not found');
    }

    if (content.processingStatus === 'processing') {
      throw new Error('Content is already being processed');
    }

    if (content.type === 'note') {
      throw new Error('Notes do not require reprocessing');
    }

    // Reset status and add back to queue
    await contentModel.findByIdAndUpdate(contentId, {
      processingStatus: 'pending',
      processingError: undefined
    });

    processingQueue.add({
      contentId: content._id.toString(),
      type: content.type,
      link: content.link || '',
      description: content.description,
      userId
    });

    return { 
      message: 'Content queued for reprocessing',
      queueSize: processingQueue.getQueueSize()
    };
  }

  /**
   * Reprocess tweets that failed extraction
   * Specifically designed for tweet content that may have failed Apify extraction
   */
  static async reprocessTweetContent(contentId: string, userId: string) {
    const content = await contentModel.findOne({
      _id: contentId,
      userId,
      type: 'twitter'
    }) as any;

    if (!content) {
      throw new Error('Tweet content not found');
    }

    if (content.processingStatus === 'processing') {
      throw new Error('Tweet is already being processed');
    }

    // For tweets, we'll try a more aggressive reprocessing approach
    console.log(`🔄 Reprocessing tweet ${contentId} with enhanced extraction`);

    // Reset status and clear any previous errors
    await contentModel.findByIdAndUpdate(contentId, {
      processingStatus: 'pending',
      processingError: undefined,
      fullContent: undefined, // Clear previous content to force fresh extraction
      contentMetadata: {
        ...content.contentMetadata,
        reprocessedAt: new Date(),
        reprocessReason: 'Tweet extraction enhancement'
      }
    });

    processingQueue.add({
      contentId: content._id.toString(),
      type: content.type,
      link: content.link || '',
      description: content.description,
      userId
    });

    return { 
      message: 'Tweet queued for enhanced reprocessing',
      queueSize: processingQueue.getQueueSize()
    };
  }

  /**
   * Get queue status (for monitoring)
   */
  static getQueueStatus() {
    return {
      queueSize: processingQueue.getQueueSize(),
      isProcessing: processingQueue.isProcessing()
    };
  }

  /**
   * Update existing content
   */
  static async updateContent(
    contentId: string,
    userId: string,
    updateData: UpdateContentDTO
  ) {
    // Validate ID format
    if (!isValidObjectId(contentId)) {
      throw new Error('Invalid content ID format');
    }

    // Process tags if provided
    let tagIds;
    if (updateData.tags) {
      tagIds = await this.processTags(updateData.tags);
    }

    // Update content
    const content = await contentModel.findOneAndUpdate(
      { _id: contentId, userId },
      { 
        ...updateData,
        ...(tagIds && { tags: tagIds })
      },
      { new: true, runValidators: true }
    );

    if (!content) {
      throw new Error('Content not found or you do not have permission');
    }

    // Get populated content
    const populatedContent = await contentModel
      .findById(content._id)
      .populate('tags', 'tag')
      .populate('userId', 'username')
      .lean() as any;

    if (!populatedContent) {
      throw new Error('Failed to retrieve updated content');
    }

    // If content has fullContent, update vector with it
    const searchableText = populatedContent.fullContent
      ? this.buildSearchableText(
          populatedContent.title,
          populatedContent.description,
          populatedContent.fullContent,
          populatedContent.type,
          extractTagNames(populatedContent.tags as any[])
        )
      : populatedContent.description;

    // Update vector database asynchronously
    this.updateVectorAsync(contentId, userId, {
      title: populatedContent.title || 'Untitled',
      description: searchableText,
      type: populatedContent.type,
      link: populatedContent.link ?? undefined,
      tags: extractTagNames(populatedContent.tags as any[]),
    });

    return populatedContent;
  }

  /**
   * Delete content
   */
  static async deleteContent(contentId: string, userId: string) {
    // Validate ID format
    if (!isValidObjectId(contentId)) {
      throw new Error('Invalid content ID format');
    }

    // Delete from MongoDB
    const result = await contentModel.deleteOne({
      _id: contentId,
      userId,
    });

    if (result.deletedCount === 0) {
      throw new Error('Content not found or already deleted');
    }

    // Delete from vector database asynchronously
    this.deleteVectorAsync(contentId);

    return { success: true, deletedId: contentId };
  }

  /**
   * Get all content for a user
   */
  static async getUserContent(userId: string, filter?: string) {
    const query: any = { userId };

    // Apply content type filter
    if (filter && filter !== 'all') {
      query.type = filter;
    }

    const content = await contentModel
      .find(query)
      .populate('tags', 'tag')
      .populate('userId', 'username')
      .sort({ createdAt: -1 })
      .lean();

    return content;
  }


  /**
   * Get single content by ID (useful for chat feature)
   */
  static async getContentById(contentId: string, userId: string) {
    if (!isValidObjectId(contentId)) {
      throw new Error('Invalid content ID format');
    }

    const content = await contentModel
      .findOne({ _id: contentId, userId })
      .populate('tags', 'tag')
      .populate('userId', 'username')
      .lean();

    if (!content) {
      throw new Error('Content not found');
    }

    return content;
  }

  /**
   * Semantic search across user's content
   */
  static async semanticSearch(
    userId: string,
    options: SearchOptions
  ) {
    const { query, limit = 10, contentType, tags: filterTags } = options;

    // Validate inputs
    if (!query || query.trim().length === 0) {
      throw new Error('Search query cannot be empty');
    }

    if (limit < 1 || limit > 50) {
      throw new Error('Limit must be between 1 and 50');
    }

    // Search in vector database
    const vectorResults = await searchContent(
      query.trim(),
      userId,
      limit
    );

    // Get valid content IDs
    const contentIds = vectorResults
      .map(r => r.id)
      .filter(id => isValidObjectId(id));

    if (contentIds.length === 0) {
      return {
        results: [],
        query: query.trim(),
        totalResults: 0,
      };
    }

    // Build MongoDB query
    const dbQuery: any = { 
      _id: { $in: contentIds },
      userId 
    };

    // Apply content type filter
    if (contentType && contentType.length > 0) {
      dbQuery.type = { $in: contentType };
    }

    // Fetch from MongoDB
    const contents = await contentModel
      .find(dbQuery)
      .populate('tags', 'tag')
      .populate('userId', 'username')
      .lean();

    // Merge with relevance scores
    let resultsWithScores = contents.map(content => {
      const vectorResult = vectorResults.find(
        r => r.id === content._id.toString()
      );
      return {
        ...content,
        relevanceScore: vectorResult?.score || 0,
      };
    });

    // Filter by tags if specified
    if (filterTags && filterTags.length > 0) {
      resultsWithScores = resultsWithScores.filter(content => {
        const contentTagNames = extractTagNames(content.tags as any[]);
        return filterTags.some(tag => contentTagNames.includes(tag));
      });
    }

    // Sort by relevance score
    resultsWithScores.sort((a, b) => b.relevanceScore - a.relevanceScore);

    return {
      results: resultsWithScores,
      query: query.trim(),
      totalResults: resultsWithScores.length,
    };
  }

  /**
   * Get search suggestions based on tags
   */
  static async getSearchSuggestions(userId: string, prefix: string) {
    if (!prefix || prefix.trim().length === 0) {
      throw new Error('Prefix cannot be empty');
    }

    const suggestions = await contentModel.aggregate([
      { $match: { userId: new mongoose.Types.ObjectId(userId) } },
      { $unwind: '$tags' },
      {
        $lookup: {
          from: 'tags',
          localField: 'tags',
          foreignField: '_id',
          as: 'tagInfo',
        },
      },
      { $unwind: '$tagInfo' },
      {
        $match: {
          'tagInfo.tag': { $regex: `^${prefix.trim()}`, $options: 'i' },
        },
      },
      {
        $group: {
          _id: '$tagInfo.tag',
          count: { $sum: 1 },
        },
      },
      { $sort: { count: -1 } },
      { $limit: 5 },
    ]);

    return suggestions.map(s => s._id);
  }

  /**
   * Process tags - create if they don't exist, or use existing ObjectIds
   */
  private static async processTags(tags: string[]): Promise<mongoose.Types.ObjectId[]> {
    if (!Array.isArray(tags) || tags.length === 0) {
      return [];
    }

    const tagIds: mongoose.Types.ObjectId[] = [];

    for (const tag of tags) {
      if (!tag || typeof tag !== 'string') continue;

      const trimmedTag = tag.trim();
      if (!trimmedTag) continue;

      // Check if it's an ObjectId string
      if (isValidObjectId(trimmedTag)) {
        // It's an ObjectId, use it directly
        tagIds.push(new mongoose.Types.ObjectId(trimmedTag));
      } else {
        // It's a tag name, find or create the tag
        let tagDoc = await tagModel.findOne({ tag: trimmedTag });

        if (!tagDoc) {
          tagDoc = await tagModel.create({ tag: trimmedTag });
        }

        tagIds.push(tagDoc._id as mongoose.Types.ObjectId);
      }
    }

    return tagIds;
  }

  /**
   * Index content to vector database (async, non-blocking)
   */
  private static indexContentAsync(
    contentId: string,
    userId: string,
    data: {
      title: string;
      description: string;
      type: string;
      link?: string;
      tags: string[];
      fullContent?: string;
    }
  ): void {
    addContentToVector(contentId, userId, data)
      .catch(err => {
        console.error(`Failed to index content ${contentId}:`, err);
        // Could add to a retry queue here
      });
  }

  /**
   * Update vector database (async, non-blocking)
   */
  private static updateVectorAsync(
    contentId: string,
    userId: string,
    data: {
      title: string;
      description: string;
      type: string;
      link?: string;
      tags: string[];
      fullContent?: string;
    }
  ): void {
    updateContentInVector(contentId, userId, data)
      .catch(err => {
        console.error(`Failed to update vector for content ${contentId}:`, err);
        // Could add to a retry queue here
      });
  }

  /**
   * Delete from vector database (async, non-blocking)
   */
  private static deleteVectorAsync(contentId: string): void {
    deleteContentFromVector(contentId)
      .catch(err => {
        console.error(`Failed to delete vector for content ${contentId}:`, err);
        // Could add to a retry queue here
      });
  }

  /**
   * Batch index all user content (for migration/sync)
   */
  static async reindexUserContent(userId: string): Promise<{
    indexed: number;
    failed: number;
  }> {
    const content = await contentModel
      .find({ userId })
      .populate('tags', 'tag')
      .lean() as any[];

    let indexed = 0;
    let failed = 0;

    for (const item of content) {
      try {
        // Use fullContent if available, otherwise description
        const searchableText = item.fullContent
          ? this.buildSearchableText(
              item.title || 'Untitled',
              item.description,
              item.fullContent,
              item.type,
              extractTagNames(item.tags as any[])
            )
          : item.description;

        await addContentToVector(
          item._id.toString(),
          userId,
          {
            title: item.title || 'Untitled',
            description: searchableText,
            type: item.type,
            link: item.link ?? undefined,
            tags: extractTagNames(item.tags as any[]),
            fullContent: item.fullContent || '',
          }
        );
        indexed++;
      } catch (error) {
        console.error(`Failed to index content ${item._id}:`, error);
        failed++;
      }
    }

    return { indexed, failed };
  }

  /**
   * Get processing statistics for monitoring
   */
  static async getProcessingStats(userId: string) {
    const stats = await contentModel.aggregate([
      { $match: { userId: new mongoose.Types.ObjectId(userId) } },
      {
        $group: {
          _id: '$processingStatus',
          count: { $sum: 1 }
        }
      }
    ]);

    const statsMap: Record<string, number> = {
      pending: 0,
      processing: 0,
      completed: 0,
      failed: 0
    };

    stats.forEach(stat => {
      if (stat._id) {
        statsMap[stat._id] = stat.count;
      }
    });

    return {
      ...statsMap,
      total: Object.values(statsMap).reduce((a, b) => a + b, 0),
      queueSize: processingQueue.getQueueSize(),
      isProcessing: processingQueue.isProcessing()
    };
  }

  /**
   * Migrate content where fullContent is empty but description contains full content
   * This fixes the issue where extraction failed but content was stored in description
   */
  static async migrateContentFromDescription(userId: string): Promise<{
    migrated: number;
    skipped: number;
    errors: number;
  }> {
    console.log(`🔄 Starting content migration for user ${userId}`);
    
    const contents = await contentModel.find({
      userId: new mongoose.Types.ObjectId(userId),
      $or: [
        { fullContent: { $exists: false } },
        { fullContent: '' },
        { fullContent: null }
      ]
    }).lean() as any[];

    let migrated = 0;
    let skipped = 0;
    let errors = 0;

    for (const content of contents) {
      try {
        // Skip migration - we no longer store fullContent in description
        console.log(`⏭️ Skipped content ${content._id}: Migration no longer needed`);
        skipped++;
      } catch (error) {
        console.error(`❌ Failed to migrate content ${content._id}:`, error);
        errors++;
      }
    }

    console.log(`✅ Migration completed: ${migrated} migrated, ${skipped} skipped, ${errors} errors`);
    
    return { migrated, skipped, errors };
  }
}