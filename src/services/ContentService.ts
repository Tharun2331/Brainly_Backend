// src/services/contentService.ts
import { contentModel, tagModel } from '../db';
import {
  addContentToVector,
  updateContentInVector,
  deleteContentFromVector,
  searchContent,
} from './PineconeService';
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

    // Create tag references
    const tagIds = await this.processTags(tags);

    // Create content
    const content = await contentModel.create({
      link,
      title: title || (type === 'note' ? 'Untitled Note' : ''),
      description,
      type,
      userId,
      tags: tagIds,
    });

    // Get populated content
    const populatedContent = await contentModel
      .findById(content._id)
      .populate('tags', 'tag')
      .populate('userId', 'username')
      .lean();

    if (!populatedContent) {
      throw new Error('Failed to retrieve created content');
    }

    // Add to vector database asynchronously (don't block)
    this.indexContentAsync(content._id.toString(), userId, {
      title: populatedContent.title || 'Untitled',
      description: populatedContent.description,
      type: populatedContent.type,
      link: populatedContent.link ?? undefined,
      tags: extractTagNames(populatedContent.tags as any[]),
    }); 

    return populatedContent;
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
      .lean();

    if (!populatedContent) {
      throw new Error('Failed to retrieve updated content');
    }

    // Update vector database asynchronously
    this.updateVectorAsync(contentId, userId, {
      title: populatedContent.title || 'Untitled',
      description: populatedContent.description,
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
   * Get content by type
   */
  static async getContentByType(
    userId: string,
    type: 'twitter' | 'youtube' | 'article' | 'note'
  ) {
    const content = await contentModel
      .find({ userId, type })
      .populate('tags', 'tag')
      .populate('userId', 'username')
      .sort({ createdAt: -1 })
      .lean();

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
      .lean();

    let indexed = 0;
    let failed = 0;

    for (const item of content) {
      try {
        await addContentToVector(
          item._id.toString(),
          userId,
          {
            title: item.title || 'Untitled',
            description: item.description,
            type: item.type,
            link: item.link ?? undefined,
            tags: extractTagNames(item.tags as any[]),
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
}