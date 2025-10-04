// src/services/tagService.ts
import { tagModel, contentModel } from '../db';
import mongoose from 'mongoose';

export class TagService {
  /**
   * Create tags (find or create)
   */
  static async createTags(tagNames: string[]) {
    if (!Array.isArray(tagNames) || tagNames.length === 0) {
      throw new Error('Tags must be a non-empty array');
    }

    const tagIds: mongoose.Types.ObjectId[] = [];

    for (const tagName of tagNames) {
      if (!tagName || typeof tagName !== 'string') {
        continue;
      }

      const trimmedTag = tagName.trim();
      if (!trimmedTag) {
        continue;
      }

      // Find or create tag
      let tag = await tagModel.findOne({ tag: trimmedTag });

      if (!tag) {
        tag = await tagModel.create({ tag: trimmedTag });
      }

      tagIds.push(tag._id as mongoose.Types.ObjectId);
    }

    if (tagIds.length === 0) {
      throw new Error('No valid tags provided');
    }

    return tagIds;
  }

  /**
   * Get all tags for a user
   */
  static async getUserTags(userId: string) {
    const tags = await contentModel.aggregate([
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
        $group: {
          _id: '$tagInfo._id',
          tag: { $first: '$tagInfo.tag' },
          count: { $sum: 1 },
        },
      },
      { $sort: { count: -1 } },
    ]);

    return tags.map(t => ({
      _id: t._id,
      tag: t.tag,
      count: t.count,
    }));
  }

  /**
   * Get popular tags (most used)
   */
  static async getPopularTags(limit: number = 10) {
    const tags = await contentModel.aggregate([
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
        $group: {
          _id: '$tagInfo._id',
          tag: { $first: '$tagInfo.tag' },
          count: { $sum: 1 },
        },
      },
      { $sort: { count: -1 } },
      { $limit: limit },
    ]);

    return tags.map(t => ({
      _id: t._id,
      tag: t.tag,
      count: t.count,
    }));
  }

  /**
   * Get content by tag
   */
  static async getContentByTag(userId: string, tagName: string) {
    const tag = await tagModel.findOne({ tag: tagName });

    if (!tag) {
      return [];
    }

    const content = await contentModel
      .find({
        userId,
        tags: tag._id,
      })
      .populate('tags', 'tag')
      .populate('userId', 'username')
      .sort({ createdAt: -1 })
      .lean();

    return content;
  }

  /**
   * Search tags by prefix
   */
  static async searchTags(userId: string, prefix: string, limit: number = 10) {
    const tags = await contentModel.aggregate([
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
          'tagInfo.tag': { $regex: `^${prefix}`, $options: 'i' },
        },
      },
      {
        $group: {
          _id: '$tagInfo._id',
          tag: { $first: '$tagInfo.tag' },
          count: { $sum: 1 },
        },
      },
      { $sort: { count: -1 } },
      { $limit: limit },
    ]);

    return tags.map(t => ({
      _id: t._id,
      tag: t.tag,
      count: t.count,
    }));
  }

  /**
   * Delete unused tags (cleanup)
   */
  static async deleteUnusedTags() {
    // Find all tags that are not referenced by any content
    const allTags = await tagModel.find().lean();
    const deletedTags: string[] = [];

    for (const tag of allTags) {
      const contentCount = await contentModel.countDocuments({
        tags: tag._id,
      });

      if (contentCount === 0) {
        await tagModel.deleteOne({ _id: tag._id });
        deletedTags.push(tag.tag);
      }
    }

    return {
      deletedCount: deletedTags.length,
      deletedTags,
    };
  }

  /**
   * Rename a tag
   */
  static async renameTag(userId: string, oldTagName: string, newTagName: string) {
    const oldTag = await tagModel.findOne({ tag: oldTagName });

    if (!oldTag) {
      throw new Error('Tag not found');
    }

    // Check if new tag name already exists
    const existingTag = await tagModel.findOne({ tag: newTagName });

    if (existingTag) {
      // Merge tags: update all content to use existing tag
      await contentModel.updateMany(
        { userId, tags: oldTag._id },
        { $set: { 'tags.$': existingTag._id } }
      );

      // Delete old tag
      await tagModel.deleteOne({ _id: oldTag._id });

      return {
        merged: true,
        tag: existingTag,
      };
    }

    // Simply rename the tag
    oldTag.tag = newTagName;
    await oldTag.save();

    return {
      merged: false,
      tag: oldTag,
    };
  }
}