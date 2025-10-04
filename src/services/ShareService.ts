// src/services/shareService.ts
import { linkModel, userModel, contentModel } from '../db';
import { Random } from '../utils/hashUtils';

export class ShareService {
  /**
   * Generate or retrieve share link for user
   */
  static async createShareLink(userId: string) {
    // Check if user already has a share link
    const existingLink = await linkModel.findOne({ userId });

    if (existingLink) {
      return {
        hash: existingLink.hash,
        shareUrl: `/share/${existingLink.hash}`,
      };
    }

    // Generate new hash
    const hash = Random(10);

    // Create share link
    await linkModel.create({
      userId,
      hash,
    });

    return {
      hash,
      shareUrl: `/share/${hash}`,
    };
  }

  /**
   * Remove share link for user
   */
  static async removeShareLink(userId: string) {
    const result = await linkModel.deleteOne({ userId });

    if (result.deletedCount === 0) {
      throw new Error('No share link found to remove');
    }

    return { success: true };
  }

  /**
   * Get shared content by hash
   */
  static async getSharedContent(shareHash: string) {
    // Find the share link
    const link = await linkModel.findOne({ hash: shareHash });

    if (!link) {
      throw new Error('Share link not found');
    }

    // Get user info
    const user = await userModel.findById(link.userId).select('username').lean();

    if (!user) {
      throw new Error('User not found');
    }

    // Get user's content
    const content = await contentModel
      .find({ userId: link.userId })
      .populate('tags', 'tag')
      .sort({ createdAt: -1 })
      .lean();

    return {
      username: user.username,
      content,
    };
  }

  /**
   * Get user's current share link if it exists
   */
  static async getUserShareLink(userId: string) {
    const link = await linkModel.findOne({ userId }).lean();

    if (!link) {
      return null;
    }

    return {
      hash: link.hash,
      shareUrl: `/share/${link.hash}`,
    };
  }

  /**
   * Check if a share link exists
   */
  static async shareLinkExists(shareHash: string) {
    const link = await linkModel.findOne({ hash: shareHash }).lean();
    return !!link;
  }

  /**
   * Regenerate share link (useful for security)
   */
  static async regenerateShareLink(userId: string) {
    // Delete old link
    await linkModel.deleteOne({ userId });

    // Create new one
    return this.createShareLink(userId);
  }
}