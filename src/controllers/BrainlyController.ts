// src/controllers/BrainlyController.ts (Updated methods)
import { Request, Response, NextFunction } from "express";
import { z } from "zod";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import { userModel, contentModel, linkModel, tagModel } from "../db";
import { 
  sendErrorResponse, 
  sendSuccessResponse, 
  formatZodError 
} from "../utils/errorHandler";
import { Random } from "../utils/hashUtils";

const USER_JWT_SECRET = process.env.USER_JWT_SECRET;

// Validation schemas
const signupSchema = z.object({
  username: z
    .string()
    .min(3, "Username must be at least 3 characters")
    .max(20, "Username cannot exceed 20 characters")
    .regex(/^[a-zA-Z0-9_]+$/, "Username can only contain letters, numbers, and underscores"),
  password: z
    .string()
    .min(8, "Password must be at least 8 characters")
    .max(20, "Password cannot exceed 20 characters")
    .regex(
      /^(?=.*[a-z])(?=.*[A-Z])(?=.*[!@#$%^&*])/,
      "Password must contain at least one lowercase letter, one uppercase letter, and one special character"
    ),
});

const signinSchema = z.object({
  username: z.string().min(1, "Username is required"),
  password: z.string().min(1, "Password is required"),
});

const contentSchema = z.object({
  link: z.string().url("Invalid URL format").optional(),
  type: z.enum(["note", "article", "twitter", "youtube"], {
    errorMap: () => ({ message: "Invalid content type" }),
  }),
  title: z.string().min(1, "Title is required").max(200, "Title is too long"),
  description: z.string().min(1, "Description is required").max(5000, "Description is too long"),
  tags: z.array(z.string()).min(1, "At least one tag is required").optional(),
});

export async function signupUser(req: Request, res: Response, next: NextFunction) {
  try {
    // Validate request body
    const result = signupSchema.safeParse(req.body);
    
    if (!result.success) {
      return sendErrorResponse(
        res,
        400,
        "Please correct the following errors",
        formatZodError(result.error),
        "VALIDATION_ERROR"
      );
    }

    const { username, password } = result.data;

    // Check if user exists
    const existingUser = await userModel.findOne({ username });
    if (existingUser) {
      return sendErrorResponse(
        res,
        409,
        "Username already taken",
        { username: "This username is already registered" },
        "DUPLICATE_USER"
      );
    }

    // Hash password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Create user
    const newUser = await userModel.create({ 
      username, 
      password: hashedPassword 
    });

    return sendSuccessResponse(
      res,
      201,
      "Account created successfully! Please sign in.",
      { userId: newUser._id, username: newUser.username }
    );
  } catch (error) {
    next(error);
  }
}

export async function signinUser(req: Request, res: Response, next: NextFunction) {
  try {
    // Validate request body
    const result = signinSchema.safeParse(req.body);
    
    if (!result.success) {
      return sendErrorResponse(
        res,
        400,
        "Please provide valid credentials",
        formatZodError(result.error),
        "VALIDATION_ERROR"
      );
    }

    const { username, password } = result.data;

    // Find user
    const user = await userModel.findOne({ username });
    if (!user) {
      return sendErrorResponse(
        res,
        401,
        "Invalid credentials",
        { username: "Username or password is incorrect" },
        "AUTH_FAILED"
      );
    }

    // Verify password
    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) {
      return sendErrorResponse(
        res,
        401,
        "Invalid credentials",
        { password: "Username or password is incorrect" },
        "AUTH_FAILED"
      );
    }

    // Generate token
    const token = jwt.sign(
      { id: user._id },
      USER_JWT_SECRET as string,
      { expiresIn: "7d" }
    );

    return sendSuccessResponse(
      res,
      200,
      "Signed in successfully!",
      { token, username: user.username }
    );
  } catch (error) {
    next(error);
  }
}

export async function createContent(req: Request, res: Response, next: NextFunction) {
  try {
    const { link, type, title, tags = [], description } = req.body;
    
    // Validate based on content type
    if (type !== 'note' && !link) {
      return sendErrorResponse(
        res,
        400,
        "Link is required for this content type",
        { link: "Please provide a valid link" },
        "VALIDATION_ERROR"
      );
    }

    // Additional validation for specific types
    if (type === 'youtube' && link) {
      const youtubeRegex = /^(https?:\/\/)?(www\.)?(youtube\.com|youtu\.be)\/.+$/;
      if (!youtubeRegex.test(link)) {
        return sendErrorResponse(
          res,
          400,
          "Invalid YouTube URL",
          { link: "Please provide a valid YouTube link" },
          "INVALID_URL"
        );
      }
    }

    if (type === 'twitter' && link) {
      const twitterRegex = /^(https?:\/\/)?(www\.)?(twitter\.com|x\.com)\/.+$/;
      if (!twitterRegex.test(link)) {
        return sendErrorResponse(
          res,
          400,
          "Invalid Twitter/X URL",
          { link: "Please provide a valid Twitter/X link" },
          "INVALID_URL"
        );
      }
    }

    // Create content
    const content = await contentModel.create({
      link,
      title,
      description,
      type,
      userId: req.userId,
      tags,
    });

    const populatedContent = await contentModel
      .findById(content._id)
      .populate("tags", "tag");

    return sendSuccessResponse(
      res,
      201,
      "Content created successfully!",
      populatedContent
    );
  } catch (error) {
    next(error);
  }
}

export async function updateContent(req: Request, res: Response, next: NextFunction) {
  try {
    const { title, link, description, type, tags } = req.body;
    const contentId = req.params.id;
    const userId = req.userId;

    // Validate content ID
    if (!contentId.match(/^[0-9a-fA-F]{24}$/)) {
      return sendErrorResponse(
        res,
        400,
        "Invalid content ID",
        undefined,
        "INVALID_ID"
      );
    }

    // Find and update content
    const content = await contentModel.findOneAndUpdate(
      { _id: contentId, userId: userId },
      { title, link, description, type, tags },
      { new: true, runValidators: true }
    );

    if (!content) {
      return sendErrorResponse(
        res,
        404,
        "Content not found",
        undefined,
        "NOT_FOUND"
      );
    }

    const updatedContent = await contentModel
      .findById(content._id)
      .populate("tags", "tag");

    return sendSuccessResponse(
      res,
      200,
      "Content updated successfully!",
      updatedContent
    );
  } catch (error) {
    next(error);
  }
}

export async function deleteContent(req: Request, res: Response, next: NextFunction) {
  try {
    const contentId = req.params.id;
    const userId = req.userId;

    // Validate content ID
    if (!contentId.match(/^[0-9a-fA-F]{24}$/)) {
      return sendErrorResponse(
        res,
        400,
        "Invalid content ID",
        undefined,
        "INVALID_ID"
      );
    }

    const result = await contentModel.deleteOne({
      _id: contentId,
      userId: userId,
    });

    if (result.deletedCount === 0) {
      return sendErrorResponse(
        res,
        404,
        "Content not found or already deleted",
        undefined,
        "NOT_FOUND"
      );
    }

    return sendSuccessResponse(
      res,
      200,
      "Content deleted successfully!"
    );
  } catch (error) {
    next(error);
  }
}

export async function getContent(req: Request, res: Response, next: NextFunction) {
  try {
    const userId = req.userId;
    
    const content = await contentModel
      .find({ userId })
      .populate("userId", "username")
      .populate("tags", "tag")
      .sort({ createdAt: -1 });

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

export async function getNotes(req: Request, res: Response, next: NextFunction) {
  try {
    const userId = req.userId;
    
    const notes = await contentModel
      .find({ userId, type: "note" })
      .populate("tags", "tag")
      .sort({ createdAt: -1 });

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

export async function getArticles(req: Request, res: Response, next: NextFunction) {
  try {
    const userId = req.userId;
    
    const articles = await contentModel
      .find({ userId, type: "article" })
      .populate("tags", "tag")
      .sort({ createdAt: -1 });

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

export async function getTweets(req: Request, res: Response, next: NextFunction) {
  try {
    const userId = req.userId;
    
    const tweets = await contentModel
      .find({ userId, type: "twitter" })
      .populate("tags", "tag")
      .sort({ createdAt: -1 });

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

export async function getVideos(req: Request, res: Response, next: NextFunction) {
  try {
    const userId = req.userId;
    
    const videos = await contentModel
      .find({ userId, type: "youtube" })
      .populate("tags", "tag")
      .sort({ createdAt: -1 });

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

export async function createHash(req: Request, res: Response, next: NextFunction) {
  try {
    const { share } = req.body;
    const userId = req.userId;

    if (share === true || share === undefined) {
      // Check if user already has a share link
      const existingLink = await linkModel.findOne({ userId });
      
      if (existingLink) {
        return sendSuccessResponse(
          res,
          200,
          "Share link retrieved successfully!",
          { hash: existingLink.hash, shareUrl: `/share/${existingLink.hash}` }
        );
      }

      // Create new share link
      const hash = Random(10);
      await linkModel.create({
        userId,
        hash
      });

      return sendSuccessResponse(
        res,
        200,
        "Share link created successfully!",
        { hash, shareUrl: `/share/${hash}` }
      );
    } else {
      // Remove share link
      await linkModel.deleteOne({ userId });
      
      return sendSuccessResponse(
        res,
        200,
        "Share link removed successfully!"
      );
    }
  } catch (error) {
    next(error);
  }
}

export async function getLink(req: Request, res: Response, next: NextFunction) {
  try {
    const { shareLink } = req.params;

    // Find the share link
    const link = await linkModel.findOne({ hash: shareLink });
    
    if (!link) {
      return sendErrorResponse(
        res,
        404,
        "Share link not found",
        undefined,
        "NOT_FOUND"
      );
    }

    // Get user info
    const user = await userModel.findById(link.userId);
    if (!user) {
      return sendErrorResponse(
        res,
        404,
        "User not found",
        undefined,
        "USER_NOT_FOUND"
      );
    }

    // Get user's content
    const content = await contentModel
      .find({ userId: link.userId })
      .populate("tags", "tag")
      .sort({ createdAt: -1 });

    return sendSuccessResponse(
      res,
      200,
      "Shared content fetched successfully!",
      {
        username: user.username,
        content
      }
    );
  } catch (error) {
    next(error);
  }
}

export async function createTags(req: Request, res: Response, next: NextFunction) {
  try {
    const { tags } = req.body;

    // Validate tags
    if (!Array.isArray(tags) || tags.length === 0) {
      return sendErrorResponse(
        res,
        400,
        "Tags must be a non-empty array",
        { tags: "Please provide at least one tag" },
        "VALIDATION_ERROR"
      );
    }

    const tagIds = [];
    
    for (const tagText of tags) {
      // Check if tag already exists
      let tagDoc = await tagModel.findOne({ tag: tagText });
      
      if (!tagDoc) {
        // Create new tag
        tagDoc = await tagModel.create({ tag: tagText });
      }
      
      tagIds.push(tagDoc._id);
    }

    return sendSuccessResponse(
      res,
      200,
      "Tags processed successfully!",
      { tagIds }
    );
  } catch (error) {
    next(error);
  }
}