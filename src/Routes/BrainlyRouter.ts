// src/Routes/BrainlyRouter.ts
import { Router } from "express";
import { userMiddleware } from "../middleware";
import { chatMessage, getChatSuggestions } from '../controllers/ChatController';
// Auth Controllers
import {
  signupUser,
  signinUser,
  verifyToken,
  changePassword,
  deleteAccount,
} from "../controllers/AuthController";

// Content Controllers
import {
  createContent,
  updateContent,
  deleteContent,
  getContent,
  getContentById,
  getNotes,
  getArticles,
  getTweets,
  getVideos,
  semanticSearch,
  getSearchSuggestions,
  reindexContent,
  // NEW: Processing endpoints
  reprocessContent,
  getQueueStatus,
  getProcessingStats,
  batchReprocessContent,
  getFailedContent,
  getPendingContent,
  processingHealthCheck,
  migrateContentFromDescription,
  reprocessTweetContent,
} from "../controllers/ContentController";

// Share Controllers
import {
  createHash,
  getLink,
  getMyShareLink,
  regenerateShareLink,
} from "../controllers/ShareController";

// Tag Controllers
import {
  createTags,
  getUserTags,
  getPopularTags,
  getContentByTag,
  searchTags,
  renameTag,
  deleteUnusedTags,
} from "../controllers/TagController";

export const router = Router();

// ============================================
// Public Routes (No Authentication Required)
// ============================================

// Auth
router.post("/signup", signupUser);
router.post("/signin", signinUser);
router.get("/verify", verifyToken);

// Share (public)
router.get("/brain/:shareLink", getLink);

// Health check (public)
router.get("/health/processing", processingHealthCheck);

// ============================================
// Protected Routes (Authentication Required)
// ============================================

// Content Management
router.post("/content", userMiddleware, createContent);
router.get("/content", userMiddleware, getContent);

// Content by Type (must come before /content/:id)
router.get("/content/tweets", userMiddleware, getTweets);
router.get("/content/youtube", userMiddleware, getVideos);
router.get("/content/articles", userMiddleware, getArticles);
router.get("/content/notes", userMiddleware, getNotes);

// Content by ID (must come after specific routes)
router.get("/content/:id", userMiddleware, getContentById);
router.put("/content/:id", userMiddleware, updateContent);
router.delete("/content/:id", userMiddleware, deleteContent);

// Search & Discovery
router.get("/search", userMiddleware, semanticSearch);
router.get("/search/suggestions", userMiddleware, getSearchSuggestions);

// ============================================
// NEW: Content Processing Endpoints
// ============================================

// Reprocess single content
router.post("/content/:id/reprocess", userMiddleware, reprocessContent);

// Batch reprocess multiple content items
router.post("/content/reprocess/batch", userMiddleware, batchReprocessContent);

// Get queue status
router.get("/processing/queue", userMiddleware, getQueueStatus);

// Get processing statistics
router.get("/processing/stats", userMiddleware, getProcessingStats);

// Get failed content
router.get("/content/failed", userMiddleware, getFailedContent);

// Get pending content
router.get("/content/pending", userMiddleware, getPendingContent);

// Reindex all content (admin)
router.post("/content/reindex", userMiddleware, reindexContent);

// Migrate content from description to fullContent field
router.post("/content/migrate", userMiddleware, migrateContentFromDescription);

// Reprocess tweet content specifically
router.post("/content/:id/reprocess-tweet", userMiddleware, reprocessTweetContent);

// ============================================
// Share Management
// ============================================
router.post("/brain/share", userMiddleware, createHash);
router.get("/brain/share/me", userMiddleware, getMyShareLink);
router.post("/brain/share/regenerate", userMiddleware, regenerateShareLink);

// ============================================
// Tag Management
// ============================================
router.post("/tags", userMiddleware, createTags);
router.get("/tags", userMiddleware, getUserTags);
router.get("/tags/popular", userMiddleware, getPopularTags);
router.get("/tags/search", userMiddleware, searchTags);
router.get("/tags/:tagName/content", userMiddleware, getContentByTag);
router.put("/tags/rename", userMiddleware, renameTag);
router.delete("/tags/unused", userMiddleware, deleteUnusedTags);

// ============================================
// User Account
// ============================================
router.post("/account/password", userMiddleware, changePassword);
router.delete("/account", userMiddleware, deleteAccount);


// Add these routes in the protected section
router.post('/chat', userMiddleware, chatMessage);
router.get('/chat/suggestions', userMiddleware, getChatSuggestions);