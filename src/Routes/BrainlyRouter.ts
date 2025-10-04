// src/Routes/BrainlyRouter.ts
import { Router } from "express";
import { userMiddleware } from "../middleware";

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
  getNotes,
  getArticles,
  getTweets,
  getVideos,
  semanticSearch,
  getSearchSuggestions,
  reindexContent,
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

// ============================================
// Protected Routes (Authentication Required)
// ============================================

// Content Management
router.post("/content", userMiddleware, createContent);
router.get("/content", userMiddleware, getContent);
router.put("/content/:id", userMiddleware, updateContent);
router.delete("/content/:id", userMiddleware, deleteContent);

// Content by Type
router.get("/content/tweets", userMiddleware, getTweets);
router.get("/content/youtube", userMiddleware, getVideos);
router.get("/content/articles", userMiddleware, getArticles);
router.get("/content/notes", userMiddleware, getNotes);

// Search & Discovery
router.get("/search", userMiddleware, semanticSearch);
router.get("/search/suggestions", userMiddleware, getSearchSuggestions);

// Share Management
router.post("/brain/share", userMiddleware, createHash);
router.get("/brain/share/me", userMiddleware, getMyShareLink);
router.post("/brain/share/regenerate", userMiddleware, regenerateShareLink);

// Tag Management
router.post("/tags", userMiddleware, createTags);
router.get("/tags", userMiddleware, getUserTags);
router.get("/tags/popular", userMiddleware, getPopularTags);
router.get("/tags/search", userMiddleware, searchTags);
router.get("/tags/:tagName/content", userMiddleware, getContentByTag);
router.put("/tags/rename", userMiddleware, renameTag);
router.delete("/tags/unused", userMiddleware, deleteUnusedTags);

// User Account
router.post("/account/password", userMiddleware, changePassword);
router.delete("/account", userMiddleware, deleteAccount);

// Admin/Maintenance
router.post("/content/reindex", userMiddleware, reindexContent);