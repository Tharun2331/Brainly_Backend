
import express, { Request, Response } from "express";
import mongoose from "mongoose";
import jwt from "jsonwebtoken";
import { contentModel, linkModel, tagModel, userModel } from "../db";
import {z} from "zod";
import dotenv from "dotenv";
import bcrypt from "bcrypt";
import { userMiddleware } from "../middleware";
import crypto from "crypto";
import { Random } from "../utils";
import cors from "cors";
import OpenAI from "openai";
import { Router } from "express";
import { signupUser, signinUser, createContent, getContent, deleteContent, createHash, getLink, createTags, getTweets, getVideos, getArticles, getNotes, updateContent } from "../controllers/BrainlyController";
const USER_JWT_SECRET = process.env.USER_JWT_SECRET
export const router = Router();



router.post("/signup", signupUser);
router.post("/signin", signinUser)
router.post("/content", userMiddleware, createContent);
router.get("/content", userMiddleware, getContent);
router.delete("/content/:id",userMiddleware, deleteContent)
router.post("/brain/share", userMiddleware, createHash)
router.get("/brain/:shareLink", getLink)
router.post("/tags", userMiddleware, createTags);
router.get("/content/tweets", userMiddleware, getTweets)
router.get("/content/youtube", userMiddleware, getVideos);
router.get("/content/articles", userMiddleware, getArticles)
router.get("/content/notes", userMiddleware, getNotes)
router.put("/content/:id", userMiddleware, updateContent);