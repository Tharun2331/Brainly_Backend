declare global {
  namespace Express {
    export interface Request {
      userId?: string;
    }
  }
}

import express, { Request, Response } from "express";
import mongoose from "mongoose";
import jwt from "jsonwebtoken";
import { userMiddleware } from "../middleware";
import { contentModel, linkModel, tagModel, userModel } from "../db";
import {z} from "zod";
const USER_JWT_SECRET = process.env.USER_JWT_SECRET;
import bcrypt from "bcrypt";
import { Random } from "../utils";

export async function signupUser(req: Request, res: Response){
    try {
      const schema = z.object({
        username: z.string().min(3).max(10),
        password: z.string().min(8).max(20).regex(
          /^(?=.*[a-z])(?=.*[A-Z])(?=.*[!@#$%^&*])/,
          {
            message: "Password must contain lowercase, uppercase, and special character",
          }
        ),
      });
  
  
      const result = schema.safeParse(req.body);
  
      if (!result.success) {
        return res.status(411).json({
          message: "Invalid request body",
          errors: result.error.errors,
        });
      }
  
      const { username, password } = result.data;
  
      const existingUser = await userModel.findOne({ username });
      if (existingUser) {
        return res.status(403).json({ message: "Username already exists" });
      }
  
      const hashedPassword = await bcrypt.hash(password, 5);
  
      await userModel.create({ username, password: hashedPassword });
  
      return res.status(200).json({ message: "User Signed up!" });
    } catch (err) {
      return res.status(500).json({
        message: "Internal Server Error",
        error: err instanceof Error ? err.message : "Unknown error",
      });
    }
  };


 export async function signinUser(req: Request, res: Response) {
    const { username, password } = req.body;
    try {
      const user = await userModel.findOne({
        username
      });

      if (!user) {
        return res.status(404).json({
          message: "User not found",
        })
      }
      const isPasswordValid = await bcrypt.compare(password, user.password);
      if (!isPasswordValid) {
        return res.status(403).json({
          message:"Invalid password",
        })
      }
      else {
        const token = jwt.sign({
          id: user._id,
        },USER_JWT_SECRET as string)
        return res.status(200).json({
          message:"User signed in Successfully",
          token
        })
      }
    }
    catch (err) {
      return res.status(500).json({
        message: "Internal Server Error",
        error: err instanceof Error ? err.message : "Unknown error",
      });
    }
  }



 export async function createContent  (req: Request, res: Response) {
    try {
      const { link, type, title, tags = [], description } = req.body;
      
      // Validation
      if (!type || !['note', 'article', 'twitter','youtube'].includes(type)) {
        return res.status(400).json({ error: "Invalid or missing content type" });
      }
      
      if (type !== 'note' && !link) {
        return res.status(400).json({ error: "Link required for article/twitter content" });
      }
  
      const doc = await contentModel.create({
        link,
        title,
        description,
        type,
        userId: req.userId,
        tags,
        processingStatus: "pending"
      });
  
  
      return res.status(201).json({
        message: "Content added successfully",
        contentId: doc._id.toString()
      });
      
    } catch (error: any) {
      console.error('Failed to create content:', error);
      return res.status(500).json({ 
        error: "Failed to create content",
        details: error.message 
      });
    }
  }


  export async function getContent(req:Request, res: Response) {
      const userId = req.userId;
      const content = await contentModel.find({
       userId: userId
      }).populate("userId", "username").populate("tags", "tag");
 
      return res.status(200).json({
       content
      })
   }

export async function deleteContent(req:Request, res: Response){
  const contentId = req.params.id;
  const userId = req.userId;
  const results = await contentModel.deleteOne({
    _id:contentId,
    userId: userId
  })
  if(results.deletedCount === 0) {
    return res.status(404).json({
      message:"Content not found or you do not have permission to delete it"
    })
  }
  return res.status(200).json({
    message:"content deleted"
  })
};

export async function createHash(req:Request,res:Response) {
  try{
    
    const share= req.body.share;
    const userId = req.userId;
    const hash = Random(10);
    if(share === true || share === undefined) {
      const existingLink = await linkModel.findOne({
       userId: req.userId
      })
      if(existingLink) {
        return res.json({ 
          hash:existingLink.hash
        }) 
      }
      await linkModel.create({
      userId:userId,
      hash:hash
    });
    res.status(200).json({
      message: `/share/${hash}`
    })
    }
    else {
      await linkModel.deleteOne({
        userId:userId
      })
      res.status(403).json({
        message:"Removed Link!"
      })
    }

    }

    catch(err) {
       return res.status(500).json({
      message: "Could not generate share link",
      error: err instanceof Error ? err.message : "Unknown error",
    });
    }
  }

export async function getLink(req: Request, res: Response)
{
  try {
    const {shareLink} = req.params;
    const link = await linkModel.findOne({
      hash: shareLink
    })
    if(!link)
    {
      return res.status(404).json({
        message:"Share link not found!"
      })
    }
    // userId
    const content = await contentModel.find({
      userId: link.userId
    }).populate("tags","tag")
    
    const user = await userModel.findOne({
      _id: link.userId
    })

    console.log(link)
    if(!user) {
      return res.status(411).json({
        message: "User not found!"
      })
    }

    return res.status(200).json({
      message: "Content fetched Successfully!",
      username: user.username,
      content: content,
    })

  }
  catch(err){
    return res.status(500).json({
    message: "Failed to fetch shared content",
    error: err instanceof Error ? err.message : "Unknown error",
  });
  }
}

export async function createTags(req: Request, res:Response){
  const {tags} = req.body;
    if(!Array.isArray(tags) || tags.length === 0) {
      return res.status(400).json({
        message: "Tags must be a non-empty array"
      })
    }
    try{
      const tagIds = [];
      for(const tagText of tags)
      {
        let tagDoc = await tagModel.findOne({
          tag: tagText
        })

        if(!tagDoc)
        {
          tagDoc = await tagModel.create({
            tag: tagText
          });
        }
        tagIds.push(tagDoc._id);
      }
      return res.status(200).json({
        message: "Tags added successfully",
        tagIds
      })
    }
    catch(err) {
      return res.status(500).json({
        message: "Failed to add tags",
        error: err instanceof Error ? err.message : "Unknown error",
      });
    }

  }

  export async function getTweets(req:Request, res:Response){
    try {
      const userId = req.userId;
      const twitter = await contentModel.find({
        userId: userId,
        type: "twitter"
      }). populate("tags", "tag")
      res.status(200).json({
        message: "Tweets fetched successfully",
        twitter: twitter,
      });
    }

    catch (err) {
      return res.status(500).json({
        message: "Failed to fetch tweets",
        error: err instanceof Error ? err.message : "Unknown error",
      });
    }
  }

  export async function getVideos(req:Request, res: Response){
    try {
      const userId = req.userId;

      const youtubeVideos = await contentModel.find({
        userId: userId,
        type: "youtube"
      }).populate("tags", "tag")
      return res.status(200).json({
        message: "Youtube videos fetched successfully",
        youtubeVideos: youtubeVideos,
      });
    }
    catch (err) {
      return res.status(500).json({
        message: "Failed to fetch youtube videos",
        error: err instanceof Error ? err.message : "Unknown error",
      });
    }
  }

  export async function getArticles(req:Request, res:Response) {
    try {
      const userId = req.userId;
      const articles = await contentModel.find({
        userId: userId,
        type:"article",
      }).populate("tags","tag")
      return res.status(200).json({
        message: "Articles are fetched successfully",
        articles: articles
      });
    }
    catch(err){
      return res.status(500).json({
        message: "Failed to fetch articles",
        error: err instanceof Error ? err.message : "Unknown error",
      })
    }
  }
  

  export async function getNotes(req:Request, res: Response) {
    try {
      const notes = await contentModel.find({ userId: req.userId, type: "note" }).populate("tags", "tag");
      return res.status(200).json({ notes });
    } catch (err) {
      return res.status(500).json({
        message: "Failed to fetch notes",
        error: err instanceof Error ? err.message : "Unknown error",
      });
    }
  }
  

  export async function updateContent(req:Request, res:Response) {
  const { title, link, description, type, tags } = req.body;
  const contentId = req.params.id;
  const userId = req.userId;

  try {
    const content = await contentModel.findOneAndUpdate(
      { _id: contentId, userId: userId },
      { title, link, description, type, tags },
      { new: true, runValidators: true }
    );

    if (!content) {
      return res.status(404).json({
        message: "Content not found or you do not have permission to update it",
      });
    }

    const updatedContent = await contentModel
      .findById(content._id)
      .populate("tags", "tag")
      .populate("userId", "username");

    return res.status(200).json({
      message: "Content updated successfully",
      content: updatedContent,
    });
  } catch (err) {
    return res.status(500).json({
      message: "Failed to update content",
      error: err instanceof Error ? err.message : "Unknown error",
    });
  }
}