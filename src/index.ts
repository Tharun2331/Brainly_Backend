
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
import { contentModel, linkModel, tagModel, userModel } from "./db";
import {z} from "zod";
import dotenv from "dotenv";
import bcrypt from "bcrypt";
import { userMiddleware } from "./middleware";
import crypto from "crypto";
import { Random } from "./utils";
import cors from "cors";
const USER_JWT_SECRET = process.env.USER_JWT_SECRET
const port= process.env.PORT || 3000;
const app = express();
app.use(express.json())
app.use(cors());
dotenv.config();


app.post("/api/v1/signup", async (req: Request, res: Response) => {
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
});



  app.post("/api/v1/signin", async (req, res) => {
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
  })

  app.post("/api/v1/content", userMiddleware, async (req,res)=> {
      const {link,type,title,tags=[]} = req.body;
      await contentModel.create({
        link,
        title,
        type,
        userId: req.userId,
        tags
      })
      return res.status(200).json({
        message:"content added"
      })
  })  

  app.get("/api/v1/content", userMiddleware, async (req,res)=> {
     const userId = req.userId;
     const content = await contentModel.find({
      userId: userId
     }).populate("userId", "username").populate("tags", "tag");

     return res.status(200).json({
      content
     })
  })

  app.delete("/api/v1/content/:id",userMiddleware, async (req,res)=> {
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
  })

  app.post("/api/v1/brain/share", userMiddleware, async (req,res)=> {
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
  })

  app.get("/api/v1/brain/:shareLink", async (req,res)=> {
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
  })


  app.post("/api/v1/tags", userMiddleware, async (req,res)=> {
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

  );

  app.get("/api/v1/content/tweets", userMiddleware, async (req, res) => {
    try {
      const userId = req.userId;
      const twitter = await contentModel.find({
        userId: userId,
        type: "twitter"
      }). populate("tags", "tag").populate("userId", "username");
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
  })

  app.get("/api/v1/content/youtube", userMiddleware, async (req,res)=> {
    try {
      const userId = req.userId;

      const youtubeVideos = await contentModel.find({
        userId: userId,
        type: "youtube"
      }).populate("tags", "tag").populate("userId", "username");
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
  });
 

  

  app.listen(port, ()=> {
    console.log(`Running on Port ${port}`)
  })

