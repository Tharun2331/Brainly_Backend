
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
import OpenAI from "openai";
import { Pinecone } from "@pinecone-database/pinecone";
const USER_JWT_SECRET = process.env.USER_JWT_SECRET
const port= process.env.PORT || 3000;
const app = express();
app.use(express.json())
app.use(cors());
dotenv.config();


// const openAI = new OpenAI({
//   apiKey: process.env.OPENAI_API
// });

// const pc = new Pinecone({
//   apiKey: process.env.PINECONE_API as string
// });

// const indexName= "chatbot";
// const PineConeIndex = async () => {
//   const existingIndexes = await pc.listIndexes();

//   // Check if index already exists
//   const indexExists = existingIndexes?.indexes?.some(idx => idx.name === indexName);

//   if (!indexExists) {
//     console.log(`Creating index: ${indexName}`);
//     await pc.createIndex({
//       name: indexName,
//       dimension: 1536, // for OpenAI's text-embedding-3-small
//       metric: "cosine",
//       spec: {
//         serverless: {
//           cloud: "aws",
//           region: "us-east-1"
//         }
//       }
//     });

//     // Wait for index to become ready
//     // Pinecone client may not have waitUntilReady; optionally poll for readiness or remove this line.
//     console.log(`Index "${indexName}" is now ready.`);
//   } else {
//     console.log(`Index "${indexName}" already exists.`);
//   }
// };

// // Load MongoDB content into vector DB
// const indexContent = async () => {
//   const index = pc.index(indexName).namespace("chatrag");
//   const mongoData = await contentModel.find().populate("tags", "tag");

//   const vectors = await Promise.all(
//     mongoData.map(async (data) => {
//       const chunkText = `${data.title || ""} ${data.description || ""} ${Array.isArray(data.tags) ? data.tags.map((t: any) => t.tag).join(", ") : ""}`.trim();

//       // Embed using OpenAI (you could also pre-compute this)
//       const embeddingResponse = await openAI.embeddings.create({
//         model: "text-embedding-3-small",
//         input: chunkText,
//       });

//       return {
//         id: data._id.toString(),
//         values: embeddingResponse.data[0].embedding,
//         metadata: {
//           link: data.link || "",
//           type: data.type || "",
//           originalTitle: data.title || "",
//           originalDescription: data.description || "",
//           originalTags: Array.isArray(data.tags)
//         },
//       };
//     })
//   );

//   await index.upsert(vectors);
// };

// export {PineConeIndex,indexContent}


// app.post("/api/v1/ai-query", userMiddleware, async (req:Request,res:Response)=> {
//   try{
//     const {query} = req.body;
//     if(!query)
//     {
//       return res.status(400).json({
//         message: "Query is required!"
//       })
//     }

//     const index = pc.index(indexName).namespace("chatrag");

//     const embeddingResponse = await openAI.embeddings.create({
//       model: "text-embedding-3-small",
//       input:query
//     });

//     const queryEmbedding = embeddingResponse.data[0].embedding;

//     const result = await index.query({
//       topK:5,
//       vector: queryEmbedding,
//       includeMetadata:true,
//     });

//     return res.status(200).json({
//       message: "Success",
//       results: result.matches,
//     });
//   }
//   catch (error) {
//     console.error("Query Error:", error);
//     return res.status(500).json({ message: "Internal Server Error" });
//   }
// })

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
      const {link,type,title,tags=[],description} = req.body;
      await contentModel.create({
        link,
        title,
        description,
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
  })

  app.get("/api/v1/content/youtube", userMiddleware, async (req,res)=> {
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
  });

app.get("/api/v1/content/articles", userMiddleware, async (req: Request, res: Response) => {
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
})

app.get("/api/v1/content/notes", userMiddleware, async (req, res) => {
  try {
    const notes = await contentModel.find({ type: "note" }).populate("tags");
    return res.status(200).json({ notes });
  } catch (err) {
    return res.status(500).json({
      message: "Failed to fetch notes",
      error: err instanceof Error ? err.message : "Unknown error",
    });
  }
})

app.put("/api/v1/content/:id", userMiddleware, async (req, res) => {
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
});

  app.listen(port, ()=> {
    console.log(`Running on Port ${port}`)
  })

