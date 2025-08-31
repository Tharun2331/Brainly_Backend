
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
import job from "./cron";
import {router} from "./Routes/BrainlyRouter";


const port= process.env.PORT || 3000;
const app = express();
app.use(express.json())
app.use(cors());
app.use("/api/v1",router)
dotenv.config();

const openAI = process.env.OPENAI_API_KEY ? new OpenAI({ apiKey: process.env.OPENAI_API_KEY }) : null;
if(process.env.NODE_ENV==="production") job.start();

app.get("/api/v1/health",(req,res)=> {
  res.status(200).json({message:"Server is running"})
})




  app.listen(port, ()=> {
    console.log(`Running on Port ${port}`)
  })

