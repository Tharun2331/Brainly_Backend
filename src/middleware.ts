import { NextFunction, Request, Response } from "express";
import jwt, {JwtPayload} from "jsonwebtoken"
import dotenv from "dotenv";
dotenv.config();

const JWT_SECRET = process.env.USER_JWT_SECRET;

export const userMiddleware = (req:Request, res: Response, next: NextFunction) => {
  const header = req.headers["authorization"];
  const decoded = jwt.verify(header as string,JWT_SECRET as string)
  if (decoded)
  { 
    req.userId = (decoded as JwtPayload).id;
    next();
  }
  else {
    res.status(403).json({
      message:"You are not logged in!"
    })
  }

}