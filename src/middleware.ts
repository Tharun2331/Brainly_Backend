import { NextFunction, Request, Response } from "express";
import jwt, {JwtPayload} from "jsonwebtoken"
import dotenv from "dotenv";
dotenv.config();

const JWT_SECRET = process.env.USER_JWT_SECRET;

export const userMiddleware = (req:Request, res: Response, next: NextFunction) => {
  try {
    const header = req.headers["authorization"];
    if (!header) {
      return res.status(401).json({ message: "Missing Authorization header" });
    }

    const [scheme, token] = header.split(" ");
    const jwtToken = scheme?.toLowerCase() === "bearer" ? token : header;

    if (!jwtToken) {
      return res.status(401).json({ message: "Invalid Authorization header format" });
    }

    const decoded = jwt.verify(jwtToken, JWT_SECRET as string);
    req.userId = (decoded as JwtPayload).id;
    return next();
  } catch {
    return res.status(401).json({ message: "Invalid or expired token" });
  }
}