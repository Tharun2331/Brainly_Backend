// src/services/authService.ts
import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';
import { userModel } from '../db';

const USER_JWT_SECRET = process.env.USER_JWT_SECRET!;
const SALT_ROUNDS = 10;
const TOKEN_EXPIRY = '7d';

export interface SignupDTO {
  username: string;
  password: string;
}

export interface SigninDTO {
  username: string;
  password: string;
}

export class AuthService {
  /**
   * Register a new user
   */
  static async signup(data: SignupDTO) {
    const { username, password } = data;

    // Check if user already exists
    const existingUser = await userModel.findOne({ username });
    if (existingUser) {
      throw new Error('Username already taken');
    }

    // Hash password
    const hashedPassword = await bcrypt.hash(password, SALT_ROUNDS);

    // Create user
    const user = await userModel.create({
      username,
      password: hashedPassword,
    });

    return {
      userId: user._id.toString(),
      username: user.username,
    };
  }

  /**
   * Authenticate user and generate token
   */
  static async signin(data: SigninDTO) {
    const { username, password } = data;

    // Find user
    const user = await userModel.findOne({ username });
    if (!user) {
      throw new Error('Invalid credentials');
    }

    // Verify password
    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) {
      throw new Error('Invalid credentials');
    }

    // Generate JWT token
    const token = jwt.sign(
      { id: user._id.toString() },
      USER_JWT_SECRET,
      { expiresIn: TOKEN_EXPIRY }
    );

    return {
      token,
      username: user.username,
      userId: user._id.toString(),
    };
  }

  /**
   * Verify JWT token
   */
  static verifyToken(token: string): { id: string } {
    try {
      const decoded = jwt.verify(token, USER_JWT_SECRET) as { id: string };
      return decoded;
    } catch (error) {
      throw new Error('Invalid or expired token');
    }
  }

  /**
   * Get user by ID
   */
  static async getUserById(userId: string) {
    const user = await userModel.findById(userId).select('-password').lean();
    
    if (!user) {
      throw new Error('User not found');
    }

    return user;
  }

  /**
   * Change password
   */
  static async changePassword(
    userId: string,
    currentPassword: string,
    newPassword: string
  ) {
    const user = await userModel.findById(userId);
    
    if (!user) {
      throw new Error('User not found');
    }

    // Verify current password
    const isValid = await bcrypt.compare(currentPassword, user.password);
    if (!isValid) {
      throw new Error('Current password is incorrect');
    }

    // Hash new password
    const hashedPassword = await bcrypt.hash(newPassword, SALT_ROUNDS);

    // Update password
    user.password = hashedPassword;
    await user.save();

    return { success: true };
  }

  /**
   * Delete user account
   */
  static async deleteAccount(userId: string, password: string) {
    const user = await userModel.findById(userId);
    
    if (!user) {
      throw new Error('User not found');
    }

    // Verify password
    const isValid = await bcrypt.compare(password, user.password);
    if (!isValid) {
      throw new Error('Password is incorrect');
    }

    // Delete user
    await userModel.deleteOne({ _id: userId });

    return { success: true };
  }
}