// src/controllers/ChatController.ts
import { Request, Response, NextFunction } from 'express';
import { ChatService } from '../services/ChatService';
import { sendErrorResponse } from '../utils/errorHandler';

/**
 * Handle chat message with streaming response
 */
export async function chatMessage(
  req: Request,
  res: Response,
  next: NextFunction
) {
  try {
    const userId = req.userId!;
    const { message, conversationHistory = [] } = req.body;

    // Validate input
    if (!message || typeof message !== 'string' || message.trim().length === 0) {
      return sendErrorResponse(
        res,
        400,
        'Message is required',
        { message: 'Please provide a valid message' },
        'VALIDATION_ERROR'
      );
    }

    if (message.length > 1000) {
      return sendErrorResponse(
        res,
        400,
        'Message too long',
        { message: 'Message must be less than 1000 characters' },
        'VALIDATION_ERROR'
      );
    }

    // Validate conversation history
    if (!Array.isArray(conversationHistory)) {
      return sendErrorResponse(
        res,
        400,
        'Invalid conversation history',
        { conversationHistory: 'Must be an array' },
        'VALIDATION_ERROR'
      );
    }

    // Limit conversation history to prevent token overflow
    const limitedHistory = conversationHistory.slice(-10); // Keep last 10 messages

    console.log(`💬 Chat request from user ${userId}: "${message.substring(0, 50)}..."`);

    // Set up SSE (Server-Sent Events) headers
    res.setHeader('Content-Type', 'text/event-stream');
    res.setHeader('Cache-Control', 'no-cache');
    res.setHeader('Connection', 'keep-alive');
    res.setHeader('X-Accel-Buffering', 'no'); // Disable buffering in nginx

    // Get streaming response
    const { stream, sources } = await ChatService.chatStream({
      userId,
      message: message.trim(),
      conversationHistory: limitedHistory
    });

    // Send sources first
    res.write(`data: ${JSON.stringify({ 
      type: 'sources', 
      sources 
    })}\n\n`);

    // Stream the response
    let fullMessage = '';
    try {
      for await (const chunk of stream) {
        const content = chunk.choices[0]?.delta?.content || '';
        
        if (content) {
          fullMessage += content;
          res.write(`data: ${JSON.stringify({ 
            type: 'token', 
            content 
          })}\n\n`);
        }

        // Check if stream is finished
        if (chunk.choices[0]?.finish_reason === 'stop') {
          break;
        }
      }

      // Send completion signal
      res.write(`data: ${JSON.stringify({ 
        type: 'done',
        fullMessage 
      })}\n\n`);

      console.log(`✅ Chat response sent (${fullMessage.length} chars)`);

    } catch (streamError) {
      console.error('❌ Streaming error:', streamError);
      res.write(`data: ${JSON.stringify({ 
        type: 'error', 
        message: 'Stream interrupted' 
      })}\n\n`);
    }

    res.end();

  } catch (error: any) {
    console.error('❌ Chat error:', error);
    
    // If headers already sent, write error as SSE
    if (res.headersSent) {
      res.write(`data: ${JSON.stringify({ 
        type: 'error', 
        message: error.message || 'An error occurred' 
      })}\n\n`);
      res.end();
    } else {
      next(error);
    }
  }
}

/**
 * Get chat suggestions based on user's content
 */
export async function getChatSuggestions(
  req: Request,
  res: Response,
  next: NextFunction
) {
  try {
    const userId = req.userId!;

    // Get content statistics
    const { contentModel } = await import('../db');
    
    const stats = await contentModel.aggregate([
      { $match: { userId } },
      {
        $group: {
          _id: '$type',
          count: { $sum: 1 }
        }
      }
    ]);

    // Generate contextual suggestions
    const suggestions: string[] = [];

    stats.forEach(stat => {
      switch (stat._id) {
        case 'youtube':
          suggestions.push('Summarize my recent video about...');
          suggestions.push('What are the key takeaways from my videos?');
          break;
        case 'article':
          suggestions.push('What articles have I saved about...?');
          suggestions.push('Find articles mentioning...');
          break;
        case 'twitter':
          suggestions.push('Show me tweets about...');
          break;
        case 'note':
          suggestions.push('What notes do I have about...?');
          break;
      }
    });

    // Add general suggestions
    suggestions.push(
      'Summarize my saved content'
    );

    res.json({
      success: true,
      suggestions: suggestions.slice(0, 6) // Return top 6
    });

  } catch (error) {
    next(error);
  }
}