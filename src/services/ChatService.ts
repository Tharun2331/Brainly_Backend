// src/services/ChatService.ts
import OpenAI from 'openai';
import { searchContent } from './PineconeService';
import { contentModel } from '../db';
import mongoose from 'mongoose';

const openai = new OpenAI({
  apiKey: process.env.OPENAI_API_KEY!
});

interface Message {
  role: 'user' | 'assistant' | 'system';
  content: string;
}

interface ChatOptions {
  userId: string;
  message: string;
  conversationHistory: Message[];
  maxSources?: number;
}

export class ChatService {
  /**
   * Generate chat response with streaming
   */
  static async chatStream(options: ChatOptions) {
    const { userId, message, conversationHistory, maxSources = 5 } = options;

    // 1. Search for relevant content using semantic search
    console.log(`🔍 Searching for relevant content for query: "${message}"`);
    const relevantContent = await searchContent(message, userId, maxSources);

    if (relevantContent.length === 0) {
      console.log('⚠️ No relevant content found');
      return {
        stream: this.createEmptyResponseStream(),
        sources: []
      };
    }

    // 2. Fetch full content from MongoDB
    const contentIds = relevantContent.map(c => c.id);
    const fullContents = await contentModel.find({
      _id: { $in: contentIds },
      userId: new mongoose.Types.ObjectId(userId)
    }).lean();

    console.log(`📚 Found ${fullContents.length} relevant content items`);

    // 3. Build rich context from full content
    const context = this.buildRichContext(fullContents, relevantContent);

    // 4. Create system prompt with context
    const systemPrompt = this.buildSystemPrompt(context, fullContents.length);

    // 5. Build messages array
    const messages: OpenAI.Chat.ChatCompletionMessageParam[] = [
      { role: 'system', content: systemPrompt },
      ...conversationHistory.map(msg => ({
        role: msg.role as 'user' | 'assistant',
        content: msg.content
      })),
      { role: 'user', content: message }
    ];

    // 6. Create streaming response
    const stream = await openai.chat.completions.create({
      model: 'gpt-4o-mini', // Cost-effective for RAG
      messages,
      temperature: 0.7,
      max_tokens: 800,
      stream: true
    });

    // 7. Return stream and sources
    return {
      stream,
      sources: this.formatSources(fullContents, relevantContent)
    };
  }

  /**
   * Build rich context from content with full text
   */
  private static buildRichContext(
    fullContents: any[],
    relevantContent: any[]
  ): string {
    return fullContents.map((content, idx) => {
      const vectorData = relevantContent[idx];
      
      // Use fullContent if available, otherwise fall back to description
      let contentText = content.fullContent || content.description;
      
      // Truncate if too long (keep first 2000 chars per item)
      if (contentText.length > 2000) {
        contentText = contentText.substring(0, 2000) + '... [content truncated for brevity]';
      }

      // Clean up the text
      contentText = contentText
        .replace(/\s+/g, ' ')
        .replace(/\n{3,}/g, '\n\n')
        .trim();

      const metadata = content.contentMetadata || {};
      const relevanceScore = Math.round((vectorData?.score || 0) * 100);

      // Build structured context
      let contextStr = `\n[Content ID: ${content._id}]`;
      contextStr += `\nTitle: ${content.title || 'Untitled'}`;
      contextStr += `\nType: ${content.type}`;
      
      if (content.link) {
        contextStr += `\nURL: ${content.link}`;
      }
      
      if (metadata.author) {
        contextStr += `\nAuthor: ${metadata.author}`;
      }
      
      if (metadata.authorHandle) {
        contextStr += `\nAuthor Handle: @${metadata.authorHandle}`;
      }
      
      if (metadata.publishDate) {
        contextStr += `\nPublished: ${new Date(metadata.publishDate).toLocaleDateString()}`;
      }
      
      if (metadata.duration) {
        const minutes = Math.floor(metadata.duration / 60);
        contextStr += `\nDuration: ${minutes} minutes`;
      }
      
      if (metadata.wordCount) {
        contextStr += `\nWord Count: ${metadata.wordCount.toLocaleString()}`;
      }

      // Add extraction method and any notes for tweets
      if (metadata.extractionMethod) {
        contextStr += `\nExtraction Method: ${metadata.extractionMethod}`;
      }
      
      if (metadata.note) {
        contextStr += `\nNote: ${metadata.note}`;
      }

      // Add tags
      const tags = this.extractTagNames(content.tags);
      if (tags.length > 0) {
        contextStr += `\nTags: ${tags.join(', ')}`;
      }

      contextStr += `\nRelevance Score: ${relevanceScore}%`;
      contextStr += `\n\nContent:\n${contentText}`;
      contextStr += '\n---';

      return contextStr;
    }).join('\n\n');
  }

  /**
   * Build system prompt with instructions
   */
  private static buildSystemPrompt(context: string, contentCount: number): string {
    return `You are a helpful AI assistant that answers questions about the user's saved content library.

You have access to ${contentCount} relevant pieces of content from the user's library.

AVAILABLE CONTENT:
${context}

INSTRUCTIONS:
1. Answer questions based ONLY on the provided content above
2. Cite sources by mentioning the title and content ID: "According to [Title] (ID: xxx)..."
3. If the answer isn't in the provided content, clearly say: "I don't see information about that in your saved content."
4. Be conversational and helpful, but always accurate
5. If multiple sources say different things, mention both perspectives
6. For follow-up questions, remember the previous context in this conversation
7. When relevant, suggest related content from the library
8. If a user asks about a specific video/article/tweet, identify it by title or URL

RESPONSE STYLE:
- Be concise but complete
- Use bullet points for lists
- Quote key phrases when helpful
- Be natural and conversational
- If content is from a video, you can reference "in the video" or specific timestamps if available

Remember: You can ONLY discuss content from the user's library shown above. Don't make up information or use general knowledge.`;
  }

  /**
   * Format sources for response
   */
  private static formatSources(
    fullContents: any[],
    relevantContent: any[]
  ): Array<{
    id: string;
    title: string;
    type: string;
    link?: string;
    score: number;
    excerpt: string;
    metadata?: any;
  }> {
    // Create a map for quick lookup of vector data by content ID
    const vectorDataMap = new Map(
      relevantContent.map(item => [item.id, item])
    );

    // Format sources and maintain the relevance order from vector search
    return relevantContent
      .map(vectorItem => {
        // Find the corresponding full content by ID
        const content = fullContents.find(c => c._id.toString() === vectorItem.id);
        
        if (!content) {
          console.warn(`Content not found for ID: ${vectorItem.id}`);
          return null;
        }

        // Get a relevant excerpt
        const fullText = content.fullContent || content.description;
        const excerpt = fullText.length > 200 
          ? fullText.substring(0, 200) + '...'
          : fullText;

        return {
          id: content._id.toString(),
          title: content.title || 'Untitled',
          type: content.type,
          link: content.link,
          score: vectorItem.score || 0,
          excerpt: excerpt.replace(/\s+/g, ' ').trim(),
          metadata: content.contentMetadata
        };
      })
      .filter((item): item is NonNullable<typeof item> => item !== null); // Type-safe filter
  }

  /**
   * Extract tag names from tag objects
   */
  private static extractTagNames(tags: any[]): string[] {
    if (!Array.isArray(tags)) return [];
    return tags
      .map(t => {
        if (typeof t === 'string') return t;
        if (t && typeof t === 'object' && 'tag' in t) return t.tag;
        return null;
      })
      .filter(Boolean) as string[];
  }

  /**
   * Create empty response stream for when no content is found
   */
  private static async *createEmptyResponseStream() {
    yield {
      id: 'empty',
      object: 'chat.completion.chunk' as const,
      created: Date.now(),
      model: 'gpt-4o-mini',
      choices: [{
        index: 0,
        delta: {
          content: "I don't have any saved content that's relevant to your question. Try adding some content to your library first, or ask about content you've already saved!"
        },
        finish_reason: null
      }]
    };
  }

  /**
   * Non-streaming version (for testing or simple use cases)
   */
  static async chat(options: ChatOptions): Promise<{
    message: string;
    sources: any[];
  }> {
    const { userId, message, conversationHistory, maxSources = 5 } = options;

    // Search and fetch content
    const relevantContent = await searchContent(message, userId, maxSources);

    if (relevantContent.length === 0) {
      return {
        message: "I don't have any saved content that's relevant to your question. Try adding some content to your library first!",
        sources: []
      };
    }

    const contentIds = relevantContent.map(c => c.id);
    const fullContents = await contentModel.find({
      _id: { $in: contentIds },
      userId: new mongoose.Types.ObjectId(userId)
    }).lean();

    const context = this.buildRichContext(fullContents, relevantContent);
    const systemPrompt = this.buildSystemPrompt(context, fullContents.length);

    const messages: OpenAI.Chat.ChatCompletionMessageParam[] = [
      { role: 'system', content: systemPrompt },
      ...conversationHistory.map(msg => ({
        role: msg.role as 'user' | 'assistant',
        content: msg.content
      })),
      { role: 'user', content: message }
    ];

    const response = await openai.chat.completions.create({
      model: 'gpt-4o-mini',
      messages,
      temperature: 0.7,
      max_tokens: 800
    });

    return {
      message: response.choices[0].message.content || '',
      sources: this.formatSources(fullContents, relevantContent)
    };
  }
}