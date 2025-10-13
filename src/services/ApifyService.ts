// src/services/ApifyService.ts - FIXED TYPE ERRORS
import { ApifyClient } from 'apify-client';
import dotenv from 'dotenv';
dotenv.config();

// Initialize Apify client only if token is available
let client: ApifyClient | null = null;

if (process.env.APIFY_API_TOKEN) {
  client = new ApifyClient({
    token: process.env.APIFY_API_TOKEN
  });
  console.log('✅ Apify client initialized with token');
} else {
  console.warn('⚠️ APIFY_API_TOKEN not found - Apify services will be disabled');
}

export class ApifyService {
  
  /**
   * Extract YouTube transcript using correct Apify actor
   */
  static async extractYouTubeTranscript(videoUrl: string): Promise<{
    fullContent: string;
    metadata: any;
  }> {
    if (!client) {
      throw new Error('Apify client not initialized - APIFY_API_TOKEN missing');
    }

    try {
      console.log(`🎥 Starting YouTube extraction for: ${videoUrl}`);

      const videoId = this.extractYouTubeVideoId(videoUrl);
      if (!videoId) {
        throw new Error('Invalid YouTube URL');
      }

      // Use YouTube Scraper actor - extracts captions/transcripts
      const run = await client.actor('streamers/youtube-scraper').call({
        startUrls: [{ url: videoUrl }],
        maxResults: 1,
        subtitlesLanguage: 'en'
      });

      console.log(`✅ Apify run completed: ${run.id}`);

      // Get results
      const { items } = await client.dataset(run.defaultDatasetId).listItems();

      if (!items || items.length === 0) {
        throw new Error('No captions found from Apify');
      }

      const result = items[0] as any;
      
      // Extract subtitles from result - ONLY use actual subtitles, not description
      let transcript: string = '';
      
      if (result.subtitles) {
        // If subtitles is an array of subtitle objects
        if (Array.isArray(result.subtitles)) {
          transcript = result.subtitles.map((s: any) => s.text || '').join(' ');
        } else if (typeof result.subtitles === 'string') {
          transcript = result.subtitles;
        }
      }
      
      // DO NOT use description/text as fallback - those are metadata, not transcript
      if (!transcript || transcript.length < 50) {
        throw new Error('No subtitles found in Apify response - will try free library');
      }

      // Clean up transcript
      const cleanTranscript = transcript
        .replace(/\[Music\]/gi, '')
        .replace(/\[Applause\]/gi, '')
        .replace(/\[Laughter\]/gi, '')
        .replace(/\s{2,}/g, ' ')
        .trim();

      console.log(`✅ Extracted ${cleanTranscript.length} characters via Apify`);

      return {
        fullContent: cleanTranscript,
        metadata: {
          title: result.title || 'Untitled',
          author: result.channelName || result.channelTitle || 'Unknown',
          wordCount: cleanTranscript.split(/\s+/).length,
          extractionMethod: 'apify-youtube-scraper',
          videoId,
          duration: result.duration || result.lengthSeconds || 0
        }
      };

    } catch (error: any) {
      console.error('❌ Apify YouTube extraction failed:', error.message);
      throw new Error(`YouTube extraction failed: ${error.message}`);
    }
  }

  /**
   * Extract article content using Apify
   */
  static async extractArticle(url: string): Promise<{
    fullContent: string;
    metadata: any;
  }> {
    if (!client) {
      throw new Error('Apify client not initialized - APIFY_API_TOKEN missing');
    }

    try {
      console.log(`📰 Starting article extraction for: ${url}`);

      // Use Website Content Crawler
      const run = await client.actor('apify/website-content-crawler').call({
        startUrls: [{ url }],
        maxCrawlPages: 1,
        crawlerType: 'playwright:firefox'
      });

      const { items } = await client.dataset(run.defaultDatasetId).listItems();

      if (!items || items.length === 0) {
        throw new Error('No content extracted from article');
      }

      const article = items[0] as any;
      let content: string = article.text || article.markdown || article.html || '';
      
      if (typeof content !== 'string') {
        content = JSON.stringify(content);
      }

      if (!content || content.length < 100) {
        throw new Error('Article content too short or empty');
      }

      // Clean and limit content
      const cleanContent = content
        .replace(/\s{2,}/g, ' ')
        .trim()
        .substring(0, 10000); // Limit to 10k chars

      console.log(`✅ Article extracted: ${cleanContent.length} characters`);

      return {
        fullContent: cleanContent,
        metadata: {
          title: article.title || 'Untitled Article',
          author: article.author || 'Unknown',
          publishDate: article.publishDate || null,
          wordCount: cleanContent.split(/\s+/).length,
          extractionMethod: 'apify-article-scraper',
          url: article.url || url
        }
      };

    } catch (error: any) {
      console.error('❌ Article extraction failed:', error.message);
      throw new Error(`Article extraction failed: ${error.message}`);
    }
  }

  /**
   * Extract article content using basic HTTP request (fallback when Apify fails)
   */
  static async extractArticleFallback(url: string): Promise<{
    fullContent: string;
    metadata: any;
  }> {
    try {
      console.log(`🔄 Trying basic article extraction for: ${url}`);
      
      // Use axios to fetch the page content
      const axios = require('axios');
      const response = await axios.get(url, {
        headers: {
          'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        },
        timeout: 10000
      });

      const html = response.data;
      
      // Basic HTML parsing to extract text content
      let content = html
        .replace(/<script[^>]*>[\s\S]*?<\/script>/gi, '') // Remove scripts
        .replace(/<style[^>]*>[\s\S]*?<\/style>/gi, '') // Remove styles
        .replace(/<[^>]+>/g, ' ') // Remove HTML tags
        .replace(/\s+/g, ' ') // Normalize whitespace
        .trim();

      // Extract title from HTML
      const titleMatch = html.match(/<title[^>]*>([^<]+)<\/title>/i);
      const title = titleMatch ? titleMatch[1].trim() : 'Article';

      if (!content || content.length < 100) {
        throw new Error('Article content too short or could not be extracted');
      }

      // Limit content length
      const limitedContent = content.substring(0, 5000);

      console.log(`✅ Basic article extraction successful: ${limitedContent.length} characters`);

      return {
        fullContent: limitedContent,
        metadata: {
          title: title,
          author: 'Unknown',
          publishDate: null,
          wordCount: limitedContent.split(/\s+/).length,
          extractionMethod: 'basic-http-fallback',
          url: url,
          note: 'Article extracted using basic HTTP request - limited content'
        }
      };

    } catch (error: any) {
      console.error('❌ Basic article extraction failed:', error.message);
      throw new Error(`Basic article extraction failed: ${error.message}`);
    }
  }

  /**
   * Extract Twitter content using alternative method (fallback)
   */
  static async extractTwitterContentFallback(tweetUrl: string): Promise<{
    fullContent: string;
    metadata: any;
  }> {
    try {
      console.log(`🔄 Trying fallback Twitter extraction for: ${tweetUrl}`);
      
      // Extract tweet ID from URL
      const tweetIdMatch = tweetUrl.match(/status\/(\d+)/);
      if (!tweetIdMatch) {
        throw new Error('Invalid Twitter URL format');
      }
      
      const tweetId = tweetIdMatch[1];
      
      // Try to extract basic info from URL structure
      const urlParts = tweetUrl.split('/');
      const username = urlParts[3]; // Extract username from URL
      
      // Create a basic tweet representation
      const fallbackContent = `Tweet from @${username}\nTweet ID: ${tweetId}\nURL: ${tweetUrl}\n\nNote: This tweet could not be fully extracted due to Twitter API restrictions. The original tweet may contain more detailed information.`;
      
      return {
        fullContent: fallbackContent,
        metadata: {
          author: username,
          authorHandle: username,
          tweetId: tweetId,
          publishDate: null,
          likes: 0,
          retweets: 0,
          wordCount: fallbackContent.split(/\s+/).length,
          extractionMethod: 'fallback-url-parsing',
          note: 'Tweet content extracted using URL parsing due to API limitations'
        }
      };
    } catch (error: any) {
      console.error('❌ Fallback Twitter extraction failed:', error.message);
      throw new Error(`Fallback Twitter extraction failed: ${error.message}`);
    }
  }


  /**
   * Get YouTube metadata without requiring transcript
   */
  static async getYouTubeMetadata(videoUrl: string): Promise<any> {
    if (!client) {
      throw new Error('Apify client not initialized - APIFY_API_TOKEN missing');
    }

    try {
      console.log(`📊 Getting YouTube metadata for: ${videoUrl}`);

      const run = await client.actor('streamers/youtube-scraper').call({
        startUrls: [{ url: videoUrl }],
        maxResults: 1
      });

      const { items } = await client.dataset(run.defaultDatasetId).listItems();

      if (!items || items.length === 0) {
        throw new Error('No metadata found');
      }

      const result = items[0] as any;
      
      return {
        title: result.title || 'YouTube Video',
        channelName: result.channelName || result.channelTitle || 'Unknown',
        text: result.text || result.description || '',
        duration: result.duration || result.lengthSeconds || 0,
        viewCount: result.viewCount || 0,
        likes: result.likes || 0
      };

    } catch (error: any) {
      console.error('❌ Failed to get YouTube metadata:', error.message);
      throw error;
    }
  }

  /**
   * Helper: Extract YouTube video ID from URL
   */
  private static extractYouTubeVideoId(url: string): string | null {
    const patterns = [
      /(?:youtube\.com\/watch\?v=|youtu\.be\/|youtube\.com\/embed\/)([^&\n?#]+)/,
      /^([a-zA-Z0-9_-]{11})$/
    ];

    for (const pattern of patterns) {
      const match = url.match(pattern);
      if (match) return match[1];
    }

    return null;
  }
}