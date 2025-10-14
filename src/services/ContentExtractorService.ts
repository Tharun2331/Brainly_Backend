// src/services/ContentExtractorService.ts
import dotenv from 'dotenv';
dotenv.config();

import { google } from 'googleapis';
import { YoutubeTranscript } from 'youtube-transcript';
import axios from 'axios';

export class ContentExtractorService {
  
  // YouTube API client for metadata only
  private static getYouTubeClient() {
    if (!process.env.YOUTUBE_API_KEY) {
      console.warn('⚠️ YouTube API key not configured - will use fallback metadata');
      return null;
    }
    
    return google.youtube({
      version: 'v3',
      auth: process.env.YOUTUBE_API_KEY
    });
  }

  static async extractContent(
    type: string,
    link: string,
    description: string
  ): Promise<{
    fullContent: string;
    metadata: any;
  }> {
    try {
      switch (type) {
        case 'youtube':
          return await this.extractYouTubeContent(link);
        case 'twitter':
          return await this.extractTwitterContent(link, description);
        case 'article':
          return await this.extractArticleContent(link);
        case 'note':
          return {
            fullContent: description,
            metadata: {
              wordCount: description.split(/\s+/).length,
              extractionMethod: 'direct'
            }
          };
        default:
          throw new Error(`Unsupported content type: ${type}`);
      }
    } catch (error) {
      console.error(`Content extraction failed for ${type}:`, error);
      
      // Final fallback to user description
      let fallbackContent = description || 'No content available';
      
      return {
        fullContent: fallbackContent,
        metadata: {
          wordCount: fallbackContent.split(/\s+/).length,
          extractionMethod: 'fallback-description',
          error: error instanceof Error ? error.message : 'Unknown error'
        }
      };
    }
  }

  /**
   * Extract YouTube content using hybrid approach
   */
  private static async extractYouTubeContent(link: string): Promise<{
    fullContent: string;
    metadata: any;
  }> {
    console.log(`🎥 Extracting YouTube content from: ${link}`);

    const videoId = this.extractYouTubeVideoId(link);
    if (!videoId) {
      throw new Error('Invalid YouTube URL - could not extract video ID');
    }

    // Get metadata from YouTube API v3
    let metadata: any = {
      title: 'YouTube Video',
      author: 'Unknown',
      publishDate: null,
      thumbnailUrl: '',
      viewCount: 0,
      likeCount: 0,
      description: '',
      duration: 0,
      channelId: ''
    };

    const youtube = this.getYouTubeClient();
    if (youtube) {
      try {
        console.log('📊 Getting video metadata from YouTube API...');
        const videoResponse = await youtube.videos.list({
          part: ['snippet', 'contentDetails', 'statistics'],
          id: [videoId]
        });

        const video = videoResponse.data.items?.[0];
        if (video) {
          metadata = {
            title: video.snippet?.title || 'YouTube Video',
            author: video.snippet?.channelTitle || 'Unknown',
            publishDate: video.snippet?.publishedAt ? new Date(video.snippet.publishedAt) : null,
            thumbnailUrl: video.snippet?.thumbnails?.high?.url || '',
            viewCount: parseInt(video.statistics?.viewCount || '0'),
            likeCount: parseInt(video.statistics?.likeCount || '0'),
            description: video.snippet?.description || '',
            duration: this.parseYouTubeDuration(video.contentDetails?.duration || ''),
            channelId: video.snippet?.channelId || ''
          };
          console.log(`✅ YouTube API metadata successful: ${metadata.title}`);
        }
      } catch (apiError) {
        console.warn('⚠️ YouTube API metadata failed:', apiError);
      }
    }

    // Get transcript using youtube-transcript library
    let transcript = '';
    try {
      console.log('📹 Getting transcript using youtube-transcript library...');
      
      // Try multiple languages
      const languagesToTry = ['en', 'en-US', 'en-GB'];
      
      for (const lang of languagesToTry) {
        try {
          const transcriptItems = await YoutubeTranscript.fetchTranscript(videoId, {
            lang: lang
          });
          
          if (transcriptItems && transcriptItems.length > 0) {
            transcript = transcriptItems
              .map((item: any)  => item.text) 
              .join(' ')
              .replace(/\[Music\]/gi, '')
              .replace(/\[Applause\]/gi, '')
              .replace(/\[Laughter\]/gi, '')
              .replace(/\s{2,}/g, ' ')
              .trim();

            if (transcript.length >= 50) {
              console.log(`✅ Transcript extraction successful (${lang}): ${transcript.length} chars`);
              break;
            }
          }
        } catch (langError: any) {
          console.warn(`❌ Language ${lang} failed:`, langError.message);
          continue;
        }
      }

      // Try auto-generated captions if no language-specific captions found
      if (!transcript) {
        try {
          console.log('🔄 Trying auto-generated captions...');
          const transcriptItems = await YoutubeTranscript.fetchTranscript(videoId);
          
          if (transcriptItems && transcriptItems.length > 0) {
            transcript = transcriptItems
              .map((item:any) => item.text)
              .join(' ')
              .replace(/\[Music\]/gi, '')
              .replace(/\s{2,}/g, ' ')
              .trim();

            if (transcript.length >= 50) {
              console.log(`✅ Auto-generated transcript successful: ${transcript.length} chars`);
            }
          }
        } catch (autoError) {
          console.warn('Auto-generated captions failed:', autoError);
        }
      }
    } catch (transcriptError) {
      console.warn('⚠️ Transcript extraction failed:', transcriptError);
    }

    // Build final content
    let fullContent = '';
    
    if (transcript) {
      // Use transcript as primary content
      fullContent = transcript;
    } else {
      // Use metadata to build comprehensive content
      fullContent = `Title: ${metadata.title}\n\n`;
      
      if (metadata.description) {
        // Use first 1000 characters of description
        const description = metadata.description.length > 1000 
          ? metadata.description.substring(0, 1000) + '...'
          : metadata.description;
        fullContent += `Description: ${description}\n\n`;
      }
      
      fullContent += `Channel: ${metadata.author}\n`;
      
      if (metadata.duration) {
        const minutes = Math.floor(metadata.duration / 60);
        const seconds = metadata.duration % 60;
        fullContent += `Duration: ${minutes}:${seconds.toString().padStart(2, '0')}\n`;
      }
      
      if (metadata.viewCount) {
        fullContent += `Views: ${metadata.viewCount.toLocaleString()}\n`;
      }
      
      fullContent += `\nVideo URL: ${link}\n`;
      fullContent += `\nNote: This video does not have captions available. The content above is from the video's metadata and description.`;
    }

    return {
      fullContent: fullContent.trim(),
      metadata: {
        ...metadata,
        wordCount: fullContent.split(/\s+/).length,
        extractionMethod: transcript ? 'youtube-transcript-hybrid' : 'youtube-api-metadata-hybrid',
        videoId,
        hasTranscript: !!transcript,
        transcriptLength: transcript.length
      }
    };
  }

  /**
   * Parse ISO 8601 duration format (PT4M13S -> seconds)
   */
  private static parseYouTubeDuration(duration: string): number {
    if (!duration) return 0;
    
    const match = duration.match(/PT(?:(\d+)H)?(?:(\d+)M)?(?:(\d+)S)?/);
    if (!match) return 0;

    const hours = parseInt(match[1] || '0');
    const minutes = parseInt(match[2] || '0');
    const seconds = parseInt(match[3] || '0');

    return hours * 3600 + minutes * 60 + seconds;
  }

  /**
   * Extract article content using basic HTTP requests
   */
  private static async extractArticleContent(link: string): Promise<{
    fullContent: string;
    metadata: any;
  }> {
    try {
      console.log(`📰 Extracting article from: ${link}`);
      
      const response = await axios.get(link, {
        headers: {
          'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        },
        timeout: 10000
      });

      const html = response.data;
      
      // Basic HTML parsing to extract text content
      let content = html
        .replace(/<script[^>]*>[\s\S]*?<\/script>/gi, '')
        .replace(/<style[^>]*>[\s\S]*?<\/style>/gi, '')
        .replace(/<[^>]+>/g, ' ')
        .replace(/\s+/g, ' ')
        .trim();

      // Extract title from HTML
      const titleMatch = html.match(/<title[^>]*>([^<]+)<\/title>/i);
      const title = titleMatch ? titleMatch[1].trim() : 'Article';

      if (!content || content.length < 100) {
        throw new Error('Article content too short or could not be extracted');
      }

      // Limit content length
      const limitedContent = content.substring(0, 5000);

      return {
        fullContent: limitedContent,
        metadata: {
          title: title,
          author: 'Unknown',
          publishDate: null,
          wordCount: limitedContent.split(/\s+/).length,
          extractionMethod: 'basic-http-fallback',
          url: link,
          note: 'Article extracted using basic HTTP request - limited content'
        }
      };

    } catch (error: any) {
      console.error('❌ Article extraction failed:', error.message);
      throw new Error(`Article extraction failed: ${error.message}`);
    }
  }

  /**
   * Extract Twitter content using URL parsing
   */
  private static async extractTwitterContent(link: string, description: string): Promise<{
    fullContent: string;
    metadata: any;
  }> {
    try {
      console.log(`🐦 Extracting tweet using URL parsing: ${link}`);
      
      const tweetIdMatch = link.match(/status\/(\d+)/);
      if (!tweetIdMatch) {
        throw new Error('Invalid Twitter URL format');
      }
      
      const tweetId = tweetIdMatch[1];
      const urlParts = link.split('/');
      const username = urlParts[3];
      
      const fallbackContent = `Tweet from @${username}\nTweet ID: ${tweetId}\nURL: ${link}\n\nNote: This tweet could not be fully extracted due to Twitter API restrictions. The original tweet may contain more detailed information.`;
      
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
          extractionMethod: 'url-parsing',
          note: 'Tweet content extracted using URL parsing due to API limitations'
        }
      };
    } catch (fallbackError) {
      console.warn('⚠️ URL parsing failed, using enhanced description:', fallbackError);

      let enhancedContent = description || 'No content available';
      if (enhancedContent.length < 50 || enhancedContent.includes('Article is about')) {
        enhancedContent = `Tweet content could not be extracted from: ${link}\n\nDescription: ${description}\n\nNote: This appears to be a tweet that could not be fully processed.`;
      }

      return {
        fullContent: enhancedContent,
        metadata: {
          author: 'Unknown',
          authorHandle: '',
          wordCount: enhancedContent.split(/\s+/).length,
          extractionMethod: 'fallback-enhanced',
          fallbackError: fallbackError instanceof Error ? fallbackError.message : 'Unknown fallback error',
          originalLink: link,
          note: 'Fallback tweet extraction failed - using enhanced description content'
        }
      };
    }
  }

  /**
   * Extract YouTube video ID from various URL formats
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