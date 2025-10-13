// src/services/ContentExtractorService.ts - FIXED TYPE ERRORS
import { YoutubeTranscript } from 'youtube-transcript';
import axios from 'axios';

export class ContentExtractorService {
  
  // Rate limiting state
  private static lastYouTubeRequest = 0;
  private static readonly YOUTUBE_REQUEST_DELAY = parseInt(process.env.YOUTUBE_REQUEST_DELAY || '3000'); // 3 seconds between requests (configurable)
  
  /**
   * Add delay between YouTube requests to avoid rate limiting
   */
  private static async delayYouTubeRequest(): Promise<void> {
    const now = Date.now();
    const timeSinceLastRequest = now - this.lastYouTubeRequest;
    
    if (timeSinceLastRequest < this.YOUTUBE_REQUEST_DELAY) {
      const delayNeeded = this.YOUTUBE_REQUEST_DELAY - timeSinceLastRequest;
      console.log(`⏳ Rate limiting: waiting ${delayNeeded}ms before YouTube request (delay: ${this.YOUTUBE_REQUEST_DELAY}ms)`);
      await new Promise(resolve => setTimeout(resolve, delayNeeded));
    }
    
    this.lastYouTubeRequest = Date.now();
  }
  
  /**
   * Check if error is due to rate limiting
   */
  private static isRateLimitError(error: any): boolean {
    const errorMessage = error?.message?.toLowerCase() || '';
    return errorMessage.includes('too many requests') || 
           errorMessage.includes('captcha') ||
           errorMessage.includes('rate limit') ||
           errorMessage.includes('quota exceeded');
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
      
      // Check if this is a rate limiting error
      if (this.isRateLimitError(error)) {
        console.warn(`⚠️ Rate limiting detected for ${type}, using fallback strategies`);
      }
      
      // For YouTube, try multiple fallback strategies
      if (type === 'youtube') {
        const videoId = this.extractYouTubeVideoId(link);
        
        // Strategy 1: Try YouTube API metadata fallback
        if (process.env.YOUTUBE_API_KEY && videoId) {
          try {
            console.log('🔄 Trying YouTube API metadata fallback...');
            const apiMetadata = await this.getYouTubeMetadataFromAPI(videoId);
            if (apiMetadata.title) {
              const apiContent = `${apiMetadata.title}\n\n${apiMetadata.description || 'No transcript available for this video.'}`;
              return {
                fullContent: apiContent,
                metadata: {
                  ...apiMetadata,
                  wordCount: apiContent.split(/\s+/).length,
                  extractionMethod: 'api-metadata-fallback',
                  videoId,
                  error: error instanceof Error ? error.message : 'Unknown error'
                }
              };
            }
          } catch (apiError) {
            console.warn('YouTube API metadata fallback failed:', apiError);
          }
        }
        
        // Strategy 2: Basic video info fallback
        if (videoId) {
          console.log('🔄 Using basic video info fallback...');
          const basicContent = `YouTube Video\nVideo ID: ${videoId}\nURL: ${link}\n\nNo transcript or captions available for this video. The creator may not have enabled captions or subtitles.`;
          return {
            fullContent: basicContent,
            metadata: {
              title: 'YouTube Video',
              author: 'Unknown',
              wordCount: basicContent.split(/\s+/).length,
              extractionMethod: 'basic-fallback',
              videoId,
              error: error instanceof Error ? error.message : 'Unknown error'
            }
          };
        }
      }
      
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
   * Extract YouTube content with multiple fallback strategies
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

    // Strategy 1: Try YouTube API metadata (if available)
    let apiMetadata: any = null;
    if (process.env.YOUTUBE_API_KEY) {
      try {
        apiMetadata = await this.getYouTubeMetadataFromAPI(videoId);
      } catch (apiError) {
        console.warn('Could not get YouTube API metadata');
      }
    }

    // Strategy 2: Try free youtube-transcript library (multiple languages)
    console.log('🔄 Trying free youtube-transcript library...');
    
    // Add delay to avoid rate limiting
    await this.delayYouTubeRequest();
    
    // Try multiple languages in order of preference
    const languagesToTry = ['en', 'en-US', 'en-GB'];
    
    for (const lang of languagesToTry) {
      try {
        console.log(`📹 Fetching transcript for video ${videoId} (lang: ${lang})`);
        
        const transcriptItems = await YoutubeTranscript.fetchTranscript(videoId, {
          lang: lang
        });
        
        if (transcriptItems && transcriptItems.length > 0) {
          const fullTranscript = transcriptItems
            .map(item => item.text)
            .join(' ')
            .replace(/\[Music\]/gi, '')
            .replace(/\[Applause\]/gi, '')
            .replace(/\[Laughter\]/gi, '')
            .replace(/\s{2,}/g, ' ')
            .trim();

          if (fullTranscript.length >= 50) {
            console.log(`✅ Free library extraction successful with lang=${lang}: ${fullTranscript.length} chars`);

            // Get additional metadata from YouTube API if available
            let metadata: any = {
              title: 'YouTube Video',
              author: 'Unknown',
              wordCount: fullTranscript.split(/\s+/).length,
              extractionMethod: 'youtube-transcript-free',
              duration: transcriptItems[transcriptItems.length - 1]?.offset || 0,
              videoId,
              language: lang
            };

            // Try to get metadata from YouTube API
            if (process.env.YOUTUBE_API_KEY) {
              try {
                const apiMetadata = await this.getYouTubeMetadataFromAPI(videoId);
                metadata = { ...metadata, ...apiMetadata };
              } catch (apiError) {
                console.warn('Could not fetch YouTube API metadata');
              }
            }

            return {
              fullContent: fullTranscript,
              metadata
            };
          }
        }
      } catch (langError: any) {
        if (this.isRateLimitError(langError)) {
          console.warn(`  ⚠️ Rate limited for language ${lang}, skipping remaining attempts:`, langError.message);
          break; // Don't try other languages if rate limited
        } else {
          console.warn(`  ❌ Language ${lang} failed:`, langError.message);
        }
        continue;
      }
    }

    // Strategy 3: Try to get auto-generated captions (no language specified)
    try {
      console.log('🔄 Trying auto-generated captions...');
      
      // Add delay to avoid rate limiting
      await this.delayYouTubeRequest();
      
      const transcriptItems = await YoutubeTranscript.fetchTranscript(videoId);
      
      if (transcriptItems && transcriptItems.length > 0) {
        const fullTranscript = transcriptItems
          .map(item => item.text)
          .join(' ')
          .replace(/\[Music\]/gi, '')
          .replace(/\s{2,}/g, ' ')
          .trim();

        if (fullTranscript.length >= 50) {
          console.log(`✅ Auto-generated captions successful: ${fullTranscript.length} chars`);
          
          return {
            fullContent: fullTranscript,
            metadata: {
              title: 'YouTube Video',
              author: 'Unknown',
              wordCount: fullTranscript.split(/\s+/).length,
              extractionMethod: 'youtube-transcript-auto',
              duration: transcriptItems[transcriptItems.length - 1]?.offset || 0,
              videoId
            }
          };
        }
      }
    } catch (autoError: any) {
      if (this.isRateLimitError(autoError)) {
        console.warn('⚠️ Auto-generated captions failed due to rate limiting:', autoError.message);
      } else {
        console.warn('Auto-generated captions failed:', autoError);
      }
    }

    // Strategy 4: Try to get content from video page HTML
    try {
      console.log('🔄 Trying to extract content from video page HTML...');
      const pageContent = await this.extractFromVideoPage(link);
      if (pageContent && pageContent.length > 100) {
        console.log(`✅ Video page extraction successful: ${pageContent.length} chars`);
        return {
          fullContent: pageContent,
          metadata: {
            title: 'YouTube Video',
            author: 'Unknown',
            wordCount: pageContent.split(/\s+/).length,
            extractionMethod: 'video-page-html',
            videoId,
            note: 'Content extracted from video page HTML'
          }
        };
      }
    } catch (pageError) {
      console.warn('Video page extraction failed:', pageError);
    }

    // Strategy 5: Use video metadata as fallback (better than nothing)
    if (apiMetadata) {
      console.warn('⚠️ No transcript found, using video metadata as content');
      
      // Create more comprehensive content from metadata
      let metadataContent = '';
      
      if (apiMetadata.title) {
        metadataContent += `Title: ${apiMetadata.title}\n\n`;
      }
      
      if (apiMetadata.description) {
        // Use first 1000 characters of description
        const description = apiMetadata.description.length > 1000 
          ? apiMetadata.description.substring(0, 1000) + '...'
          : apiMetadata.description;
        metadataContent += `Description: ${description}\n\n`;
      }
      
      if (apiMetadata.author) {
        metadataContent += `Channel: ${apiMetadata.author}\n`;
      }
      
      if (apiMetadata.duration) {
        const minutes = Math.floor(apiMetadata.duration / 60);
        const seconds = apiMetadata.duration % 60;
        metadataContent += `Duration: ${minutes}:${seconds.toString().padStart(2, '0')}\n`;
      }
      
      if (apiMetadata.viewCount) {
        metadataContent += `Views: ${apiMetadata.viewCount.toLocaleString()}\n`;
      }
      
      metadataContent += `\nVideo URL: ${link}\n`;
      metadataContent += `\nNote: This video does not have captions or transcripts available. The content above is from the video's metadata and description.`;
      
      return {
        fullContent: metadataContent.trim(),
        metadata: {
          title: apiMetadata.title || 'YouTube Video',
          author: apiMetadata.author || 'Unknown',
          wordCount: metadataContent.split(/\s+/).length,
          extractionMethod: 'metadata-only',
          videoId,
          duration: apiMetadata.duration || 0,
          viewCount: apiMetadata.viewCount || 0,
          note: 'No transcript available - content is from video metadata and description'
        }
      };
    }

    // All strategies failed - try to get basic metadata as final fallback
    console.warn('⚠️ All YouTube extraction strategies failed, attempting basic metadata fallback');
    
    try {
      // Try to get basic video info from YouTube API if available
      if (process.env.YOUTUBE_API_KEY) {
        const basicMetadata = await this.getYouTubeMetadataFromAPI(videoId);
        if (basicMetadata.title) {
          console.log(`✅ Using YouTube API metadata as fallback: ${basicMetadata.title}`);
          return {
            fullContent: `${basicMetadata.title}\n\n${basicMetadata.description || 'No transcript available for this video.'}`,
            metadata: {
              ...basicMetadata,
              wordCount: basicMetadata.title.split(/\s+/).length + (basicMetadata.description?.split(/\s+/).length || 0),
              extractionMethod: 'api-metadata-fallback',
              videoId,
              note: 'No transcript available - using video metadata only'
            }
          };
        }
      }
      
      // Final fallback with basic video info
      console.log(`📝 Using basic video info as final fallback for video ${videoId}`);
      const basicContent = `YouTube Video\nVideo ID: ${videoId}\nURL: ${link}\n\nThis video could not be processed for the following reasons:\n- No captions or transcripts are available\n- The video may be private or restricted\n- The creator may not have enabled captions\n- The video may be too new or still processing\n\nTo get the content from this video, please:\n1. Watch the video directly on YouTube\n2. Check if captions are available in the video player\n3. Try adding the video again later if it's still processing`;
      
      return {
        fullContent: basicContent,
        metadata: {
          title: 'YouTube Video',
          author: 'Unknown',
          wordCount: basicContent.split(/\s+/).length,
          extractionMethod: 'basic-fallback',
          videoId,
          note: 'No transcript available - using basic video information with troubleshooting tips'
        }
      };
    } catch (finalError) {
      console.error('❌ All fallback strategies failed:', finalError);
      throw new Error(
        'No transcript available for this video. The creator may not have enabled captions or subtitles.'
      );
    }
  }

  /**
   * Get YouTube metadata from official API
   */
  private static async getYouTubeMetadataFromAPI(videoId: string): Promise<any> {
    try {
      const response = await axios.get(
        'https://www.googleapis.com/youtube/v3/videos',
        {
          params: {
            part: 'snippet,contentDetails,statistics',
            id: videoId,
            key: process.env.YOUTUBE_API_KEY
          }
        }
      );

      const video = response.data.items?.[0];
      if (!video) return {};

      return {
        title: video.snippet?.title || 'YouTube Video',
        author: video.snippet?.channelTitle || 'Unknown',
        publishDate: video.snippet?.publishedAt ? new Date(video.snippet.publishedAt) : null,
        thumbnailUrl: video.snippet?.thumbnails?.high?.url || '',
        viewCount: parseInt(video.statistics?.viewCount || '0'),
        likeCount: parseInt(video.statistics?.likeCount || '0'),
        description: video.snippet?.description?.substring(0, 500) || '',
        duration: this.parseYouTubeDuration(video.contentDetails?.duration || ''),
        channelId: video.snippet?.channelId || ''
      };
    } catch (error) {
      console.warn('YouTube API call failed:', error);
      return {};
    }
  }

  /**
   * Parse ISO 8601 duration format
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
   * Extract article content using free HTTP requests
   */
  private static async extractArticleContent(link: string): Promise<{
    fullContent: string;
    metadata: any;
  }> {
    try {
      console.log(`📰 Extracting article from: ${link}`);
      const result = await this.extractArticleFallback(link);
      console.log(`✅ Article extraction successful: ${result.metadata.wordCount} words`);
      return result;
    } catch (error) {
      console.error('❌ Article extraction failed:', error);
      throw error;
    }
  }

  /**
   * Extract article content using basic HTTP request (free method)
   */
  private static async extractArticleFallback(url: string): Promise<{
    fullContent: string;
    metadata: any;
  }> {
    try {
      console.log(`🔄 Trying basic article extraction for: ${url}`);
      
      // Use axios to fetch the page content
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
   * Extract Twitter content using URL parsing (free method)
   */
  private static async extractTwitterContent(link: string, description: string): Promise<{
    fullContent: string;
    metadata: any;
  }> {
    try {
      console.log(`🐦 Extracting tweet using URL parsing: ${link}`);
      
      // Extract tweet ID from URL
      const tweetIdMatch = link.match(/status\/(\d+)/);
      if (!tweetIdMatch) {
        throw new Error('Invalid Twitter URL format');
      }
      
      const tweetId = tweetIdMatch[1];
      
      // Try to extract basic info from URL structure
      const urlParts = link.split('/');
      const username = urlParts[3]; // Extract username from URL
      
      // Create a basic tweet representation
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

      // Enhanced fallback: try to extract more meaningful content from description
      let enhancedContent = description || 'No content available';

      // If description is very short or generic, provide more context
      if (enhancedContent.length < 50 || enhancedContent.includes('Article is about')) {
        enhancedContent = `Tweet content could not be extracted from: ${link}\n\nDescription: ${description}\n\nNote: This appears to be a tweet that could not be fully processed. The original tweet may contain more detailed information that was not captured.`;
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
   * Extract content from YouTube video page HTML
   */
  private static async extractFromVideoPage(videoUrl: string): Promise<string> {
    try {
      const response = await axios.get(videoUrl, {
        headers: {
          'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        },
        timeout: 10000
      });

      const html = response.data;
      
      // Extract title
      const titleMatch = html.match(/<title[^>]*>([^<]+)<\/title>/i);
      const title = titleMatch ? titleMatch[1].replace(' - YouTube', '').trim() : 'YouTube Video';
      
      // Extract description from meta tag
      const descMatch = html.match(/<meta name="description" content="([^"]+)"/i);
      const description = descMatch ? descMatch[1] : '';
      
      // Extract channel name
      const channelMatch = html.match(/"ownerChannelName":"([^"]+)"/i);
      const channel = channelMatch ? channelMatch[1] : 'Unknown';
      
      // Try to extract more content from JSON-LD or other structured data
      const jsonLdMatch = html.match(/<script type="application\/ld\+json">([^<]+)<\/script>/i);
      let additionalContent = '';
      
      if (jsonLdMatch) {
        try {
          const jsonData = JSON.parse(jsonLdMatch[1]);
          if (jsonData.description) {
            additionalContent = jsonData.description;
          }
        } catch (e) {
          // Ignore JSON parsing errors
        }
      }
      
      // Combine all extracted content
      let content = `Title: ${title}\n`;
      if (channel !== 'Unknown') {
        content += `Channel: ${channel}\n`;
      }
      if (description) {
        content += `\nDescription: ${description}\n`;
      }
      if (additionalContent && additionalContent !== description) {
        content += `\nAdditional Info: ${additionalContent}\n`;
      }
      
      content += `\nVideo URL: ${videoUrl}`;
      
      return content;
    } catch (error) {
      throw new Error(`Failed to extract from video page: ${error}`);
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