// src/services/ContentExtractorService.ts - FIXED TYPE ERRORS
import { ApifyService } from './ApifyService';
import { YoutubeTranscript } from 'youtube-transcript';
import axios from 'axios';

export class ContentExtractorService {
  
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
      
      // For YouTube, try to get metadata from Apify as fallback
      if (type === 'youtube' && process.env.APIFY_API_TOKEN) {
        try {
          console.log('🔄 Trying Apify metadata fallback...');
          const apifyMetadata = await ApifyService.getYouTubeMetadata(link);
          const metadataContent = `${apifyMetadata.title || 'YouTube Video'}\n\n${apifyMetadata.text || ''}`.trim();
          
          return {
            fullContent: metadataContent || description || 'No content available',
            metadata: {
              title: apifyMetadata.title || 'YouTube Video',
              author: apifyMetadata.channelName || 'Unknown',
              wordCount: metadataContent.split(/\s+/).length,
              extractionMethod: 'fallback-metadata',
              videoId: this.extractYouTubeVideoId(link),
              duration: apifyMetadata.duration || 0,
              error: error instanceof Error ? error.message : 'Unknown error'
            }
          };
        } catch (metaError) {
          console.warn('Apify metadata fallback failed:', metaError);
        }
      }
      
      // Final fallback to user description
      // Extract full content from description if it contains "Full Content:" section
      let fallbackContent = description || 'No content available';
      
      // Check if description contains structured content with "Full Content:" section
      const fullContentMatch = description?.match(/Full Content:\s*([\s\S]+?)(?:\n\n|$)/);
      if (fullContentMatch && fullContentMatch[1]) {
        fallbackContent = fullContentMatch[1].trim();
        console.log(`📝 Extracted ${fallbackContent.length} chars from description's "Full Content" section`);
      }
      
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

    let apifyMetadata: any = null; // Store Apify metadata for fallback

    // Strategy 1: Try Apify (if available and configured)
    if (process.env.APIFY_API_TOKEN) {
      try {
        console.log('📡 Attempting Apify YouTube extraction...');
        const result = await ApifyService.extractYouTubeTranscript(link);
        console.log(`✅ Apify extraction successful: ${result.metadata.wordCount} words`);
        return result;
      } catch (apifyError: any) {
        console.warn('⚠️ Apify YouTube extraction failed:', apifyError.message);
        // Try to get metadata from Apify even if transcript failed
        try {
          apifyMetadata = await ApifyService.getYouTubeMetadata(link);
        } catch (metaError) {
          console.warn('Could not get Apify metadata');
        }
      }
    }

    // Strategy 2: Try free youtube-transcript library (multiple languages)
    console.log('🔄 Trying free youtube-transcript library...');
    
    // Try 'en' first as it's most common, then variants
    const languagesToTry = ['en'];
    
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
        console.warn(`  ❌ Language ${lang} failed:`, langError.message);
        continue;
      }
    }

    // Strategy 3: Try to get auto-generated captions (no language specified)
    try {
      console.log('🔄 Trying auto-generated captions...');
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
    } catch (autoError) {
      console.warn('Auto-generated captions failed:', autoError);
    }

    // Strategy 4: Use video metadata as fallback (better than nothing)
    if (apifyMetadata) {
      console.warn('⚠️ No transcript found, using video metadata as content');
      const metadataContent = `${apifyMetadata.title || 'YouTube Video'}\n\n${apifyMetadata.text || ''}`.trim();
      
      return {
        fullContent: metadataContent || 'No content available',
        metadata: {
          title: apifyMetadata.title || 'YouTube Video',
          author: apifyMetadata.channelName || 'Unknown',
          wordCount: metadataContent.split(/\s+/).length,
          extractionMethod: 'metadata-only',
          videoId,
          duration: apifyMetadata.duration || 0,
          note: 'No transcript available - content is from video metadata only'
        }
      };
    }

    // All strategies failed and no metadata
    throw new Error(
      'No transcript available for this video. The creator may not have enabled captions or subtitles.'
    );
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
   * Extract article content
   */
  private static async extractArticleContent(link: string): Promise<{
    fullContent: string;
    metadata: any;
  }> {
    try {
      console.log(`📰 Extracting article from: ${link}`);
      const result = await ApifyService.extractArticle(link);
      console.log(`✅ Article extraction successful: ${result.metadata.wordCount} words`);
      return result;
    } catch (error) {
      console.error('❌ Article extraction failed:', error);
      throw error;
    }
  }

  /**
   * Extract Twitter content
   */
  private static async extractTwitterContent(link: string, description: string): Promise<{
    fullContent: string;
    metadata: any;
  }> {
    try {
      console.log(`🐦 Extracting tweet using fallback method: ${link}`);
      const result = await ApifyService.extractTwitterContentFallback(link);
      console.log(`✅ Fallback tweet extraction successful`);
      return result;
    } catch (fallbackError) {
      console.warn('⚠️ Fallback extraction failed, using enhanced description:', fallbackError);

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