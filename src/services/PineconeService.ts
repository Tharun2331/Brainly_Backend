import { Pinecone } from '@pinecone-database/pinecone';
import OpenAI from 'openai';
import dotenv from 'dotenv';
dotenv.config();

const pinecone = new Pinecone({
  apiKey: process.env.PINECONE_API_KEY as string
})

const openai = new OpenAI({
  apiKey: process.env.OPENAI_API_KEY as string
})

const indexName = process.env.PINECONE_INDEX_NAME || "brainly-content";

// src/services/pineconeService.ts - Update initPineconeIndex
export async function initPineconeIndex() {
  try {
    const indexList = await pinecone.listIndexes();
    const indexExists = indexList.indexes?.some(index => index.name === indexName);

    if (!indexExists) {
      await pinecone.createIndex({
        name: indexName,
        dimension: 1536, // ✅ Match OpenAI text-embedding-3-small
        metric: 'cosine',
        spec: {
          serverless: {
            cloud: 'aws',
            region: 'us-east-1'
          }
        }
      });
      console.log(`Created Pinecone index: ${indexName}`);
    } else {
      console.log(`Pinecone index ${indexName} already exists`);
    }
  } catch (error) {
    console.error('Error initializing Pinecone index:', error);
    throw error;
  }
}

export async function generateEmbedding(text:string): Promise<number[]> {

try {
  const response = await openai.embeddings.create({
    model: 'text-embedding-3-small',
    input: text,
  });
  return response.data[0].embedding;
}

catch(error) {
  console.error('Error generating embedding:', error);
  throw error;
}
}

export async function addContentToVector(
contentId: string,
userId:string,
content: {
  title: string;
  description: string;
  type: string;
  link?: string;
  tags?: string[];
}
)
{
  try {
    const index = pinecone.index(indexName);

    const searchableText = `
    Title: ${content.title}
    Description: ${content.description}
    Type: ${content.type}
    Tags: ${content.tags?.join(', ') || 'none'}
    `.trim();

    // Generate Embeddings
    const embedding = await generateEmbedding(searchableText);

    //  upsert to pinecone
    await index.upsert([
      {
        id: contentId,
        values: embedding,
        metadata: {
          userId,
          title: content.title,
          description: content.description,
          type: content.type,
          link: content.link || '',
          tags: content.tags?.join(',') || '',
          createdAt: new Date().toISOString(),
        },
      },
    ]);
    console.log(`Added content ${contentId} to vector database`);
  }
  catch(error) {
    console.error('Error adding content to vector database:', error);
    throw error;
  }
}

export async function searchContent(
 query: string,
 userId: string,
 topK: number = 5
)
{
  try {
    const index = pinecone.index(indexName);
    
    // Generate embedding for query
    const queryEmbedding = await generateEmbedding(query);

    // Search in Pinecone
    const searchResults = await index.query({
      vector: queryEmbedding,
      topK,
      includeMetadata: true,
      filter: {
        userId: { $eq: userId },
      },
    });

    return searchResults.matches?.map(match => ({
      id: match.id,
      score: match.score,
      metadata: match.metadata
    })) || [];

  }
  catch(error)
  {
    console.error('Error searching content:', error);
    throw error;
  }
}

// Delete content from Pinecone
export async function deleteContentFromVector(contentId: string) {
  try {
    const index = pinecone.index(indexName);
    await index.deleteOne(contentId);
    console.log(`Deleted content ${contentId} from vector database`);
  } catch (error) {
    console.error('Error deleting content from vector database:', error);
    throw error;
  }
}



// Update content in Pinecone
export async function updateContentInVector(
  contentId: string,
  userId: string,
  content: {
    title: string;
    description: string;
    type: string;
    link?: string;
    tags?: string[];
  }
) {
  try {
    // Delete old entry
    await deleteContentFromVector(contentId);
    
    // Add updated entry
    await addContentToVector(contentId, userId, content);
    
    console.log(`Updated content ${contentId} in vector database`);
  } catch (error) {
    console.error('Error updating content in vector database:', error);
    throw error;
  }
}

// Batch delete for user
export async function deleteUserContentFromVector(userId: string) {
  try {
    const index = pinecone.index(indexName);
    await index.deleteMany({
      filter: {
        userId: { $eq: userId }
      }
    });
    console.log(`Deleted all content for user ${userId} from vector database`);
  } catch (error) {
    console.error('Error deleting user content from vector database:', error);
    throw error;
  }
}