import mongoose from "mongoose"
const Schema = mongoose.Schema;
import dotenv from "dotenv";
import { optional } from "zod";
dotenv.config();
if (!process.env.MONGODBURI) {
  throw new Error("MONGOURI environment variable is not defined");
}

mongoose.connect(process.env.MONGODBURI);

// Add these connection handlers
mongoose.connection.on('connected', () => {
  console.log('Connected to MongoDB');
});

mongoose.connection.on('error', (err) => {
  console.error('MongoDB connection error:', err);
});

const userSchema = new Schema({
  username: {
    type:String,
    required:true,
    unique:true},
  password: {
    type:String,
    required:true
  }
})

const tagSchema = new Schema({
  tag: {type:String, required:true, unique:true, trim:true},
})
const contentTypes = ['image','video', 'article', 'audio','youtube', 'twitter','note'];

const contentSchema = new Schema({
  link: {type:String, required:false},
  type: {type:String, enum:contentTypes, required:true},
  title:{type:String,required:true},
  tags: [{type: Schema.Types.ObjectId, ref:'Tags'}],
  userId: {type: Schema.Types.ObjectId, ref:'Users', required:true},
  description: {type:String, required:true}

})

const linkSchema = new Schema({
  hash:String,
  userId:{type:Schema.Types.ObjectId, ref: 'Users', required:true, unique:true}
})



export const userModel = mongoose.model('Users',userSchema)
export const contentModel = mongoose.model('Contents',contentSchema)
export const tagModel = mongoose.model('Tags',tagSchema)
export const linkModel = mongoose.model('Links',linkSchema)