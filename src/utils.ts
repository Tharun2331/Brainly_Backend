import dotenv from "dotenv";
dotenv.config();
const options = process.env.RANDOM_STRING;
  
export function Random(len:number) {
    const length = (options as string).length;
    let result="";
    for(let i=0; i<len; i++)
    {
      result+= (options as string)[Math.floor((Math.random()*length))]
    }
    return result;
}