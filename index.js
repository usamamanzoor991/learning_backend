import express from "express";
import path from "path";
import mongoose from "mongoose";
import cookieParser from "cookie-parser";
import Jwt from "jsonwebtoken";
import bcrypt from "bcrypt";

//Database Connection
mongoose.connect("mongodb://127.0.0.1:27017" , {
    dbName : "Backend"
}).then(() => console.log("Database Connected!")).catch((e) => console.log(e));

//User Schema
const userSchema = new mongoose.Schema({
    name : String,
    email : String,
    hashedPassword : String,
});

//User Model
const User = mongoose.model("User" , userSchema);

//Server Creation
const app = express();

//middle ware
app.use(express.static(path.join(path.resolve() , "public")));
app.use(express.urlencoded({ extended : true}));
app.use(cookieParser());

//setting up view engine
app.set("view engine" , "ejs");

//Routes
const isAuthenticated = async (req,res,next) => {
    const { token } = req.cookies;
    if(token){
        
        //verifying token value
        const vToken = Jwt.verify(token , "My Name Is Kuchu");
        
        //saving user data in req.user and where we use function isAuthenticated we can access user
        req.user = await User.findById(vToken._id);

        next();
    }
    else{
        res.redirect("/login");
    }
}

app.get('/' , isAuthenticated , (req , res) => {

    //Accessing user using isUthenticated Function
    res.render("logout" , { name : req.user.name }); 
});

app.get('/login' , async(req,res) => {
    res.render("login");
})

app.post('/login' ,  async (req , res) => {
    
    //get data from page
    const {email , password} = req.body;
    
    //check if user registered or not 
    let user = await User.findOne({ email });
    if(!user){
        return res.redirect("/register");
    }
    
    //match password
    const isMatch = await bcrypt.compare(password , user.hashedPassword);

    if(!isMatch) return res.render("login" , { email ,message : "Incorrect Password"});

    //create json web token to secure user._id , Jwt.sign means creation of jwt token
    const token = Jwt.sign({_id : user._id} , "My Name Is Kuchu");

    //creation of cookie and encoding cookie data with jwt token
    res.cookie("token" , token ,{
        httpOnly : true,
        expires : new Date(Date.now() + 60 * 1000),
    });
    res.redirect("/");
});

app.get('/register' , async (req,res) => {
    res.render("register");
})

app.post('/register' , async (req , res) => {
    
    //get data from page
    const {name , email , password} = req.body;
    
    //check if user registered or not
    let user = await User.findOne({email});
    if(user){
        return res.redirect("/login");
    }

    const hashedPassword = await bcrypt.hash(password , 10);

    //add data to database
    user = await User.create({
        name , email , hashedPassword ,
    });

    //create json web token to secure user._id , Jwt.sign means creation of jwt token
    const token = Jwt.sign({_id : user._id} , "My Name Is Kuchu");

    //creation of cookie and encoding cookie data with jwt token
    res.cookie("token" , token ,{
        httpOnly : true,
        expires : new Date(Date.now() + 60 * 1000),
    });
    res.redirect("/");
});

app.get('/logout' , async(req , res) => {
    res.cookie("token" , "null" , {
        httpOnly : true,
        expires : new Date(Date.now()),
    });
    res.redirect("/");
});

app.listen(5000 , () => {
    console.log("Server is Working!")
})