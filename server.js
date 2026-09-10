
const express = require("express");
const session = require("express-session");
const bcrypt = require("bcryptjs");
const Database = require("better-sqlite3");
const path = require("path");

const app = express();
const db = new Database("savestickersfree.db");
db.exec(`
CREATE TABLE IF NOT EXISTS users (
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 username TEXT UNIQUE NOT NULL,
 email TEXT UNIQUE NOT NULL,
 password TEXT NOT NULL,
 created_at TEXT DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS favorites (
 user_id INTEGER NOT NULL,
 sticker TEXT NOT NULL,
 UNIQUE(user_id, sticker)
);
`);

app.use(express.json());
app.use(express.static(__dirname));
app.use(session({
 secret: process.env.SESSION_SECRET || "change-this-secret",
 resave: false, saveUninitialized: false,
 cookie: { httpOnly: true, sameSite: "lax", secure: false }
}));

const stickers = [
 ["😂","Risa","Memes"],["🤣","Carcajada","Memes"],["😭","Lloro","Memes"],["💀","Me morí de risa","Memes"],
 ["🐱","Gatito","Animales"],["🐶","Perrito","Animales"],["🦄","Unicornio","Animales"],["🐼","Panda","Animales"],
 ["🎮","Gaming","Gaming"],["👾","Pixel","Gaming"],["🏆","Victoria","Gaming"],["🕹️","Arcade","Gaming"],
 ["❤️","Corazón","Amor"],["😍","Enamorado","Amor"],["💖","Corazón rosa","Amor"],["🥰","Cariño","Amor"],
 ["😎","Cool","Emojis"],["🤔","Pensando","Emojis"],["🥳","Fiesta","Emojis"],["🤩","Wow","Emojis"]
];

app.get("/api/stickers", (req,res)=>res.json(stickers));

app.post("/api/register", async (req,res)=>{
 const {username,email,password}=req.body;
 if(!username || !email || !password || password.length < 8)
   return res.status(400).json({error:"Completa todos los campos. La contraseña debe tener al menos 8 caracteres."});
 try {
   const hash=await bcrypt.hash(password,12);
   const info=db.prepare("INSERT INTO users(username,email,password) VALUES(?,?,?)").run(username.trim(),email.trim().toLowerCase(),hash);
   req.session.userId=info.lastInsertRowid;
   res.json({ok:true,username:username.trim()});
 } catch(e){ res.status(400).json({error:"Ese usuario o correo ya está registrado."}); }
});

app.post("/api/login", async (req,res)=>{
 const {email,password}=req.body;
 const user=db.prepare("SELECT * FROM users WHERE email=?").get((email||"").trim().toLowerCase());
 if(!user || !(await bcrypt.compare(password||"",user.password)))
   return res.status(401).json({error:"Correo o contraseña incorrectos."});
 req.session.userId=user.id;
 res.json({ok:true,username:user.username});
});

app.post("/api/logout",(req,res)=>req.session.destroy(()=>res.json({ok:true})));

app.get("/api/me",(req,res)=>{
 if(!req.session.userId) return res.json({loggedIn:false});
 const u=db.prepare("SELECT id,username,email FROM users WHERE id=?").get(req.session.userId);
 res.json({loggedIn:true,...u});
});

app.get("/api/favorites",(req,res)=>{
 if(!req.session.userId) return res.status(401).json({error:"Inicia sesión."});
 res.json(db.prepare("SELECT sticker FROM favorites WHERE user_id=?").all(req.session.userId).map(x=>x.sticker));
});

app.post("/api/favorites",(req,res)=>{
 if(!req.session.userId) return res.status(401).json({error:"Inicia sesión para guardar favoritos."});
 const sticker=String(req.body.sticker||"");
 const exists=db.prepare("SELECT 1 FROM favorites WHERE user_id=? AND sticker=?").get(req.session.userId,sticker);
 if(exists) db.prepare("DELETE FROM favorites WHERE user_id=? AND sticker=?").run(req.session.userId,sticker);
 else db.prepare("INSERT OR IGNORE INTO favorites(user_id,sticker) VALUES(?,?)").run(req.session.userId,sticker);
 res.json({saved:!exists});
});

app.gapp.get("*",(req,res)=>res.sendFile(path.join(__dirname,"index.html")));
app.listen(process.env.PORT||3000,()=>console.log("SaveStickersFree running"));
