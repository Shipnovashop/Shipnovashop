const API = window.SHIPNOVA_API || "/api";
const TOKEN_KEY = "shipnova_token";
const USER_KEY = "shipnova_user";
const CART_KEY = "shipnova_cart";
const WISH_KEY = "shipnova_wishlist";

function getToken(){ return localStorage.getItem(TOKEN_KEY) || ""; }
function getUser(){ try{return JSON.parse(localStorage.getItem(USER_KEY)||"null")}catch{return null} }
function saveAuth(data){
  if(data.token) localStorage.setItem(TOKEN_KEY,data.token);
  if(data.user) localStorage.setItem(USER_KEY,JSON.stringify(data.user));
}
function logout(){
  localStorage.removeItem(TOKEN_KEY);
  localStorage.removeItem(USER_KEY);
  location.href="index.html";
}
async function api(path, options={}){
  const headers = {"Content-Type":"application/json", ...(options.headers||{})};
  const token=getToken();
  if(token) headers.Authorization="Bearer "+token;
  const res=await fetch(API+path,{...options,headers});
  const text=await res.text();
  let data={}; try{data=text?JSON.parse(text):{}}catch{data={message:text}};
  if(!res.ok) throw new Error(data.message||"Request failed");
  return data;
}
function money(v){ return "₹"+Number(v||0).toLocaleString("en-IN",{minimumFractionDigits:2,maximumFractionDigits:2}); }
function escapeHtml(s){
  return String(s??"").replace(/[&<>"']/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#039;"}[c]));
}
function getCart(){try{return JSON.parse(localStorage.getItem(CART_KEY)||"[]")}catch{return[]}}
function saveCart(c){localStorage.setItem(CART_KEY,JSON.stringify(c))}
function addToCart(product, qty=1, variant=null){
  const c=getCart(), key=product.id+":"+(variant?.id||"0");
  const x=c.find(i=>i.key===key);
  if(x)x.quantity+=qty; else c.push({key,product,quantity:qty,variant});
  saveCart(c); alert("Product cart में add हो गया");
}
function cartCount(){return getCart().reduce((n,x)=>n+Number(x.quantity||0),0)}
function toggleWish(product){
  let w; try{w=JSON.parse(localStorage.getItem(WISH_KEY)||"[]")}catch{w=[]}
  const i=w.findIndex(x=>x.id===product.id);
  if(i>=0){w.splice(i,1);alert("Wishlist से हटाया");}else{w.push(product);alert("Wishlist में add किया");}
  localStorage.setItem(WISH_KEY,JSON.stringify(w)); return i<0;
}
function stars(r){const n=Math.round(Number(r||0));return "★".repeat(n)+"☆".repeat(5-n)}