const API = window.SHIPNOVA_API || localStorage.getItem('SHIPNOVA_API') || '/api';
const $ = s => document.querySelector(s);
const token = () => localStorage.getItem('shipnova_token');
const user = () => { try { return JSON.parse(localStorage.getItem('shipnova_user')); } catch { return null; } };
async function api(path, opt = {}) {
  const h = {'Content-Type':'application/json', ...(opt.headers || {})};
  if (token()) h.Authorization = 'Bearer ' + token();
  const r = await fetch(API + path, {...opt, headers:h});
  const d = await r.json().catch(() => ({error:'Invalid server response'}));
  if (!r.ok) throw Error(d.error || 'Request failed');
  return d;
}
function saveAuth(d){ localStorage.setItem('shipnova_token', d.token); localStorage.setItem('shipnova_user', JSON.stringify(d.user)); }
function logout(){ localStorage.removeItem('shipnova_token'); localStorage.removeItem('shipnova_user'); location.href='index.html'; }
window.api=api; window.saveAuth=saveAuth; window.logout=logout; window.user=user; window.API=API;
