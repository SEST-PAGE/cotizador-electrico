import { getDb } from '../_lib/db.js';
import jwt from 'jsonwebtoken';

function getUser(req) {
  try { return jwt.verify((req.headers['authorization']||'').replace('Bearer ',''), process.env.JWT_SECRET||'secreto-dev'); }
  catch { return null; }
}

async function checkAdmin(sql, userId) {
  try {
    await sql`ALTER TABLE usuarios ADD COLUMN IF NOT EXISTS permisos VARCHAR(20) DEFAULT 'vendedor'`;
  } catch(e) {}
  const rows = await sql`SELECT rol, permisos FROM usuarios WHERE id=${userId}`;
  if (!rows.length) return false;
  return rows[0].rol === 'admin' || rows[0].permisos === 'admin';
}

export default async function handler(req, res) {
  res.setHeader('Access-Control-Allow-Origin','*');
  res.setHeader('Access-Control-Allow-Methods','GET,POST,PUT,DELETE,OPTIONS');
  res.setHeader('Access-Control-Allow-Headers','Content-Type,Authorization');
  if (req.method==='OPTIONS') return res.status(204).end();
  const user = getUser(req);
  if (!user) return res.status(401).json({error:'No autorizado'});
  const sql = getDb();
  const {q,categoria,page='1',limit='200',id} = req.query;
  try {
    if (req.method==='GET') {
      const l=parseInt(limit), off=(parseInt(page)-1)*l;
      let mats;
      if (q&&categoria) {
        mats = await sql`SELECT m.*,c.nombre AS categoria_nombre FROM materiales m LEFT JOIN categorias c ON m.categoria_id=c.id WHERE m.activo=true AND (m.nombre ILIKE ${'%'+q+'%'} OR m.codigo ILIKE ${'%'+q+'%'}) AND m.categoria_id=${parseInt(categoria)} ORDER BY m.nombre LIMIT ${l} OFFSET ${off}`;
      } else if (q) {
        mats = await sql`SELECT m.*,c.nombre AS categoria_nombre FROM materiales m LEFT JOIN categorias c ON m.categoria_id=c.id WHERE m.activo=true AND (m.nombre ILIKE ${'%'+q+'%'} OR m.codigo ILIKE ${'%'+q+'%'}) ORDER BY m.nombre LIMIT ${l} OFFSET ${off}`;
      } else if (categoria) {
        mats = await sql`SELECT m.*,c.nombre AS categoria_nombre FROM materiales m LEFT JOIN categorias c ON m.categoria_id=c.id WHERE m.activo=true AND m.categoria_id=${parseInt(categoria)} ORDER BY m.nombre LIMIT ${l} OFFSET ${off}`;
      } else {
        mats = await sql`SELECT m.*,c.nombre AS categoria_nombre FROM materiales m LEFT JOIN categorias c ON m.categoria_id=c.id WHERE m.activo=true ORDER BY m.nombre LIMIT ${l} OFFSET ${off}`;
      }
      const cats = await sql`SELECT * FROM categorias ORDER BY nombre`;
      return res.status(200).json({materiales:mats,categorias:cats});
    }
    if (req.method==='POST') {
      const {codigo,nombre,descripcion,categoria_id,unidad,precio_costo,precio_venta,stock} = req.body;
      if (!codigo||!nombre||precio_venta===undefined) return res.status(400).json({error:'Código, nombre y precio son requeridos'});
      const r = await sql`INSERT INTO materiales(codigo,nombre,descripcion,categoria_id,unidad,precio_costo,precio_venta,stock) VALUES(${codigo},${nombre},${descripcion||''},${categoria_id||null},${unidad||'unidad'},${precio_costo||0},${precio_venta},${stock||0}) RETURNING *`;
      return res.status(201).json(r[0]);
    }
    if (req.method==='PUT') {
      if (!id) return res.status(400).json({error:'ID requerido'});
      const {nombre,descripcion,categoria_id,unidad,precio_costo,precio_venta,stock} = req.body;
      const r = await sql`UPDATE materiales SET nombre=${nombre},descripcion=${descripcion||''},categoria_id=${categoria_id||null},unidad=${unidad},precio_costo=${precio_costo},precio_venta=${precio_venta},stock=${stock},actualizado_en=NOW() WHERE id=${parseInt(id)} RETURNING *`;
      return res.status(200).json(r[0]);
    }
    if (req.method==='DELETE') {
      const isAdmin = await checkAdmin(sql, user.id);
      if (!isAdmin) return res.status(403).json({error:'Solo los administradores pueden eliminar materiales'});
      if (!id) return res.status(400).json({error:'ID requerido'});
      await sql`UPDATE materiales SET activo=false WHERE id=${parseInt(id)}`;
      return res.status(200).json({success:true});
    }
    return res.status(405).json({error:'Método no permitido'});
  } catch(err) { console.error(err); return res.status(500).json({error:err.message}); }
}