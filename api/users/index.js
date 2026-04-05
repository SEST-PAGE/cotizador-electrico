import { getDb } from '../_lib/db.js';
import jwt from 'jsonwebtoken';

function getUser(req) {
  try { return jwt.verify((req.headers['authorization']||'').replace('Bearer ',''), process.env.JWT_SECRET||'secreto-dev'); }
  catch { return null; }
}

export default async function handler(req, res) {
  res.setHeader('Access-Control-Allow-Origin','*');
  res.setHeader('Access-Control-Allow-Methods','GET,PUT,OPTIONS');
  res.setHeader('Access-Control-Allow-Headers','Content-Type,Authorization');
  if (req.method==='OPTIONS') return res.status(204).end();
  const user = getUser(req);
  if (!user) return res.status(401).json({error:'No autorizado'});

  const sql = getDb();
  // Ensure permisos column exists
  try { await sql`ALTER TABLE usuarios ADD COLUMN IF NOT EXISTS permisos VARCHAR(20) DEFAULT 'vendedor'`; } catch(e) {}

  // Verify current role/permisos from DB (permisos can change without re-login)
  const dbUser = await sql`SELECT rol, permisos FROM usuarios WHERE id=${user.id} AND activo=true`;
  if (!dbUser.length) return res.status(401).json({error:'Usuario no encontrado'});
  const isAdmin = dbUser[0].rol === 'admin' || dbUser[0].permisos === 'admin';
  if (!isAdmin) return res.status(403).json({error:'Solo administradores pueden gestionar usuarios'});

  const {id} = req.query;
  try {
    if (req.method==='GET') {
      const rows = await sql`SELECT id, nombre, email, rol, permisos, activo, creado_en FROM usuarios ORDER BY creado_en ASC`;
      return res.status(200).json(rows);
    }
    if (req.method==='PUT') {
      if (!id) return res.status(400).json({error:'ID requerido'});
      if (parseInt(id) === user.id) return res.status(400).json({error:'No puedes modificar tu propio rol/permiso'});
      const {rol, permisos} = req.body;
      if (permisos !== undefined) {
        if (!['admin','vendedor'].includes(permisos)) return res.status(400).json({error:'Permiso inválido'});
        const r = await sql`UPDATE usuarios SET permisos=${permisos} WHERE id=${parseInt(id)} RETURNING id, nombre, email, rol, permisos, activo`;
        if (!r.length) return res.status(404).json({error:'Usuario no encontrado'});
        return res.status(200).json(r[0]);
      }
      if (!['admin','vendedor'].includes(rol)) return res.status(400).json({error:'Rol inválido'});
      const r = await sql`UPDATE usuarios SET rol=${rol} WHERE id=${parseInt(id)} RETURNING id, nombre, email, rol, permisos, activo`;
      if (!r.length) return res.status(404).json({error:'Usuario no encontrado'});
      return res.status(200).json(r[0]);
    }
    return res.status(405).json({error:'Método no permitido'});
  } catch(err) { console.error(err); return res.status(500).json({error:err.message}); }
}