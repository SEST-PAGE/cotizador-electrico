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

  // Ensure extra columns exist
  try { await sql`ALTER TABLE usuarios ADD COLUMN IF NOT EXISTS permisos VARCHAR(20) DEFAULT 'vendedor'`; } catch(e) {}
  try { await sql`ALTER TABLE usuarios ADD COLUMN IF NOT EXISTS compartir_datos BOOLEAN DEFAULT false`; } catch(e) {}

  // Verify current role from DB
  const dbUser = await sql`SELECT rol, permisos FROM usuarios WHERE id=${user.id} AND activo=true`;
  if (!dbUser.length) return res.status(401).json({error:'Usuario no encontrado'});

  const isPrincipalAdmin = dbUser[0].rol === 'admin';
  const isAdmin = isPrincipalAdmin || dbUser[0].permisos === 'admin';

  const {id} = req.query;
  try {
    if (req.method==='GET') {
      // Only principal admin can see the full users list
      if (!isPrincipalAdmin) return res.status(403).json({error:'Solo el administrador principal puede gestionar usuarios'});
      const rows = await sql`SELECT id, nombre, email, rol, permisos, compartir_datos, activo, creado_en FROM usuarios ORDER BY creado_en ASC`;
      return res.status(200).json(rows);
    }

    if (req.method==='PUT') {
      if (!id) return res.status(400).json({error:'ID requerido'});
      const targetId = parseInt(id);
      const {rol, permisos, compartir_datos} = req.body;

      // Allow any user to toggle their OWN compartir_datos
      if (compartir_datos !== undefined && targetId === user.id) {
        const r = await sql`UPDATE usuarios SET compartir_datos=${!!compartir_datos} WHERE id=${targetId} RETURNING id, nombre, email, rol, permisos, compartir_datos, activo`;
        if (!r.length) return res.status(404).json({error:'Usuario no encontrado'});
        return res.status(200).json(r[0]);
      }

      // For rol/permisos changes: ONLY principal admin can do this
      if (!isPrincipalAdmin) return res.status(403).json({error:'Solo el administrador principal puede cambiar roles y permisos'});
      if (targetId === user.id) return res.status(400).json({error:'No puedes modificar tu propio rol/permiso'});

      if (permisos !== undefined) {
        if (!['admin','vendedor'].includes(permisos)) return res.status(400).json({error:'Permiso inválido'});
        const r = await sql`UPDATE usuarios SET permisos=${permisos} WHERE id=${targetId} RETURNING id, nombre, email, rol, permisos, compartir_datos, activo`;
        if (!r.length) return res.status(404).json({error:'Usuario no encontrado'});
        return res.status(200).json(r[0]);
      }

      if (rol !== undefined) {
        if (!['admin','vendedor'].includes(rol)) return res.status(400).json({error:'Rol inválido'});
        const r = await sql`UPDATE usuarios SET rol=${rol} WHERE id=${targetId} RETURNING id, nombre, email, rol, permisos, compartir_datos, activo`;
        if (!r.length) return res.status(404).json({error:'Usuario no encontrado'});
        return res.status(200).json(r[0]);
      }

      return res.status(400).json({error:'Nada que actualizar'});
    }
    return res.status(405).json({error:'Método no permitido'});
  } catch(err) { console.error(err); return res.status(500).json({error:err.message}); }
}