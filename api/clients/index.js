import { getDb } from '../_lib/db.js';
import jwt from 'jsonwebtoken';

function getUser(req) {
  try { return jwt.verify((req.headers['authorization']||'').replace('Bearer ',''), process.env.JWT_SECRET||'secreto-dev'); }
  catch { return null; }
}

export default async function handler(req, res) {
  res.setHeader('Access-Control-Allow-Origin','*');
  res.setHeader('Access-Control-Allow-Methods','GET,POST,PUT,DELETE,OPTIONS');
  res.setHeader('Access-Control-Allow-Headers','Content-Type,Authorization');
  if (req.method==='OPTIONS') return res.status(204).end();
  const user = getUser(req);
  if (!user) return res.status(401).json({error:'No autorizado'});
  const sql = getDb();
  try { await sql`ALTER TABLE usuarios ADD COLUMN IF NOT EXISTS compartir_datos BOOLEAN DEFAULT false`; } catch(e) {}
  const {id, equipo} = req.query;
  try {
    if (req.method==='GET') {
      // Equipo mode: return clients from users who have compartir_datos=true
      if (equipo === '1') {
        const rows = await sql`
          SELECT c.*, u.nombre AS usuario_nombre
          FROM clientes c
          JOIN usuarios u ON c.usuario_id=u.id
          WHERE u.compartir_datos=true
          ORDER BY c.nombre ASC LIMIT 500`;
        return res.status(200).json(rows);
      }
      const rows = await sql`SELECT * FROM clientes WHERE usuario_id=${user.id} ORDER BY nombre ASC LIMIT 500`;
      return res.status(200).json(rows);
    }
    if (req.method==='POST') {
      const {nombre,empresa,email,telefono,direccion,ruc_cedula,notas} = req.body;
      if (!nombre) return res.status(400).json({error:'El nombre es requerido'});
      const r = await sql`INSERT INTO clientes(nombre,empresa,email,telefono,direccion,ruc_cedula,notas,usuario_id) VALUES(${nombre},${empresa||''},${email||''},${telefono||''},${direccion||''},${ruc_cedula||''},${notas||''},${user.id}) RETURNING *`;
      return res.status(201).json(r[0]);
    }
    if (req.method==='PUT') {
      if (!id) return res.status(400).json({error:'ID requerido'});
      const {nombre,empresa,email,telefono,direccion,ruc_cedula,notas} = req.body;
      if (!nombre) return res.status(400).json({error:'Nombre requerido'});
      const own = await sql`SELECT id FROM clientes WHERE id=${parseInt(id)} AND usuario_id=${user.id}`;
      if (!own.length) return res.status(403).json({error:'No tienes permiso'});
      const r = await sql`UPDATE clientes SET nombre=${nombre},empresa=${empresa||''},email=${email||''},telefono=${telefono||''},direccion=${direccion||''},ruc_cedula=${ruc_cedula||''},notas=${notas||''} WHERE id=${parseInt(id)} AND usuario_id=${user.id} RETURNING *`;
      return res.status(200).json(r[0]);
    }
    if (req.method==='DELETE') {
      if (!id) return res.status(400).json({error:'ID requerido'});
      const own = await sql`SELECT id FROM clientes WHERE id=${parseInt(id)} AND usuario_id=${user.id}`;
      if (!own.length) return res.status(403).json({error:'No tienes permiso'});
      await sql`DELETE FROM clientes WHERE id=${parseInt(id)} AND usuario_id=${user.id}`;
      return res.status(200).json({success:true});
    }
    return res.status(405).json({error:'Método no permitido'});
  } catch(err) { console.error(err); return res.status(500).json({error:err.message}); }
}