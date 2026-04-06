import { getDb } from '../_lib/db.js';
import jwt from 'jsonwebtoken';

function getUser(req) {
  try { return jwt.verify((req.headers['authorization']||'').replace('Bearer ',''), process.env.JWT_SECRET||'secreto-dev'); }
  catch { return null; }
}
function numCot() {
  const d=new Date();
  return `COT-${d.getFullYear()}${String(d.getMonth()+1).padStart(2,'0')}-${Math.floor(Math.random()*9000)+1000}`;
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
      // Equipo mode: return quotes from users who have compartir_datos=true
      if (equipo === '1') {
        const rows = await sql`
          SELECT c.id,c.numero,c.titulo,c.estado,c.total,c.subtotal,c.iva_valor,c.descuento_valor,c.creado_en,
            cl.nombre AS cliente_nombre, cl.empresa AS cliente_empresa,
            u.nombre AS usuario_nombre
          FROM cotizaciones c
          LEFT JOIN clientes cl ON c.cliente_id=cl.id
          JOIN usuarios u ON c.usuario_id=u.id
          WHERE u.compartir_datos=true
          ORDER BY c.creado_en DESC LIMIT 500`;
        return res.status(200).json(rows);
      }

      if (id) {
        const cots = await sql`
          SELECT c.*,
            cl.nombre AS cliente_nombre, cl.empresa AS cliente_empresa,
            cl.email AS cliente_email, cl.telefono AS cliente_telefono,
            cl.ruc_cedula AS cliente_ruc, cl.direccion AS cliente_direccion,
            u.nombre AS usuario_nombre
          FROM cotizaciones c
          LEFT JOIN clientes cl ON c.cliente_id=cl.id
          LEFT JOIN usuarios u ON c.usuario_id=u.id
          WHERE c.id=${parseInt(id)} AND c.usuario_id=${user.id}`;
        if (!cots.length) return res.status(404).json({error:'No encontrada'});
        const items = await sql`
          SELECT ci.*, m.codigo, m.nombre AS material_nombre, m.unidad AS material_unidad
          FROM cotizacion_items ci
          LEFT JOIN materiales m ON ci.material_id=m.id
          WHERE ci.cotizacion_id=${parseInt(id)} ORDER BY ci.id`;
        return res.status(200).json({...cots[0], items});
      }
      const rows = await sql`
        SELECT c.id,c.numero,c.titulo,c.estado,c.total,c.subtotal,c.iva_valor,c.descuento_valor,c.creado_en,
          cl.nombre AS cliente_nombre, cl.empresa AS cliente_empresa
        FROM cotizaciones c
        LEFT JOIN clientes cl ON c.cliente_id=cl.id
        WHERE c.usuario_id=${user.id}
        ORDER BY c.creado_en DESC LIMIT 500`;
      return res.status(200).json(rows);
    }

    if (req.method==='POST') {
      const {cliente_id,titulo,descripcion='',items=[],descuento_pct=0,iva_pct=15,notas='',validez_dias=30} = req.body;
      if (!titulo) return res.status(400).json({error:'El título es requerido'});
      const sub   = items.reduce((s,i)=>s+i.cantidad*i.precio_unitario*(1-(i.descuento_pct||0)/100),0);
      const dv    = sub*(descuento_pct/100);
      const base  = sub-dv;
      const iv    = base*(iva_pct/100);
      const total = base+iv;
      const num   = numCot();
      const cliId = cliente_id ? parseInt(cliente_id) : null;
      const cot = await sql`
        INSERT INTO cotizaciones(numero,cliente_id,usuario_id,titulo,descripcion,estado,subtotal,descuento_pct,descuento_valor,iva_pct,iva_valor,total,notas,validez_dias)
        VALUES(${num},${cliId},${user.id},${titulo},${descripcion},'borrador',${sub},${descuento_pct},${dv},${iva_pct},${iv},${total},${notas},${validez_dias})
        RETURNING *`;
      for (const item of items) {
        await sql`INSERT INTO cotizacion_items(cotizacion_id,material_id,descripcion,cantidad,unidad,precio_unitario,descuento_pct) VALUES(${cot[0].id},${item.material_id||null},${item.descripcion||''},${item.cantidad},${item.unidad||'unidad'},${item.precio_unitario},${item.descuento_pct||0})`;
      }
      return res.status(201).json(cot[0]);
    }

    if (req.method==='PUT') {
      if (!id) return res.status(400).json({error:'ID requerido'});
      const own = await sql`SELECT id FROM cotizaciones WHERE id=${parseInt(id)} AND usuario_id=${user.id}`;
      if (!own.length) return res.status(403).json({error:'No tienes permiso'});

      const {estado, titulo, notas, _fullEdit, items, descuento_pct, iva_pct, validez_dias, descripcion, cliente_id} = req.body;

      if (_fullEdit && items) {
        const dp = parseFloat(descuento_pct)||0;
        const ip = parseFloat(iva_pct)||0;
        const sub = items.reduce((s,i)=>s+(parseFloat(i.cantidad)||0)*(parseFloat(i.precio_unitario)||0)*(1-(parseFloat(i.descuento_pct)||0)/100),0);
        const dv = sub*(dp/100);
        const base = sub-dv;
        const iv = base*(ip/100);
        const total = base+iv;
        const cliId = cliente_id ? parseInt(cliente_id) : null;
        const r = await sql`UPDATE cotizaciones SET
          titulo=COALESCE(${titulo||null},titulo),
          descripcion=COALESCE(${descripcion||null},descripcion),
          notas=COALESCE(${notas||null},notas),
          cliente_id=COALESCE(${cliId},cliente_id),
          subtotal=${sub},
          descuento_pct=${dp},
          descuento_valor=${dv},
          iva_pct=${ip},
          iva_valor=${iv},
          total=${total},
          validez_dias=COALESCE(${validez_dias||null},validez_dias),
          actualizado_en=NOW()
          WHERE id=${parseInt(id)} RETURNING *`;
        await sql`DELETE FROM cotizacion_items WHERE cotizacion_id=${parseInt(id)}`;
        for (const item of items) {
          await sql`INSERT INTO cotizacion_items(cotizacion_id,material_id,descripcion,cantidad,unidad,precio_unitario,descuento_pct) VALUES(${parseInt(id)},${item.material_id||null},${item.descripcion||''},${parseFloat(item.cantidad)||1},${item.unidad||'unidad'},${parseFloat(item.precio_unitario)||0},${parseFloat(item.descuento_pct)||0})`;
        }
        return res.status(200).json(r[0]);
      }

      const r = await sql`UPDATE cotizaciones SET estado=COALESCE(${estado||null},estado),titulo=COALESCE(${titulo||null},titulo),notas=COALESCE(${notas||null},notas),actualizado_en=NOW() WHERE id=${parseInt(id)} RETURNING *`;
      return res.status(200).json(r[0]);
    }

    if (req.method==='DELETE') {
      if (!id) return res.status(400).json({error:'ID requerido'});
      const own = await sql`SELECT id FROM cotizaciones WHERE id=${parseInt(id)} AND usuario_id=${user.id}`;
      if (!own.length) return res.status(403).json({error:'No tienes permiso'});
      await sql`DELETE FROM cotizacion_items WHERE cotizacion_id=${parseInt(id)}`;
      await sql`DELETE FROM cotizaciones WHERE id=${parseInt(id)} AND usuario_id=${user.id}`;
      return res.status(200).json({success:true});
    }

    return res.status(405).json({error:'Método no permitido'});
  } catch(err) { console.error(err); return res.status(500).json({error:err.message}); }
}