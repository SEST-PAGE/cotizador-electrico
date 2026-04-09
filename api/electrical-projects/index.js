// ═══════════════════════════════════════════════════════════════
// API ENDPOINT: /api/electrical-projects/index.js
// Compatible con el patrón de rutas de SEST · Cotizador
// Neon PostgreSQL — tabla: electrical_projects
// ═══════════════════════════════════════════════════════════════

import { Pool } from 'pg';
import jwt from 'jsonwebtoken';

// ── Conexión Neon PostgreSQL ─────────────────────────────────
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false },
});

// ── Helper: verificar JWT y obtener usuario ──────────────────
function getUsuario(req) {
  try {
    const auth = req.headers.authorization || '';
    const token = auth.replace('Bearer ', '').trim();
    if (!token) return null;
    return jwt.verify(token, process.env.JWT_SECRET);
  } catch {
    return null;
  }
}

// ── Helper: respuesta JSON ───────────────────────────────────
const ok  = (res, data)   => res.status(200).json(data);
const err = (res, msg, status = 400) => res.status(status).json({ error: msg });

// ═══════════════════════════════════════════════════════════════
// HANDLER PRINCIPAL
// ═══════════════════════════════════════════════════════════════
export default async function handler(req, res) {
  // CORS (ajusta si tu backend ya lo maneja globalmente)
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  if (req.method === 'OPTIONS') return res.status(200).end();

  // Autenticación
  const usuario = getUsuario(req);
  if (!usuario) return err(res, 'No autorizado', 401);

  const userId = usuario.id;
  const { id } = req.query;

  // ── GET: listar todos los proyectos del usuario ────────────
  if (req.method === 'GET') {
    try {
      const { rows } = await pool.query(
        `SELECT
           id, user_id, nombre, cliente, ubicacion,
           tipo, temp_f, sistema, cargas,
           created_at AS "createdAt",
           updated_at AS "updatedAt"
         FROM electrical_projects
         WHERE user_id = $1
         ORDER BY updated_at DESC`,
        [userId]
      );
      return ok(res, rows);
    } catch (e) {
      console.error('[electrical-projects GET]', e.message);
      return err(res, 'Error al obtener proyectos', 500);
    }
  }

  // ── POST: crear nuevo proyecto ─────────────────────────────
  if (req.method === 'POST') {
    const { nombre, cliente, ubicacion, tipo, temp_f, sistema, cargas } = req.body;

    if (!nombre || !nombre.trim()) return err(res, 'El nombre del proyecto es requerido');

    try {
      const { rows } = await pool.query(
        `INSERT INTO electrical_projects
           (user_id, nombre, cliente, ubicacion, tipo, temp_f, sistema, cargas)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
         RETURNING
           id, user_id, nombre, cliente, ubicacion, tipo, temp_f, sistema, cargas,
           created_at AS "createdAt", updated_at AS "updatedAt"`,
        [
          userId,
          nombre.trim(),
          cliente?.trim() || null,
          ubicacion?.trim() || null,
          tipo || 'residencial',
          temp_f || '1.0',
          sistema || '120',
          JSON.stringify(cargas || []),
        ]
      );
      return ok(res, rows[0]);
    } catch (e) {
      console.error('[electrical-projects POST]', e.message);
      return err(res, 'Error al guardar proyecto', 500);
    }
  }

  // ── PUT: actualizar proyecto existente ─────────────────────
  if (req.method === 'PUT') {
    if (!id) return err(res, 'ID del proyecto requerido');

    const { nombre, cliente, ubicacion, tipo, temp_f, sistema, cargas } = req.body;

    if (!nombre || !nombre.trim()) return err(res, 'El nombre del proyecto es requerido');

    try {
      // Verificar que el proyecto pertenezca al usuario
      const check = await pool.query(
        'SELECT id FROM electrical_projects WHERE id = $1 AND user_id = $2',
        [id, userId]
      );
      if (!check.rows.length) return err(res, 'Proyecto no encontrado', 404);

      const { rows } = await pool.query(
        `UPDATE electrical_projects SET
           nombre     = $1,
           cliente    = $2,
           ubicacion  = $3,
           tipo       = $4,
           temp_f     = $5,
           sistema    = $6,
           cargas     = $7,
           updated_at = NOW()
         WHERE id = $8 AND user_id = $9
         RETURNING
           id, user_id, nombre, cliente, ubicacion, tipo, temp_f, sistema, cargas,
           created_at AS "createdAt", updated_at AS "updatedAt"`,
        [
          nombre.trim(),
          cliente?.trim() || null,
          ubicacion?.trim() || null,
          tipo || 'residencial',
          temp_f || '1.0',
          sistema || '120',
          JSON.stringify(cargas || []),
          id,
          userId,
        ]
      );
      return ok(res, rows[0]);
    } catch (e) {
      console.error('[electrical-projects PUT]', e.message);
      return err(res, 'Error al actualizar proyecto', 500);
    }
  }

  // ── DELETE: eliminar proyecto ──────────────────────────────
  if (req.method === 'DELETE') {
    if (!id) return err(res, 'ID del proyecto requerido');

    try {
      const { rowCount } = await pool.query(
        'DELETE FROM electrical_projects WHERE id = $1 AND user_id = $2',
        [id, userId]
      );
      if (!rowCount) return err(res, 'Proyecto no encontrado', 404);
      return ok(res, { deleted: true, id });
    } catch (e) {
      console.error('[electrical-projects DELETE]', e.message);
      return err(res, 'Error al eliminar proyecto', 500);
    }
  }

  return err(res, 'Método no permitido', 405);
}