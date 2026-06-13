import express from 'express';
import dotenv from 'dotenv';
import crypto from 'crypto';
import QRCode from 'qrcode';
import fs from 'fs/promises';
import path from 'path';
import { fileURLToPath } from 'url';
import { initDb, db } from './db.js';
import { verifyQrToken } from './controllers/verificationController.js';


dotenv.config();

// Initialiser la base de données SQLite native
initDb();

const app = express();
const PORT = process.env.PORT || 4000;
const FRONTEND_URL = process.env.FRONTEND_URL || 'http://localhost:5175';

// URL publique pour les QR Codes — doit pointer vers le FRONTEND (Vercel)
// afin que le scan QR ouvre la page de vérification visuelle.
// En production : APP_PUBLIC_URL=https://project-spa-eight.vercel.app
// En local      : laisser vide pour utiliser FRONTEND_URL
let APP_PUBLIC_URL = (process.env.APP_PUBLIC_URL || FRONTEND_URL).replace(/\/$/, '');

// Détermine si on est en mode développement local
let IS_LOCAL_DEV = APP_PUBLIC_URL.includes('localhost');


// Construit l'URL de vérification publique complète pour le QR Code
function getPublicVerifyUrl(token) {
  const baseUrl = APP_PUBLIC_URL || FRONTEND_URL;
  return `${baseUrl}/verification/${token}`;
}

app.use(express.json());

// ======================================================================
// CORS Middleware
// ======================================================================
app.use((req, res, next) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS, PUT, DELETE');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  if (req.method === 'OPTIONS') {
    return res.sendStatus(200);
  }
  next();
});

// ======================================================================
// HELPER FUNCTIONS
// ======================================================================
function generateId(prefix) {
  return prefix + '-' + crypto.randomUUID().substring(0, 8);
}

function getDocStatus(validUntilStr) {
  if (!validUntilStr) return 'Expiré';
  const today = new Date();
  today.setHours(0, 0, 0, 0);
  const validUntil = new Date(validUntilStr);
  validUntil.setHours(0, 0, 0, 0);

  if (isNaN(validUntil.getTime())) {
    return 'Expiré';
  }

  if (validUntil < today) {
    return 'Expiré';
  }

  const diffTime = validUntil - today;
  const diffDays = Math.ceil(diffTime / (1000 * 60 * 60 * 24));
  if (diffDays >= 0 && diffDays <= 30) {
    return 'Expire bientôt';
  }
  return 'Valide';
}

function logAudit(action, details, userId = null, ip = null) {
  try {
    db.prepare("INSERT INTO audit_logs (user_id, action, details, ip_address) VALUES (?, ?, ?, ?)")
      .run(userId, action, details, ip);
  } catch (err) {
    console.error('⚠️ Audit log error:', err.message);
  }
}

// ======================================================================
// SÉCURITÉ / MIDDLEWARES D'AUTHENTIFICATION & PERMISSIONS
// ======================================================================
function authenticate(req, res, next) {
  const authHeader = req.headers['authorization'];
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Accès refusé. Session absente.' });
  }
  const token = authHeader.substring(7);
  try {
    const user = db.prepare("SELECT * FROM users WHERE session_token = ? AND is_active = 1").get(token);
    if (!user) {
      return res.status(401).json({ error: 'Session invalide ou expirée.' });
    }
    req.user = user;
    next();
  } catch (err) {
    console.error('Auth middleware error:', err);
    return res.status(500).json({ error: 'Erreur interne de sécurité.' });
  }
}

function requirePermission(permission) {
  return (req, res, next) => {
    try {
      const roleRow = db.prepare("SELECT permissions FROM roles WHERE name = ?").get(req.user.role);
      if (!roleRow) {
        return res.status(403).json({ error: 'Rôle introuvable.' });
      }
      const permissions = JSON.parse(roleRow.permissions || '[]');
      if (!permissions.includes(permission)) {
        return res.status(403).json({ error: 'Accès refusé. Permissions insuffisantes.' });
      }
      next();
    } catch (err) {
      console.error('Permission check error:', err);
      return res.status(500).json({ error: 'Erreur interne de sécurité.' });
    }
  };
}

// ======================================================================
// 1. AUTHENTIFICATION / LOGIN
// ======================================================================
app.post('/api/auth/login', (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({ error: 'Email et mot de passe requis.' });
  }

  try {
    const user = db.prepare(
      "SELECT * FROM users WHERE email = ? AND password_hash = ? AND is_active = 1"
    ).get(email, password);

    if (user) {
      const sessionToken = crypto.randomUUID();
      db.prepare("UPDATE users SET session_token = ? WHERE id = ?").run(sessionToken, user.id);

      // Récupérer les centres assignés (pour les agents)
      const centerIds = db.prepare("SELECT center_id FROM user_centers WHERE user_id = ?").all(user.id).map(r => r.center_id);

      logAudit('USER_LOGIN', `Connexion réussie : ${user.username}`, user.id, req.ip);
      res.json({
        id: user.id,
        name: user.name,
        role: user.role,
        email: user.email,
        token: sessionToken,
        center_ids: centerIds
      });
    } else {
      logAudit('USER_LOGIN_FAILED', `Tentative échouée pour : ${email}`, null, req.ip);
      res.status(401).json({ error: 'Identifiants invalides. Vérifiez votre email et mot de passe.' });
    }
  } catch (err) {
    console.error('💥 Erreur Auth Login:', err);
    res.status(500).json({ error: 'Erreur interne du serveur.' });
  }
});

// ======================================================================
// 2. VEHICLES — GET ALL
// ======================================================================
app.get('/api/vehicles', authenticate, (req, res) => {
  try {
    let rows;
    if (req.user.role === 'agent') {
      rows = db.prepare(`
        SELECT 
          v.id, v.plate_number, v.vin, v.brand, v.model, v.year_manufactured,
          v.color, v.vehicle_type, v.status, v.registered_at, v.center_id,
          o.full_name as owner_name, o.phone as owner_phone,
          o.email as owner_email, o.address as owner_address,
          q.secure_token, q.qr_image_data
        FROM vehicles v
        LEFT JOIN owners o ON v.owner_id = o.id
        LEFT JOIN qrcodes q ON q.vehicle_id = v.id
        JOIN user_centers uc ON v.center_id = uc.center_id
        WHERE uc.user_id = ?
        ORDER BY v.registered_at DESC
      `).all(req.user.id);
    } else {
      rows = db.prepare(`
        SELECT 
          v.id, v.plate_number, v.vin, v.brand, v.model, v.year_manufactured,
          v.color, v.vehicle_type, v.status, v.registered_at, v.center_id,
          o.full_name as owner_name, o.phone as owner_phone,
          o.email as owner_email, o.address as owner_address,
          q.secure_token, q.qr_image_data
        FROM vehicles v
        LEFT JOIN owners o ON v.owner_id = o.id
        LEFT JOIN qrcodes q ON q.vehicle_id = v.id
        ORDER BY v.registered_at DESC
      `).all();
    }

    const formatted = rows.map(row => {
      const parts = db.prepare(
        "SELECT name, marking_code as id FROM vehicle_parts WHERE vehicle_id = ?"
      ).all(row.id);
      const docs = db.prepare(
        "SELECT doc_type, name, status, doc_number, valid_from, valid_until FROM vehicle_documents WHERE vehicle_id = ?"
      ).all(row.id);
      const formattedDocs = docs.map(d => ({
        doc_type: d.doc_type,
        name: d.name,
        doc_number: d.doc_number || '',
        valid_from: d.valid_from || '',
        valid_until: d.valid_until || '',
        status: getDocStatus(d.valid_until)
      }));

      return {
        id: row.id,
        plate: row.plate_number,
        brand: row.brand,
        model: row.model,
        vin: row.vin,
        year: String(row.year_manufactured),
        color: row.color,
        category: row.vehicle_type,
        status: row.status,
        registered_at: row.registered_at,
        qrCode: row.secure_token,
        qr_image_data: row.qr_image_data,
        center_id: row.center_id,
        owner: {
          name: row.owner_name || '',
          phone: row.owner_phone || '',
          email: row.owner_email || '',
          id: row.owner_address || ''
        },
        parts,
        documents: formattedDocs
      };
    });

    res.json(formatted);
  } catch (err) {
    console.error('💥 GET /api/vehicles :', err);
    res.status(500).json({ error: 'Erreur technique lors de la récupération des véhicules.' });
  }
});

// ======================================================================
// 3. VEHICLES — CREATE
// ======================================================================
app.post('/api/vehicles', authenticate, requirePermission('manage_vehicles'), async (req, res) => {
  const { plate, brand, model, vin, year, color, category, status, parts, docs } = req.body;
  const centerId = req.body.center_id || req.body.centerId;

  // Support format plat et imbriqué
  const ownerName = req.body.ownerName || (req.body.owner && req.body.owner.name);
  const ownerId   = req.body.ownerId   || (req.body.owner && req.body.owner.id);
  const ownerPhone = req.body.ownerPhone || (req.body.owner && req.body.owner.phone) || '';
  const ownerEmail = req.body.ownerEmail || (req.body.owner && req.body.owner.email) || null;

  // Validation
  if (!plate || !brand || !model || !vin || !ownerName || !centerId) {
    return res.status(400).json({ 
      error: 'Champs obligatoires manquants.',
      details: 'Plaque, marque, modèle, VIN, propriétaire et station de gravage sont requis.'
    });
  }

  // Vérifier affectation agent
  if (req.user.role === 'agent') {
    const isAssigned = db.prepare("SELECT 1 FROM user_centers WHERE user_id = ? AND center_id = ?").get(req.user.id, centerId);
    if (!isAssigned) {
      return res.status(403).json({ error: 'Accès refusé. Vous n\'êtes pas affecté à cette station de gravage.' });
    }
  }

  // Vérifier doublon plaque/VIN
  const existingPlate = db.prepare("SELECT id FROM vehicles WHERE plate_number = ?").get(plate.toUpperCase());
  if (existingPlate) {
    return res.status(409).json({ error: `La plaque ${plate.toUpperCase()} existe déjà dans le registre.` });
  }
  const existingVin = db.prepare("SELECT id FROM vehicles WHERE vin = ?").get(vin.toUpperCase());
  if (existingVin) {
    return res.status(409).json({ error: `Le numéro de châssis (VIN) ${vin.toUpperCase()} est déjà enregistré.` });
  }

  const ownerUuid = generateId('own');
  const vehicleUuid = generateId('veh');
  const secureToken = 'SPA-' + crypto.randomUUID().replace(/-/g, '').substring(0, 16).toUpperCase();

  // Générer le QR Code pointant vers l'URL publique (Ngrok ou production)
  const verifyUrl = getPublicVerifyUrl(secureToken);

  try {
    const qrDataUrl = await QRCode.toDataURL(verifyUrl, {
      width: 256,
      margin: 2,
      color: { dark: '#0A1628', light: '#FFFFFF' }
    });

    // 1. Propriétaire
    db.prepare(`INSERT INTO owners (id, full_name, phone, email, address) VALUES (?, ?, ?, ?, ?)`)
      .run(ownerUuid, ownerName, ownerPhone, ownerEmail, ownerId || '');

    // 2. Véhicule
    db.prepare(`
      INSERT INTO vehicles (id, plate_number, vin, brand, model, year_manufactured, color, vehicle_type, status, owner_id, center_id)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).run(vehicleUuid, plate.toUpperCase(), vin.toUpperCase(), brand, model,
           parseInt(year) || new Date().getFullYear(), color || '', category || 'SUV',
           status || 'authentic', ownerUuid, centerId);

    // 3. Pièces gravées
    if (parts && parts.length > 0) {
      const partStmt = db.prepare("INSERT INTO vehicle_parts (id, name, marking_code, vehicle_id) VALUES (?, ?, ?, ?)");
      for (const p of parts) {
        const mc = p.id || p.marking_code || '';
        if (mc.trim()) {
          partStmt.run(generateId('part'), p.name, mc.toUpperCase(), vehicleUuid);
        }
      }
    }

    // 4. Documents administratifs
    const docStmt = db.prepare(`
      INSERT INTO vehicle_documents (id, doc_type, name, status, doc_number, valid_from, valid_until, vehicle_id)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    `);
    if (docs && typeof docs === 'object') {
      for (const key of Object.keys(docs)) {
        const docInfo = docs[key];
        if (docInfo === true || docInfo === 'true') {
          docStmt.run(generateId('doc'), key, `${key} — ${plate.toUpperCase()}`, 'Valide', '', '', '', vehicleUuid);
        } else if (docInfo && typeof docInfo === 'object') {
          if (docInfo.active === true || docInfo.active === 'true' || docInfo.doc_number) {
            const calculatedStatus = getDocStatus(docInfo.valid_until);
            docStmt.run(
              generateId('doc'),
              key,
              `${key} — ${plate.toUpperCase()}`,
              calculatedStatus,
              docInfo.doc_number || '',
              docInfo.valid_from || '',
              docInfo.valid_until || '',
              vehicleUuid
            );
          }
        }
      }
    }

    // 5. QR Code
    db.prepare(`INSERT INTO qrcodes (id, vehicle_id, secure_token, qr_image_data) VALUES (?, ?, ?, ?)`)
      .run(generateId('qr'), vehicleUuid, secureToken, qrDataUrl);

    logAudit('VEHICLE_CREATED', `Véhicule ${plate.toUpperCase()} enregistré.`, req.user.id, req.ip);

    // Récupérer les parties et docs créés pour la réponse
    const createdParts = db.prepare("SELECT name, marking_code as id FROM vehicle_parts WHERE vehicle_id = ?").all(vehicleUuid);
    const createdDocs = db.prepare("SELECT doc_type, name, status, doc_number, valid_from, valid_until FROM vehicle_documents WHERE vehicle_id = ?").all(vehicleUuid);

    res.status(201).json({
      success: true,
      vehicle_id: vehicleUuid,
      secure_token: secureToken,
      qr_image_data: qrDataUrl,
      verify_url: verifyUrl,
      plate: plate.toUpperCase(),
      brand, model,
      vin: vin.toUpperCase(),
      year: String(year || new Date().getFullYear()),
      color: color || '',
      category: category || 'SUV',
      status: status || 'authentic',
      center_id: centerId,
      owner: { name: ownerName, id: ownerId || '', phone: ownerPhone, email: ownerEmail || '' },
      parts: createdParts,
      documents: createdDocs
    });

  } catch (err) {
    console.error('💥 Erreur création véhicule:', err);
    res.status(500).json({ error: 'Erreur lors de l\'enregistrement. ' + err.message });
  }
});

// ======================================================================
// 4. VEHICLES — UPDATE
// ======================================================================
app.put('/api/vehicles/:plate', authenticate, requirePermission('manage_vehicles'), (req, res) => {
  const { plate } = req.params;
  const { brand, model, vin, year, color, category, status, parts, docs } = req.body;
  const centerId = req.body.center_id || req.body.centerId;

  const ownerName  = req.body.ownerName  || (req.body.owner && req.body.owner.name);
  const ownerId    = req.body.ownerId    || (req.body.owner && req.body.owner.id) || '';
  const ownerPhone = req.body.ownerPhone || (req.body.owner && req.body.owner.phone) || '';
  const ownerEmail = req.body.ownerEmail || (req.body.owner && req.body.owner.email) || null;

  try {
    const vehicle = db.prepare("SELECT * FROM vehicles WHERE plate_number = ?").get(plate.toUpperCase());
    if (!vehicle) {
      return res.status(404).json({ error: `Véhicule avec la plaque ${plate.toUpperCase()} introuvable.` });
    }

    // Vérifier affectation agent pour le centre actuel
    if (req.user.role === 'agent') {
      const isAssignedCurrent = db.prepare("SELECT 1 FROM user_centers WHERE user_id = ? AND center_id = ?").get(req.user.id, vehicle.center_id);
      if (!isAssignedCurrent) {
        return res.status(403).json({ error: 'Accès refusé. Vous n\'êtes pas affecté à la station d\'origine de ce véhicule.' });
      }
      if (centerId && centerId !== vehicle.center_id) {
        const isAssignedNew = db.prepare("SELECT 1 FROM user_centers WHERE user_id = ? AND center_id = ?").get(req.user.id, centerId);
        if (!isAssignedNew) {
          return res.status(403).json({ error: 'Accès refusé. Vous n\'êtes pas affecté à la nouvelle station demandée.' });
        }
      }
    }

    // Vérifier doublon VIN si VIN changé
    if (vin) {
      const existingVin = db.prepare("SELECT id FROM vehicles WHERE vin = ? AND id != ?").get(vin.toUpperCase(), vehicle.id);
      if (existingVin) {
        return res.status(409).json({ error: `Le VIN ${vin.toUpperCase()} est déjà attribué à un autre véhicule.` });
      }
    }

    // Mettre à jour le propriétaire
    if (vehicle.owner_id) {
      db.prepare(`UPDATE owners SET full_name = ?, phone = ?, email = ?, address = ? WHERE id = ?`)
        .run(ownerName, ownerPhone, ownerEmail, ownerId, vehicle.owner_id);
    }

    // Mettre à jour le véhicule
    const updatedCenterId = centerId || vehicle.center_id;
    db.prepare(`
      UPDATE vehicles 
      SET brand = ?, model = ?, vin = ?, year_manufactured = ?, color = ?, vehicle_type = ?, status = ?, center_id = ?
      WHERE id = ?
    `).run(brand, model, (vin || '').toUpperCase(), parseInt(year) || 2024,
           color || '', category || 'SUV', status, updatedCenterId, vehicle.id);

    // Remplacer les pièces
    db.prepare("DELETE FROM vehicle_parts WHERE vehicle_id = ?").run(vehicle.id);
    if (parts && parts.length > 0) {
      const partStmt = db.prepare("INSERT INTO vehicle_parts (id, name, marking_code, vehicle_id) VALUES (?, ?, ?, ?)");
      for (const p of parts) {
        const mc = p.id || p.marking_code || '';
        if (mc.trim()) {
          partStmt.run(generateId('part'), p.name, mc.toUpperCase(), vehicle.id);
        }
      }
    }

    // Remplacer les documents si fournis
    if (docs && typeof docs === 'object') {
      db.prepare("DELETE FROM vehicle_documents WHERE vehicle_id = ?").run(vehicle.id);
      const docStmt = db.prepare(`
        INSERT INTO vehicle_documents (id, doc_type, name, status, doc_number, valid_from, valid_until, vehicle_id)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
      `);
      for (const key of Object.keys(docs)) {
        const docInfo = docs[key];
        if (docInfo === true || docInfo === 'true') {
          docStmt.run(generateId('doc'), key, `${key} — ${plate.toUpperCase()}`, 'Valide', '', '', '', vehicle.id);
        } else if (docInfo && typeof docInfo === 'object') {
          if (docInfo.active === true || docInfo.active === 'true' || docInfo.doc_number) {
            const calculatedStatus = getDocStatus(docInfo.valid_until);
            docStmt.run(
              generateId('doc'),
              key,
              `${key} — ${plate.toUpperCase()}`,
              calculatedStatus,
              docInfo.doc_number || '',
              docInfo.valid_from || '',
              docInfo.valid_until || '',
              vehicle.id
            );
          }
        }
      }
    }

    logAudit('VEHICLE_UPDATED', `Mise à jour véhicule ${plate.toUpperCase()}.`, req.user.id, req.ip);

    res.json({ success: true, message: `Véhicule ${plate.toUpperCase()} mis à jour avec succès.` });

  } catch (err) {
    console.error('💥 Erreur mise à jour véhicule:', err);
    res.status(500).json({ error: 'Erreur technique lors de la mise à jour. ' + err.message });
  }
});

// ======================================================================
// 5. VEHICLES — DELETE
// ======================================================================
app.delete('/api/vehicles/:plate', authenticate, (req, res) => {
  const { plate } = req.params;

  if (req.user.role !== 'admin') {
    return res.status(403).json({ error: 'Accès refusé. Seul l\'Administrateur peut supprimer définitivement un véhicule.' });
  }

  try {
    const vehicle = db.prepare("SELECT * FROM vehicles WHERE plate_number = ?").get(plate.toUpperCase());
    if (!vehicle) {
      return res.status(404).json({ error: `Véhicule ${plate.toUpperCase()} introuvable dans le registre.` });
    }

    db.prepare("DELETE FROM vehicles WHERE id = ?").run(vehicle.id);

    // Supprimer le propriétaire seulement s'il n'a plus de véhicule
    const otherVehicles = db.prepare("SELECT COUNT(*) as c FROM vehicles WHERE owner_id = ?").get(vehicle.owner_id);
    if (!otherVehicles || otherVehicles.c === 0) {
      db.prepare("DELETE FROM owners WHERE id = ?").run(vehicle.owner_id);
    }

    logAudit('VEHICLE_DELETED', `Suppression véhicule ${plate.toUpperCase()}.`, req.user.id, req.ip);

    res.json({ success: true, message: `Véhicule ${plate.toUpperCase()} supprimé définitivement.` });

  } catch (err) {
    console.error('💥 Erreur suppression véhicule:', err);
    res.status(500).json({ error: 'Erreur technique lors de la suppression. ' + err.message });
  }
});

// ======================================================================
// 6. CENTERS — CRUD COMPLET
// ======================================================================
app.get('/api/centers', authenticate, (req, res) => {
  try {
    let centers;
    if (req.user.role === 'agent') {
      centers = db.prepare(`
        SELECT c.* FROM centers c
        JOIN user_centers uc ON c.id = uc.center_id
        WHERE uc.user_id = ?
        ORDER BY c.created_at DESC
      `).all(req.user.id);
    } else {
      centers = db.prepare("SELECT * FROM centers ORDER BY created_at DESC").all();
    }

    res.json(centers.map(c => ({
      id: c.id,
      name: c.name,
      type: c.type || 'center',
      region: c.region,
      desc: c.description,
      staff: c.staff,
      status: c.status,
      x: c.x,
      y: c.y
    })));
  } catch (err) {
    console.error('💥 GET /api/centers:', err);
    res.status(500).json({ error: 'Erreur lors de la récupération des centres.' });
  }
});

app.post('/api/centers', authenticate, requirePermission('manage_centers'), (req, res) => {
  const { name, region, desc, staff, status, x, y } = req.body;
  if (!name || !region) {
    return res.status(400).json({ error: 'Nom et région du centre sont requis.' });
  }
  try {
    const id = generateId('cnt');
    db.prepare(`
      INSERT INTO centers (id, name, type, region, description, staff, status, x, y)
      VALUES (?, ?, 'center', ?, ?, ?, ?, ?, ?)
    `).run(id, name, region, desc || '', staff || '6 agents', status || 'Ouvert (08h - 18h)',
           parseInt(x) || 150, parseInt(y) || 150);
    
    logAudit('CENTER_CREATED', `Centre ${name} ajouté.`, req.user.id, req.ip);
    const created = db.prepare("SELECT * FROM centers WHERE id = ?").get(id);
    res.status(201).json({ ...created, desc: created.description });
  } catch (err) {
    console.error('💥 POST /api/centers:', err);
    res.status(500).json({ error: 'Erreur lors de la création du centre. ' + err.message });
  }
});

app.put('/api/centers/:id', authenticate, requirePermission('manage_centers'), (req, res) => {
  const { id } = req.params;
  const { name, region, desc, staff, status, x, y } = req.body;
  try {
    const center = db.prepare("SELECT * FROM centers WHERE id = ?").get(id);
    if (!center) return res.status(404).json({ error: 'Centre introuvable.' });

    db.prepare(`
      UPDATE centers SET name = ?, region = ?, description = ?, staff = ?, status = ?, x = ?, y = ?
      WHERE id = ?
    `).run(name || center.name, region || center.region, desc !== undefined ? desc : center.description,
           staff || center.staff, status || center.status,
           parseInt(x) || center.x, parseInt(y) || center.y, id);

    logAudit('CENTER_UPDATED', `Centre ${id} mis à jour.`, req.user.id, req.ip);
    const updated = db.prepare("SELECT * FROM centers WHERE id = ?").get(id);
    res.json({ ...updated, desc: updated.description });
  } catch (err) {
    console.error('💥 PUT /api/centers:', err);
    res.status(500).json({ error: 'Erreur lors de la mise à jour du centre. ' + err.message });
  }
});

app.delete('/api/centers/:id', authenticate, requirePermission('manage_centers'), (req, res) => {
  const { id } = req.params;
  try {
    const center = db.prepare("SELECT * FROM centers WHERE id = ?").get(id);
    if (!center) return res.status(404).json({ error: 'Centre introuvable.' });

    db.prepare("DELETE FROM centers WHERE id = ?").run(id);
    logAudit('CENTER_DELETED', `Centre ${center.name} supprimé.`, req.user.id, req.ip);
    res.json({ success: true, message: `Centre "${center.name}" supprimé.` });
  } catch (err) {
    console.error('💥 DELETE /api/centers:', err);
    res.status(500).json({ error: 'Erreur lors de la suppression du centre. ' + err.message });
  }
});

// ======================================================================
// 7. SQUADS — CRUD COMPLET
// ======================================================================
app.get('/api/squads', (req, res) => {
  try {
    const squads = db.prepare("SELECT * FROM squads ORDER BY created_at DESC").all();
    res.json(squads);
  } catch (err) {
    console.error('💥 GET /api/squads:', err);
    res.status(500).json({ error: 'Erreur lors de la récupération des patrouilles.' });
  }
});

app.post('/api/squads', (req, res) => {
  const { id: squadId, inspector, region, status, mission, battery, x, y } = req.body;
  if (!squadId || !inspector || !region) {
    return res.status(400).json({ error: 'ID, inspecteur et région de la patrouille sont requis.' });
  }
  try {
    const existing = db.prepare("SELECT id FROM squads WHERE id = ?").get(squadId);
    if (existing) {
      return res.status(409).json({ error: `L'identifiant ${squadId} est déjà utilisé.` });
    }
    db.prepare(`
      INSERT INTO squads (id, region, inspector, status, mission, battery, x, y)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    `).run(squadId, region, inspector, status || 'Disponible',
           mission || '', battery || '100%',
           parseInt(x) || 150, parseInt(y) || 150);
    
    logAudit('SQUAD_CREATED', `Patrouille ${squadId} déployée.`, null, req.ip);
    const created = db.prepare("SELECT * FROM squads WHERE id = ?").get(squadId);
    res.status(201).json(created);
  } catch (err) {
    console.error('💥 POST /api/squads:', err);
    res.status(500).json({ error: 'Erreur lors du déploiement de la patrouille. ' + err.message });
  }
});

app.put('/api/squads/:id', (req, res) => {
  const { id } = req.params;
  const { inspector, region, status, mission, battery, x, y } = req.body;
  try {
    const squad = db.prepare("SELECT * FROM squads WHERE id = ?").get(id);
    if (!squad) return res.status(404).json({ error: 'Patrouille introuvable.' });

    db.prepare(`
      UPDATE squads SET inspector = ?, region = ?, status = ?, mission = ?, battery = ?, x = ?, y = ?
      WHERE id = ?
    `).run(inspector || squad.inspector, region || squad.region,
           status || squad.status, mission !== undefined ? mission : squad.mission,
           battery || squad.battery,
           parseInt(x) || squad.x, parseInt(y) || squad.y, id);

    logAudit('SQUAD_UPDATED', `Patrouille ${id} mise à jour.`, null, req.ip);
    const updated = db.prepare("SELECT * FROM squads WHERE id = ?").get(id);
    res.json(updated);
  } catch (err) {
    console.error('💥 PUT /api/squads:', err);
    res.status(500).json({ error: 'Erreur lors de la mise à jour de la patrouille. ' + err.message });
  }
});

app.delete('/api/squads/:id', (req, res) => {
  const { id } = req.params;
  try {
    const squad = db.prepare("SELECT * FROM squads WHERE id = ?").get(id);
    if (!squad) return res.status(404).json({ error: 'Patrouille introuvable.' });

    db.prepare("DELETE FROM squads WHERE id = ?").run(id);
    logAudit('SQUAD_DELETED', `Patrouille ${id} rappelée.`, null, req.ip);
    res.json({ success: true, message: `Patrouille "${id}" retirée du déploiement.` });
  } catch (err) {
    console.error('💥 DELETE /api/squads:', err);
    res.status(500).json({ error: 'Erreur lors du rappel de la patrouille. ' + err.message });
  }
});

// ======================================================================
// 8. STATS DASHBOARD
// ======================================================================
app.get('/api/stats', authenticate, (req, res) => {
  try {
    const totalVehicles = db.prepare("SELECT COUNT(*) as c FROM vehicles").get().c;
    const authentic = db.prepare("SELECT COUNT(*) as c FROM vehicles WHERE status = 'authentic'").get().c;
    const suspicious = db.prepare("SELECT COUNT(*) as c FROM vehicles WHERE status = 'suspicious'").get().c;
    const pending = db.prepare("SELECT COUNT(*) as c FROM vehicles WHERE status = 'pending'").get().c;
    const totalCenters = db.prepare("SELECT COUNT(*) as c FROM centers").get().c;
    const totalSquads = db.prepare("SELECT COUNT(*) as c FROM squads").get().c;
    const totalParts = db.prepare("SELECT COUNT(*) as c FROM vehicle_parts").get().c;
    
    // Statistiques d'effectifs dynamiques requises
    const totalAgents = db.prepare("SELECT COUNT(*) as c FROM users WHERE role = 'agent'").get().c;
    const totalUsers = db.prepare("SELECT COUNT(*) as c FROM users").get().c;

    const recentVehicles = db.prepare(`
      SELECT v.plate_number, v.brand, v.model, v.status, v.registered_at, o.full_name as owner
      FROM vehicles v LEFT JOIN owners o ON v.owner_id = o.id
      ORDER BY v.registered_at DESC LIMIT 5
    `).all();

    res.json({
      totalVehicles, authentic, suspicious, pending,
      totalCenters, totalSquads, totalParts,
      totalAgents, totalUsers,
      recentVehicles
    });
  } catch (err) {
    console.error('💥 GET /api/stats:', err);
    res.status(500).json({ error: 'Erreur lors du calcul des statistiques.' });
  }
});

// ======================================================================
// 9. PARTS — GET & ADD per Vehicle
// ======================================================================
app.get('/api/parts/:vehicleId', authenticate, (req, res) => {
  const { vehicleId } = req.params;
  try {
    const vehicle = db.prepare("SELECT id FROM vehicles WHERE id = ?").get(vehicleId);
    if (!vehicle) return res.status(404).json({ error: 'Véhicule introuvable.' });

    const parts = db.prepare(
      "SELECT id, name, marking_code as marking_id FROM vehicle_parts WHERE vehicle_id = ? ORDER BY rowid"
    ).all(vehicleId);

    res.json(parts.map(p => ({ id: p.marking_id, name: p.name, db_id: p.id })));
  } catch (err) {
    console.error('💥 GET /api/parts:', err);
    res.status(500).json({ error: 'Erreur lors de la récupération des pièces.' });
  }
});

app.post('/api/parts/:vehicleId', authenticate, requirePermission('manage_vehicles'), (req, res) => {
  const { vehicleId } = req.params;
  const { name, marking_code } = req.body;

  if (!name || !marking_code) {
    return res.status(400).json({ error: 'Nom et code de marquage requis.' });
  }

  try {
    const vehicle = db.prepare("SELECT id FROM vehicles WHERE id = ?").get(vehicleId);
    if (!vehicle) return res.status(404).json({ error: 'Véhicule introuvable.' });

    const existingCode = db.prepare(
      "SELECT id FROM vehicle_parts WHERE marking_code = ? AND vehicle_id = ?"
    ).get(marking_code.toUpperCase(), vehicleId);
    if (existingCode) {
      return res.status(409).json({ error: `Le code de marquage ${marking_code.toUpperCase()} existe déjà pour ce véhicule.` });
    }

    const partId = generateId('part');
    db.prepare("INSERT INTO vehicle_parts (id, name, marking_code, vehicle_id) VALUES (?, ?, ?, ?)")
      .run(partId, name.trim(), marking_code.toUpperCase(), vehicleId);

    logAudit('PART_ADDED', `Pièce ${name} (${marking_code}) ajoutée au véhicule ${vehicleId}`, req.user.id, req.ip);

    res.status(201).json({ db_id: partId, id: marking_code.toUpperCase(), name: name.trim() });
  } catch (err) {
    console.error('💥 POST /api/parts:', err);
    res.status(500).json({ error: 'Erreur lors de l\'ajout de la pièce. ' + err.message });
  }
});

app.delete('/api/parts/:vehicleId/:partId', authenticate, requirePermission('manage_vehicles'), (req, res) => {
  const { vehicleId, partId } = req.params;
  try {
    const part = db.prepare("SELECT id, name FROM vehicle_parts WHERE id = ? AND vehicle_id = ?").get(partId, vehicleId);
    if (!part) return res.status(404).json({ error: 'Pièce introuvable.' });

    db.prepare("DELETE FROM vehicle_parts WHERE id = ?").run(partId);
    logAudit('PART_DELETED', `Pièce ${part.name} supprimée du véhicule ${vehicleId}`, req.user.id, req.ip);
    res.json({ success: true, message: `Pièce "${part.name}" supprimée.` });
  } catch (err) {
    console.error('💥 DELETE /api/parts:', err);
    res.status(500).json({ error: 'Erreur lors de la suppression de la pièce. ' + err.message });
  }
});

// ======================================================================
// 10. QR VERIFICATION — Endpoint API (avec ou sans auth)
// ======================================================================
app.get('/api/verify/qr/:token', verifyQrToken);

// ======================================================================
// 10b. CONFIG PUBLIQUE — Expose l'URL publique au frontend
// ======================================================================
app.get('/api/config/public-url', (req, res) => {
  res.json({
    publicUrl: APP_PUBLIC_URL || null,
    frontendUrl: FRONTEND_URL,
    isLocalDev: IS_LOCAL_DEV,
    verificationBase: APP_PUBLIC_URL ? `${APP_PUBLIC_URL}/verification` : `${FRONTEND_URL}/?tab=verify&token=`,
  });
});

app.post('/api/config/public-url', authenticate, requirePermission('manage_users'), async (req, res) => {
  const { publicUrl } = req.body;
  const url = (publicUrl || '').trim().replace(/\/$/, '');

  if (url && !url.startsWith('http://') && !url.startsWith('https://')) {
    return res.status(400).json({ error: "L'URL doit commencer par http:// ou https://" });
  }

  try {
    // 1. Mettre à jour en mémoire
    APP_PUBLIC_URL = url;
    IS_LOCAL_DEV = !url;

    // 2. Mettre à jour le fichier .env
    const __filename = fileURLToPath(import.meta.url);
    const __dirname = path.dirname(__filename);
    const envPath = path.resolve(__dirname, '.env');

    let envContent = '';
    try {
      envContent = await fs.readFile(envPath, 'utf8');
    } catch (readErr) {
      envContent = 'PORT=4000\nFRONTEND_URL=http://localhost:5175\n';
    }

    const regex = /^APP_PUBLIC_URL=.*$/m;
    if (regex.test(envContent)) {
      envContent = envContent.replace(regex, `APP_PUBLIC_URL=${url}`);
    } else {
      // S'assurer qu'il y a un retour à la ligne avant d'ajouter
      if (envContent && !envContent.endsWith('\n')) {
        envContent += '\n';
      }
      envContent += `APP_PUBLIC_URL=${url}`;
    }

    await fs.writeFile(envPath, envContent, 'utf8');

    // 3. Log Audit
    logAudit('CONFIG_UPDATED', `URL publique configurée : ${url || '(vide)'}`, req.user.id, req.ip);

    res.json({
      success: true,
      publicUrl: APP_PUBLIC_URL || null,
      frontendUrl: FRONTEND_URL,
      isLocalDev: IS_LOCAL_DEV,
      verificationBase: APP_PUBLIC_URL ? `${APP_PUBLIC_URL}/verification` : `${FRONTEND_URL}/?tab=verify&token=`,
    });
  } catch (err) {
    console.error('💥 POST /api/config/public-url error:', err);
    res.status(500).json({ error: 'Erreur lors de la mise à jour de la configuration : ' + err.message });
  }
});

// ======================================================================
// 10b-bis. RÉGÉNÉRATION DES QR CODES — Route d'administration
// ======================================================================
app.post('/api/admin/regenerate-qrcodes', authenticate, requirePermission('manage_users'), async (req, res) => {
  try {
    const qrcodes = db.prepare("SELECT * FROM qrcodes").all();
    let count = 0;

    for (const qr of qrcodes) {
      const verifyUrl = `${APP_PUBLIC_URL}/verification/${qr.secure_token}`;
      const qrDataUrl = await QRCode.toDataURL(verifyUrl, {
        width: 256,
        margin: 2,
        color: { dark: '#0A1628', light: '#FFFFFF' }
      });

      db.prepare("UPDATE qrcodes SET qr_image_data = ? WHERE id = ?").run(qrDataUrl, qr.id);
      count++;
    }

    logAudit('QR_CODES_REGENERATED', `Régénération de ${count} QR codes avec la base URL : ${APP_PUBLIC_URL}`, req.user.id, req.ip);

    res.json({
      success: true,
      message: `${count} QR codes ont été régénérés avec succès avec la base URL : ${APP_PUBLIC_URL}`,
      count,
      baseUrl: APP_PUBLIC_URL
    });
  } catch (err) {
    console.error('💥 POST /api/admin/regenerate-qrcodes error:', err);
    res.status(500).json({ error: 'Erreur lors de la régénération des QR codes : ' + err.message });
  }
});

// ======================================================================
// 10c. PAGE PUBLIQUE DE VÉRIFICATION — Route accessible via QR Code
//      GET /verification/:token → renvoie les données du véhicule (public)
// ======================================================================
app.get('/api/public/verification/:token', async (req, res) => {
  const { token } = req.params;
  if (!token) {
    return res.status(400).json({ error: 'Jeton de vérification manquant.' });
  }
  // Déléguer au même contrôleur de vérification (accès anonyme = PUBLIC_ACCESS_RESTRICTED)
  req.params.token = token;
  return verifyQrToken(req, res);
});

// ======================================================================
// 11. USERS — CRUD COMPLET (Admin uniquement)
// ======================================================================
app.get('/api/users', authenticate, requirePermission('manage_users'), (req, res) => {
  try {
    const users = db.prepare("SELECT id, username, email, role, name, is_active, created_at FROM users").all();
    const formatted = users.map(user => {
      const assigned = db.prepare(`
        SELECT center_id FROM user_centers WHERE user_id = ?
      `).all(user.id).map(r => r.center_id);
      return {
        ...user,
        is_active: !!user.is_active,
        center_ids: assigned
      };
    });
    res.json(formatted);
  } catch (err) {
    console.error('💥 GET /api/users:', err);
    res.status(500).json({ error: 'Erreur lors de la récupération des utilisateurs.' });
  }
});

app.post('/api/users', authenticate, requirePermission('manage_users'), (req, res) => {
  const { username, email, password, role, name, is_active, center_ids } = req.body;
  if (!username || !email || !password || !role || !name) {
    return res.status(400).json({ error: 'Tous les champs obligatoires doivent être renseignés.' });
  }
  if (!['admin', 'agent', 'police'].includes(role)) {
    return res.status(400).json({ error: 'Rôle invalide. Choisissez entre Administrateur, Agent, Police.' });
  }

  try {
    const existing = db.prepare("SELECT id FROM users WHERE username = ? OR email = ?").get(username, email);
    if (existing) {
      return res.status(409).json({ error: 'Le nom d\'utilisateur ou l\'adresse e-mail est déjà utilisé.' });
    }

    const userId = generateId('u');
    db.prepare(`
      INSERT INTO users (id, username, email, password_hash, role, name, is_active)
      VALUES (?, ?, ?, ?, ?, ?, ?)
    `).run(userId, username, email, password, role, name, is_active !== false ? 1 : 0);

    if (role === 'agent' && Array.isArray(center_ids)) {
      const insertUc = db.prepare("INSERT INTO user_centers (user_id, center_id) VALUES (?, ?)");
      for (const cid of center_ids) {
        insertUc.run(userId, cid);
      }
    }

    logAudit('USER_CREATED', `Utilisateur créé : ${username} (${role})`, req.user.id, req.ip);
    res.status(201).json({ id: userId, username, email, role, name, is_active: is_active !== false, center_ids: center_ids || [] });
  } catch (err) {
    console.error('💥 POST /api/users:', err);
    res.status(500).json({ error: 'Erreur lors de la création de l\'utilisateur : ' + err.message });
  }
});

app.put('/api/users/:id', authenticate, requirePermission('manage_users'), (req, res) => {
  const { id } = req.params;
  const { username, email, password, role, name, is_active, center_ids } = req.body;

  try {
    const user = db.prepare("SELECT * FROM users WHERE id = ?").get(id);
    if (!user) {
      return res.status(404).json({ error: 'Utilisateur introuvable.' });
    }

    if (user.id === req.user.id && (is_active === false || role !== user.role)) {
      return res.status(400).json({ error: 'Vous ne pouvez pas modifier votre propre rôle ou désactiver votre compte.' });
    }

    if (password && password.trim() !== '') {
      db.prepare(`
        UPDATE users 
        SET username = ?, email = ?, password_hash = ?, role = ?, name = ?, is_active = ?
        WHERE id = ?
      `).run(username || user.username, email || user.email, password, role || user.role, name || user.name, is_active !== false ? 1 : 0, id);
    } else {
      db.prepare(`
        UPDATE users 
        SET username = ?, email = ?, role = ?, name = ?, is_active = ?
        WHERE id = ?
      `).run(username || user.username, email || user.email, role || user.role, name || user.name, is_active !== false ? 1 : 0, id);
    }

    db.prepare("DELETE FROM user_centers WHERE user_id = ?").run(id);
    if (role === 'agent' && Array.isArray(center_ids)) {
      const insertUc = db.prepare("INSERT INTO user_centers (user_id, center_id) VALUES (?, ?)");
      for (const cid of center_ids) {
        insertUc.run(id, cid);
      }
    }

    logAudit('USER_UPDATED', `Mise à jour utilisateur : ${username || user.username}`, req.user.id, req.ip);
    res.json({ success: true, message: 'Utilisateur mis à jour avec succès.' });
  } catch (err) {
    console.error('💥 PUT /api/users:', err);
    res.status(500).json({ error: 'Erreur lors de la modification de l\'utilisateur : ' + err.message });
  }
});

app.delete('/api/users/:id', authenticate, requirePermission('manage_users'), (req, res) => {
  const { id } = req.params;
  if (id === req.user.id) {
    return res.status(400).json({ error: 'Vous ne pouvez pas supprimer votre propre compte.' });
  }

  try {
    const user = db.prepare("SELECT username FROM users WHERE id = ?").get(id);
    if (!user) return res.status(404).json({ error: 'Utilisateur introuvable.' });

    db.prepare("DELETE FROM users WHERE id = ?").run(id);
    logAudit('USER_DELETED', `Suppression de l'utilisateur : ${user.username}`, req.user.id, req.ip);
    res.json({ success: true, message: `Utilisateur "${user.username}" supprimé.` });
  } catch (err) {
    console.error('💥 DELETE /api/users:', err);
    res.status(500).json({ error: 'Erreur lors de la suppression de l\'utilisateur.' });
  }
});

app.get('/api/roles', authenticate, (req, res) => {
  try {
    const roles = db.prepare("SELECT name, description, permissions FROM roles").all();
    res.json(roles.map(r => ({ ...r, permissions: JSON.parse(r.permissions || '[]') })));
  } catch (err) {
    console.error('💥 GET /api/roles:', err);
    res.status(500).json({ error: 'Erreur lors de la récupération des rôles.' });
  }
});

// ======================================================================
// 12. SANTÉ DU SERVEUR
// ======================================================================
app.get('/health', (req, res) => {
  res.json({
    status: 'healthy',
    service: 'SPA RDC Backend',
    database: 'SQLITE_ACTIVE',
    version: '2.1.0',
    timestamp: new Date().toISOString()
  });
});

app.listen(PORT, () => {
  console.log(`=======================================================`);
  console.log(`🦁  SPA RDC Backend v2.1 — PORT : ${PORT}`);
  console.log(`🔗  Frontend URL  : ${FRONTEND_URL}`);
  console.log(`🌐  QR Base URL   : ${APP_PUBLIC_URL}`);
  console.log(`📱  QR Scan URL   : ${APP_PUBLIC_URL}/verification/<token>`);
  if (IS_LOCAL_DEV) {
    console.log(`⚠️   Mode LOCAL   : définissez APP_PUBLIC_URL en production.`);
  }
  console.log(`🛡️   Health       : http://localhost:${PORT}/health`);
  console.log(`=======================================================`);
});
