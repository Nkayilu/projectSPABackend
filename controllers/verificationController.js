import { db } from '../db.js';

export async function verifyQrToken(req, res) {
  const { token } = req.params;
  const authHeader = req.headers.authorization;
  const ipAddress = req.ip || req.connection.remoteAddress;

  if (!token) {
    return res.status(400).json({ error: 'Jeton de verification manquant.' });
  }

  // 1. Determination du rôle de l'utilisateur
  let userRole = 'ANONYMOUS';
  let userId = null;

  if (authHeader && authHeader.startsWith('Bearer ')) {
    const authString = authHeader.split(' ')[1];
    try {
      const user = db.prepare("SELECT * FROM users WHERE session_token = ? AND is_active = 1").get(authString);
      if (user) {
        userRole = user.role.toUpperCase();
        userId = user.id;
      }
    } catch (err) {
      console.error('Error in verifyQrToken user lookup:', err);
    }
  }

  console.log(`🔍 Scan QR Token: "${token}" | Rôle demandeur: ${userRole} | IP: ${ipAddress}`);

  try {
    // 2. Requete SQL multi-critère (token QR, plaque, VIN ou code pièce)
    const record = db.prepare(`
      SELECT DISTINCT
        v.id as vehicle_id,
        v.plate_number, v.vin, v.brand, v.model,
        v.year_manufactured, v.color, v.vehicle_type,
        v.status as vehicle_status, v.registered_at,
        o.full_name as owner_name,
        o.phone as owner_phone,
        o.email as owner_email,
        o.address as owner_address,
        qr.is_active as qr_active,
        qr.qr_image_data,
        qr.secure_token,
        c.name as center_name,
        c.region as center_region
      FROM vehicles v
      JOIN owners o ON v.owner_id = o.id
      LEFT JOIN qrcodes qr ON qr.vehicle_id = v.id
      LEFT JOIN vehicle_parts vp ON vp.vehicle_id = v.id
      LEFT JOIN centers c ON v.center_id = c.id
      WHERE UPPER(qr.secure_token) = UPPER(?)
         OR UPPER(v.plate_number) = UPPER(?)
         OR UPPER(v.vin) = UPPER(?)
         OR UPPER(vp.marking_code) = UPPER(?)
      LIMIT 1
    `).get(token, token, token, token);

    if (!record) {
      logAudit(null, 'QR_SCANNED_FAILED', `Scan invalide pour le jeton: ${token}`, ipAddress);
      return res.status(404).json({
        error: 'Véhicule introuvable.',
        message: 'Ce QR code n\'est pas répertorié dans la base nationale SPA ou a expiré.'
      });
    }

    // Récupérer les pièces associées
    const parts = db.prepare(
      `SELECT name, marking_code FROM vehicle_parts WHERE vehicle_id = ?`
    ).all(record.vehicle_id);

    // Récupérer les documents associés
    const docs = db.prepare(
      `SELECT doc_type, name, status, doc_number, valid_from, valid_until FROM vehicle_documents WHERE vehicle_id = ?`
    ).all(record.vehicle_id);

    // 3. Formater la réponse de base
    const isAuthorized = ['ADMIN', 'REGISTRATION_AGENT', 'VERIFIER', 'POLICE', 'AGENT'].includes(userRole);

    let responseData = {
      plate_number: record.plate_number,
      vin: record.vin,
      brand: record.brand,
      model: record.model,
      year_manufactured: record.year_manufactured,
      color: record.color,
      vehicle_type: record.vehicle_type,
      vehicle_status: record.vehicle_status,
      registered_at: record.registered_at,
      center_name: record.center_name || 'Centre Agréé SPA RDC',
      center_region: record.center_region || 'Kinshasa',
      qr_image_data: record.qr_image_data,
      secure_token: record.secure_token,
      parts: parts.map(p => ({ name: p.name, id: p.marking_code })),
      documents: docs.map(d => ({
        doc_type: d.doc_type,
        name: d.name,
        doc_number: d.doc_number || '',
        valid_from: d.valid_from || '',
        valid_until: d.valid_until || '',
        status: getDocStatus(d.valid_until)
      })),
      verification_status: 'VERIFIED',
      access_level: isAuthorized ? 'PRIVILEGED_ACCESS_OFFICIAL' : 'PUBLIC_ACCESS_RESTRICTED'
    };

    // Générer automatiquement un rapport de vol pour les véhicules suspects
    if (record.vehicle_status === 'suspicious') {
      responseData.stolenReport = {
        date: new Date(record.registered_at || Date.now()).toLocaleDateString('fr-FR'),
        location: 'Kinshasa - République Démocratique du Congo',
        incidentId: 'PNC-INC-' + record.vehicle_id.replace(/[^A-Z0-9]/gi, '').substring(0, 8).toUpperCase(),
        status: 'Recherché par la Police Nationale Congolaise (PNC)'
      };
    }

    // Données propriétaire selon niveau d'accès
    if (isAuthorized) {
      responseData.owner = {
        name: record.owner_name,
        full_name: record.owner_name,
        phone: record.owner_phone || 'N/A',
        email: record.owner_email || 'N/A',
        address: record.owner_address || 'N/A'
      };
    } else {
      responseData.owner = {
        name: maskName(record.owner_name),
        full_name: maskName(record.owner_name),
        phone: 'CONFIDENTIEL (Réservé Police/Agents)',
        email: 'CONFIDENTIEL',
        address: 'CONFIDENTIEL'
      };
    }

    // 4. Log Audit
    logAudit(
      null,
      'QR_SCANNED_SUCCESS',
      `Véhicule ${record.plate_number} | Status: ${record.vehicle_status} | Accès: ${responseData.access_level}`,
      ipAddress
    );

    return res.json(responseData);

  } catch (err) {
    console.error('💥 Erreur verification QR SQLite :', err);
    return res.status(500).json({ error: 'Erreur technique serveur base de données.' });
  }
}

// Masquage du nom pour accès public
function maskName(fullName) {
  if (!fullName) return 'Inconnu';
  const parts = fullName.trim().split(' ');
  if (parts.length === 1) return parts[0].substring(0, 3) + '***';
  return `${parts[0]} ${parts[1].substring(0, 1)}. (CONFIDENTIEL)`;
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

// Log audit dans la base de données
function logAudit(userId, action, details, ipAddress) {
  console.log(`📝 [AUDIT] ${action} | ${details}`);
  try {
    db.prepare(
      `INSERT INTO audit_logs (user_id, action, details, ip_address) VALUES (?, ?, ?, ?)`
    ).run(userId || 'ANONYMOUS', action, details, ipAddress);
  } catch (auditErr) {
    console.error('⚠️ Audit log error:', auditErr.message);
  }
}
