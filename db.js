import Database from 'better-sqlite3';
import path from 'path';
import { fileURLToPath } from 'url';
import fs from 'fs';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// En production Render : DB_PATH=/tmp/database.sqlite (défini dans les env vars Render)
// En développement local : fallback vers le dossier database/ local
const dbPath = process.env.DB_PATH
  ? process.env.DB_PATH
  : path.resolve(__dirname, '../database/spa_rdc.db');

// Créer le répertoire parent si nécessaire (utile pour /tmp)
const dbDir = path.dirname(dbPath);
if (!fs.existsSync(dbDir)) {
  fs.mkdirSync(dbDir, { recursive: true });
}

console.log(`📂 SQLite DB Path : ${dbPath}`);

export const db = new Database(dbPath);

// Initialiser les tables de la base de données SQLite
export function initDb() {

  // Activer les foreign keys
  db.exec(`PRAGMA foreign_keys = ON;`);

  db.exec(`
    CREATE TABLE IF NOT EXISTS roles (
      id TEXT PRIMARY KEY,
      name TEXT UNIQUE NOT NULL,
      description TEXT,
      permissions TEXT
    );
  `);

  db.exec(`
    CREATE TABLE IF NOT EXISTS users (
      id TEXT PRIMARY KEY,
      username TEXT UNIQUE NOT NULL,
      email TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      role TEXT NOT NULL REFERENCES roles(name),
      name TEXT NOT NULL,
      is_active INTEGER DEFAULT 1,
      created_at TEXT DEFAULT CURRENT_TIMESTAMP
    );
  `);

  db.exec(`
    CREATE TABLE IF NOT EXISTS user_centers (
      user_id TEXT REFERENCES users(id) ON DELETE CASCADE,
      center_id TEXT REFERENCES centers(id) ON DELETE CASCADE,
      PRIMARY KEY (user_id, center_id)
    );
  `);
  
  // Migrations pour ajouter les colonnes si elles n'existent pas
  try {
    db.exec(`ALTER TABLE users ADD COLUMN session_token TEXT;`);
  } catch (e) {
    // La colonne existe déjà
  }

  try {
    db.exec(`ALTER TABLE vehicles ADD COLUMN center_id TEXT REFERENCES centers(id) ON DELETE SET NULL;`);
  } catch (e) {
    // La colonne existe déjà
  }

  try {
    db.exec(`ALTER TABLE vehicle_documents ADD COLUMN doc_number TEXT;`);
  } catch (e) {}
  try {
    db.exec(`ALTER TABLE vehicle_documents ADD COLUMN valid_from TEXT;`);
  } catch (e) {}
  try {
    db.exec(`ALTER TABLE vehicle_documents ADD COLUMN valid_until TEXT;`);
  } catch (e) {}
  
  // CORRECTION: phone non UNIQUE et nullable pour éviter les conflits
  db.exec(`
    CREATE TABLE IF NOT EXISTS owners (
      id TEXT PRIMARY KEY,
      full_name TEXT NOT NULL,
      phone TEXT,
      email TEXT,
      address TEXT,
      status TEXT DEFAULT 'ACTIVE',
      created_at TEXT DEFAULT CURRENT_TIMESTAMP
    );
  `);
  
  db.exec(`
    CREATE TABLE IF NOT EXISTS vehicles (
      id TEXT PRIMARY KEY,
      plate_number TEXT UNIQUE NOT NULL,
      vin TEXT UNIQUE NOT NULL,
      brand TEXT NOT NULL,
      model TEXT NOT NULL,
      year_manufactured INTEGER NOT NULL,
      color TEXT DEFAULT '',
      vehicle_type TEXT NOT NULL DEFAULT 'SUV',
      status TEXT DEFAULT 'authentic',
      owner_id TEXT REFERENCES owners(id) ON DELETE RESTRICT,
      center_id TEXT REFERENCES centers(id) ON DELETE SET NULL,
      registered_at TEXT DEFAULT CURRENT_TIMESTAMP
    );
  `);

  db.exec(`
    CREATE TABLE IF NOT EXISTS vehicle_parts (
      id TEXT PRIMARY KEY,
      name TEXT NOT NULL,
      marking_code TEXT UNIQUE NOT NULL,
      vehicle_id TEXT REFERENCES vehicles(id) ON DELETE CASCADE,
      created_at TEXT DEFAULT CURRENT_TIMESTAMP
    );
  `);

  db.exec(`
    CREATE TABLE IF NOT EXISTS vehicle_documents (
      id TEXT PRIMARY KEY,
      doc_type TEXT NOT NULL,
      name TEXT NOT NULL,
      status TEXT DEFAULT 'VALID',
      doc_number TEXT,
      valid_from TEXT,
      valid_until TEXT,
      vehicle_id TEXT REFERENCES vehicles(id) ON DELETE CASCADE,
      uploaded_at TEXT DEFAULT CURRENT_TIMESTAMP
    );
  `);

  db.exec(`
    CREATE TABLE IF NOT EXISTS qrcodes (
      id TEXT PRIMARY KEY,
      vehicle_id TEXT UNIQUE REFERENCES vehicles(id) ON DELETE CASCADE,
      secure_token TEXT UNIQUE NOT NULL,
      qr_image_data TEXT,
      is_active INTEGER DEFAULT 1,
      created_at TEXT DEFAULT CURRENT_TIMESTAMP
    );
  `);

  db.exec(`
    CREATE TABLE IF NOT EXISTS audit_logs (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id TEXT,
      action TEXT NOT NULL,
      details TEXT,
      ip_address TEXT,
      created_at TEXT DEFAULT CURRENT_TIMESTAMP
    );
  `);

  db.exec(`
    CREATE TABLE IF NOT EXISTS vehicle_modification_history (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      vehicle_id TEXT,
      user_id TEXT,
      modified_at TEXT DEFAULT CURRENT_TIMESTAMP,
      action_type TEXT,
      modified_field TEXT,
      old_value TEXT,
      new_value TEXT
    );
  `);

  // TABLE CENTRES — persistée en base
  db.exec(`
    CREATE TABLE IF NOT EXISTS centers (
      id TEXT PRIMARY KEY,
      name TEXT NOT NULL,
      type TEXT DEFAULT 'center',
      region TEXT NOT NULL,
      description TEXT DEFAULT '',
      staff TEXT DEFAULT '',
      status TEXT DEFAULT 'Ouvert (08h - 18h)',
      x INTEGER DEFAULT 150,
      y INTEGER DEFAULT 150,
      created_at TEXT DEFAULT CURRENT_TIMESTAMP
    );
  `);

  // TABLE PATROUILLES — persistée en base
  db.exec(`
    CREATE TABLE IF NOT EXISTS squads (
      id TEXT PRIMARY KEY,
      region TEXT NOT NULL,
      inspector TEXT NOT NULL,
      status TEXT NOT NULL DEFAULT 'Disponible',
      mission TEXT DEFAULT '',
      battery TEXT DEFAULT '100%',
      x INTEGER DEFAULT 150,
      y INTEGER DEFAULT 150,
      created_at TEXT DEFAULT CURRENT_TIMESTAMP
    );
  `);

  // Triggers SQLite pour l'historique automatique
  db.exec(`
    CREATE TRIGGER IF NOT EXISTS trg_vehicle_insert
    AFTER INSERT ON vehicles
    BEGIN
      INSERT INTO vehicle_modification_history (vehicle_id, action_type, modified_field, old_value, new_value)
      VALUES (NEW.id, 'INSERT', 'ALL', NULL, NEW.plate_number);
    END;
  `);

  db.exec(`
    CREATE TRIGGER IF NOT EXISTS trg_vehicle_delete
    AFTER DELETE ON vehicles
    BEGIN
      INSERT INTO vehicle_modification_history (vehicle_id, action_type, modified_field, old_value, new_value)
      VALUES (OLD.id, 'DELETE', 'ALL', OLD.plate_number, NULL);
    END;
  `);

  db.exec(`
    CREATE TRIGGER IF NOT EXISTS trg_vehicle_update_status
    AFTER UPDATE OF status ON vehicles
    WHEN OLD.status <> NEW.status
    BEGIN
      INSERT INTO vehicle_modification_history (vehicle_id, action_type, modified_field, old_value, new_value)
      VALUES (NEW.id, 'UPDATE', 'status', OLD.status, NEW.status);
    END;
  `);

  // ====================================================================
  // SEED: Rôles
  // ====================================================================
  const roleCount = db.prepare("SELECT COUNT(*) as count FROM roles").get();
  if (roleCount.count === 0) {
    console.log("🌱 Insertion des rôles...");
    const insertRole = db.prepare(`
      INSERT INTO roles (id, name, description, permissions) 
      VALUES (?, ?, ?, ?)
    `);
    insertRole.run("r-admin", "admin", "Administrateur - Accès total", JSON.stringify([
      "manage_users", "manage_centers", "manage_squads", "manage_vehicles", "view_all_centers", "view_intercept", "view_map"
    ]));
    insertRole.run("r-agent", "agent", "Agent SPA - Gestion des gravages", JSON.stringify([
      "manage_vehicles", "view_own_center", "view_map"
    ]));
    insertRole.run("r-police", "police", "Officier PNC - Console Intercept & Carte", JSON.stringify([
      "view_intercept", "view_map"
    ]));
  }

  // ====================================================================
  // SEED: Utilisateurs par défaut
  // ====================================================================
  const userCount = db.prepare("SELECT COUNT(*) as count FROM users").get();
  if (userCount.count === 0) {
    console.log("🌱 Insertion des utilisateurs...");
    const insertUser = db.prepare(`
      INSERT INTO users (id, username, email, password_hash, role, name) 
      VALUES (?, ?, ?, ?, ?, ?)
    `);
    insertUser.run("u-admin", "admin", "admin@spa.cd", "admin", "admin", "Directeur Général SPA");
    insertUser.run("u-agent", "agent", "agent@spa.cd", "agent", "agent", "Agent Enregistreur SPA");
    insertUser.run("u-police", "police", "police@spa.cd", "police", "police", "Inspecteur PNC");
  }

  // ====================================================================
  // SEED: Centres agréés
  // ====================================================================
  const centerCount = db.prepare("SELECT COUNT(*) as count FROM centers").get();
  if (centerCount.count === 0) {
    console.log("🌱 Insertion des centres SPA...");
    const insertCenter = db.prepare(`INSERT INTO centers (id, name, type, region, description, staff, status, x, y) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`);
    insertCenter.run("cnt-01", "Centre National SPA - Gombe", "center", "Kinshasa - Gombe", "Centre principal de gravage laser haute puissance et délivrance des certificats physiques RDC.", "12 agents", "Ouvert (08h - 18h)", 210, 110);
    insertCenter.run("cnt-02", "Centre Agréé SPA - Limete", "center", "Kinshasa - Limete", "Centre secondaire de gravage et point de contrôle routier national.", "8 agents", "Ouvert (08h - 18h)", 340, 220);
    insertCenter.run("cnt-03", "Centre Agréé SPA - Ngaliema", "center", "Kinshasa - Ngaliema", "Poste mobile de gravage et contrôle pour l'ouest de la capitale.", "6 agents", "Ouvert (08h - 18h)", 90, 240);
  }

  // ====================================================================
  // SEED: Affectations agents aux centres
  // ====================================================================
  const userCenterCount = db.prepare("SELECT COUNT(*) as count FROM user_centers").get();
  if (userCenterCount.count === 0) {
    console.log("🌱 Insertion des affectations agents...");
    const insertUserCenter = db.prepare(`
      INSERT INTO user_centers (user_id, center_id)
      VALUES (?, ?)
    `);
    insertUserCenter.run("u-agent", "cnt-01");
  }

  // ====================================================================
  // SEED: Véhicules de démonstration
  // ====================================================================
  const vehicleCount = db.prepare("SELECT COUNT(*) as count FROM vehicles").get();
  if (vehicleCount.count === 0) {
    console.log("🌱 Insertion des véhicules de démonstration...");
    
    const insertOwner = db.prepare(`INSERT INTO owners (id, full_name, phone, email, address) VALUES (?, ?, ?, ?, ?)`);
    const insertVehicle = db.prepare(`INSERT INTO vehicles (id, plate_number, vin, brand, model, year_manufactured, color, vehicle_type, status, owner_id, center_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`);
    const insertPart = db.prepare(`INSERT INTO vehicle_parts (id, name, marking_code, vehicle_id) VALUES (?, ?, ?, ?)`);
    const insertDoc = db.prepare(`INSERT INTO vehicle_documents (id, doc_type, name, status, vehicle_id) VALUES (?, ?, ?, ?, ?)`);
    const insertQr = db.prepare(`INSERT INTO qrcodes (id, vehicle_id, secure_token) VALUES (?, ?, ?)`);

    // Véhicule 1: Authentique
    insertOwner.run("own-101", "Kabasele Mwamba Dieudonné", "+243 812 345 678", "dieudonne@kabasele.cd", "Avenue de la Gombe 12, Kinshasa");
    insertVehicle.run("veh-201", "AA-123-BC", "JTFGD21HA89012345", "Toyota", "Land Cruiser Prado", 2021, "Blanc Nacré", "SUV", "authentic", "own-101", "cnt-01");
    insertPart.run("part-1", "Catalyseur Principal", "CAT-90812", "veh-201");
    insertPart.run("part-2", "Rétroviseur Gauche", "RET-G-882", "veh-201");
    insertPart.run("part-3", "Rétroviseur Droit", "RET-D-883", "veh-201");
    insertDoc.run("doc-1", "carteRose", "Carte Rose AA-123-BC", "VALID", "veh-201");
    insertDoc.run("doc-2", "insurance", "Assurance SONAS 2026", "VALID", "veh-201");
    insertQr.run("qr-101", "veh-201", "token-authentic-123");

    // Véhicule 2: Signalé Volé
    insertOwner.run("own-102", "Mbuyi Kalombo Jean-Paul", "+243 999 123 456", "jp.mbuyi@gmail.com", "Boulevard Lumumba 340, Limete");
    insertVehicle.run("veh-202", "BG-4321-BB", "JTJHY78WF90001234", "Lexus", "LX 570", 2019, "Noir Métallisé", "SUV", "suspicious", "own-102", "cnt-01");
    insertPart.run("part-4", "Catalyseur Principal", "CAT-00192", "veh-202");
    insertPart.run("part-5", "Rétroviseurs (x2)", "RET-LX-99", "veh-202");
    insertDoc.run("doc-3", "carteRose", "Carte Rose BG-4321-BB", "VALID", "veh-202");
    insertQr.run("qr-102", "veh-202", "token-stolen-456");

    // Véhicule 3: En attente
    insertOwner.run("own-103", "Ngoma Bakwa Christelle", "+243 851 987 654", "christelle.ngoma@spa.cd", "Avenue Victoire 88, Gombe");
    insertVehicle.run("veh-203", "CD-7890-KA", "WBA3X1C54DD123456", "BMW", "X5", 2022, "Gris Métallisé", "SUV", "pending", "own-103", "cnt-01");
    insertDoc.run("doc-4", "carteRose", "Carte Rose CD-7890-KA", "VALID", "veh-203");
    insertQr.run("qr-103", "veh-203", "token-pending-789");
  }

  // Mettre à jour tous les véhicules sans center_id au cas où
  db.prepare("UPDATE vehicles SET center_id = 'cnt-01' WHERE center_id IS NULL").run();

  // ====================================================================
  // SEED: Patrouilles mobiles
  // ====================================================================
  const squadCount = db.prepare("SELECT COUNT(*) as count FROM squads").get();
  if (squadCount.count === 0) {
    console.log("🌱 Insertion des patrouilles mobiles...");
    const insertSquad = db.prepare(`INSERT INTO squads (id, region, inspector, status, mission, battery, x, y) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`);
    insertSquad.run("SQUAD-01", "Kinshasa - Gombe", "Diallo Diallo", "En Patrouille", "Contrôles aléatoires Boulevard 30 Juin", "92%", 170, 80);
    insertSquad.run("SQUAD-02", "Kinshasa - Ngaliema", "Kabasele Aimé", "En Mission", "Intervention sur pièce suspecte à Kintambo Magasin", "78%", 130, 270);
    insertSquad.run("SQUAD-03", "Kinshasa - Limete", "Mavinga Roger", "Disponible", "Standby au poste de contrôle Limete interchange", "85%", 360, 180);
    insertSquad.run("SQUAD-04", "Kinshasa - Bandalungwa", "Bondo Christian", "Disponible", "Standby Boulevard Triomphal", "95%", 230, 220);
  }

  console.log("✅ Base de données initialisée avec succès.");
}
