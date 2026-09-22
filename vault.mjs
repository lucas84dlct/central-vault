#!/usr/bin/env node
/**
 * Central Vault — coffre-fort chiffré local, zéro connaissance.
 *
 * Principes :
 *  - Ta phrase secrète ne quitte JAMAIS ta machine. Elle n'est ni stockée, ni envoyée.
 *  - Les fichiers sont chiffrés avec XChaCha20-Poly1305 (clé dérivée par Argon2id, libsodium).
 *  - Le dossier `blobs/` ne contient QUE des fichiers chiffrés : tu peux le pousser sur
 *    GitHub (ou n'importe où) sans risque — illisible sans ta phrase secrète.
 *
 * Commandes :
 *  vault init                       Crée un coffre dans ./CentralVault
 *  vault add <fichier>              Chiffre et ajoute un fichier au coffre
 *  vault list                       Liste le contenu du coffre
 *  vault get <nom> [-o <sortie>]    Déchiffre un fichier
 *  vault remove <nom>               Retire un fichier du coffre
 *  vault sync                       Pousse les blobs chiffrés vers GitHub (git)
 */

import sodium from 'libsodium-wrappers-sumo';
import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';
import readline from 'node:readline/promises';
import { stdin as input, stdout as output } from 'node:process';
import { spawnSync } from 'node:child_process';

const HOME = path.join(os.homedir(), 'CentralVault');
const BLOBS = path.join(HOME, 'blobs');
const META = path.join(HOME, 'vault.json');

/* ------------------------------------------------------------------ */
/* Source d'entropie.                                                  */
/*                                                                     */
/* Par défaut : crypto du système (CSPRNG matériel, éprouvé).          */
/* Pour brancher une source physique (caméra type "lava lamp",         */
/* micro, capteur de bruit) : remplace cette fonction par une          */
/* implémentation qui collecte des octets depuis ton capteur et        */
/* les mélange AU CSPRNG (jamais à la place).                          */
/* ------------------------------------------------------------------ */
async function secureRandom(n) {
  await sodium.ready;
  return sodium.randombytes_buf(n); // CSPRNG libsodium
}

/* ------------------------- Utilitaires --------------------------- */

async function askHidden(prompt) {
  const rl = readline.createInterface({ input, output });
  const sec = await rl.question(prompt);
  rl.close();
  return sec;
}

function bail(msg) {
  console.error(`✗ ${msg}`);
  process.exit(1);
}

function loadManifest() {
  const p = path.join(HOME, 'manifest.json');
  return JSON.parse(fs.readFileSync(p, 'utf8'));
}

function saveManifest(m) {
  fs.writeFileSync(path.join(HOME, 'manifest.json'), JSON.stringify(m, null, 2));
}

/* --------------------- Dérivation de clé ------------------------- */
/* Argon2id (paramètres libsodium "modérés" : 64 Mo, 3 passes).        */
/* La clé est dérivée À L'USAGE puis retirée de la mémoire.            */
/* ------------------------------------------------------------------ */
async function deriveKey(passphrase, salt) {
  await sodium.ready;
  return sodium.crypto_pwhash(
    sodium.crypto_aead_xchacha20poly1305_ietf_KEYBYTES,
    passphrase,
    salt,
    3,           // opsLimit (passes)
    67108864,    // memLimit (64 Mo)
    sodium.crypto_pwhash_ALG_ARGON2ID13
  );
}

/* --------------------------- Commandes --------------------------- */

async function cmdInit() {
  if (fs.existsSync(HOME)) bail(`Un coffre existe déjà dans ${HOME}`);
  fs.mkdirSync(BLOBS, { recursive: true });

  const passphrase = await askHidden('Choisis ta phrase secrète maîtresse (longue, unique, non réutilisée) : ');
  if (passphrase.length < 12) bail('Trop courte : 12 caractères minimum, idéalement une phrase de 4-5 mots.');

  const salt = sodium.randombytes_buf(sodium.crypto_pwhash_SALTBYTES);
  // On chiffre un "canari" pour valider la phrase à chaque ouverture.
  const key = await deriveKey(passphrase, salt);
  const canaryNonce = sodium.randombytes_buf(sodium.crypto_aead_xchacha20poly1305_ietf_NPUBBYTES);
  const canaryBody = sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(
    Buffer.from('central-vault-canary'), null, null, canaryNonce, key
  );
  const canary = Buffer.concat([Buffer.from(canaryNonce), Buffer.from(canaryBody)]);
  sodium.memzero(key);

  fs.writeFileSync(path.join(HOME, 'manifest.json'), JSON.stringify({
    version: 1,
    created: new Date().toISOString(),
    kdf: 'argon2id (ops=3, mem=64Mo)',
    cipher: 'xchacha20poly1305-ietf',
    salt: Buffer.from(salt).toString('hex'),
    canary: Buffer.from(canary).toString('hex'),
    entries: []
  }, null, 2));
  fs.writeFileSync(path.join(HOME, 'blobs', '.gitkeep'), '');
  console.log(`✓ Coffre créé dans ${HOME}`);
  console.log('  → Pousse `blobs/` + `manifest.json` sur ton repo GitHub privé pour la sauvegarde déportée.');
  console.log('  ⚠ N\'y mets JAMAIS ta phrase secrète. Perdue = coffre perdu, à jamais.');
}

async function openVault() {
  if (!fs.existsSync(path.join(HOME, 'manifest.json'))) bail('Aucun coffre ici. Lance : vault init');
  const manifest = JSON.parse(fs.readFileSync(path.join(HOME, 'manifest.json'), 'utf8'));
  const passphrase = await askHidden('Phrase secrète : ');
  const salt = Buffer.from(manifest.salt, 'hex');
  const key = await deriveKey(passphrase, salt);
  try {
    const raw = Buffer.from(manifest.canary, 'hex');
    sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(
      null, raw.subarray(24), null, raw.subarray(0, 24), key
    );
  } catch {
    bail('Phrase secrète incorrecte.');
  }
  return { manifest, key };
}

async function cmdAdd(file) {
  if (!fs.existsSync(file)) bail(`Fichier introuvable : ${file}`);
  const { manifest, key } = await openVault();

  const name = path.basename(file);
  if (manifest.entries.some(e => e.name === name)) bail(`"${name}" est déjà dans le coffre (remove d'abord).`);

  const nonce = sodium.randombytes_buf(sodium.crypto_aead_xchacha20poly1305_ietf_NPUBBYTES);
  const plain = fs.readFileSync(file);
  const cipher = sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(plain, null, null, nonce, key);
  sodium.memzero(key);

  const id = `${Date.now()}-${name.replace(/[^\w.-]/g, '_')}.box`;
  fs.writeFileSync(path.join(BLOBS, id), Buffer.concat([Buffer.from(nonce), Buffer.from(cipher)]));

  manifest.entries.push({
    name,
    blob: id,
    size: plain.length,
    sha256original: Buffer.from(sodium.crypto_generichash(32, plain)).toString('hex'),
    addedAt: new Date().toISOString()
  });
  saveManifest(manifest);
  console.log(`✓ "${name}" chiffré et ajouté (${(plain.length / 1024).toFixed(1)} Ko). Seul le blob chiffré est stocké.`);
}

async function cmdList() {
  const { manifest, key } = await openVault();
  sodium.memzero(key);
  if (manifest.entries.length === 0) { console.log('(coffre vide)'); return; }
  for (const e of manifest.entries) {
    console.log(`  ${e.name.padEnd(40)} ${(e.size / 1024).toFixed(1).padStart(9)} Ko   ajouté ${e.addedAt.slice(0, 10)}`);
  }
}

async function cmdGet(name, out) {
  const { manifest, key } = await openVault();
  const e = manifest.entries.find(x => x.name === name || x.name === name + '.box');
  if (!e) bail(`"${name}" n'est pas dans le coffre.`);
  const raw = fs.readFileSync(path.join(BLOBS, e.blob));
  const nonce = raw.subarray(0, sodium.crypto_aead_xchacha20poly1305_ietf_NPUBBYTES);
  const cipher = raw.subarray(sodium.crypto_aead_xchacha20poly1305_ietf_NPUBBYTES);
  let plain;
  try {
    plain = sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(null, cipher, null, nonce, key);
  } catch {
    bail('Échec du déchiffrement (données altérées ou phrase incorrecte).');
  }
  sodium.memzero(key);
  const dest = out || name;
  fs.writeFileSync(dest, plain);
  console.log(`✓ "${e.name}" déchiffré → ${dest} (integrity OK)`);
}

async function cmdRemove(name) {
  const { manifest, key } = await openVault();
  sodium.memzero(key);
  const e = manifest.entries.find(x => x.name === name);
  if (!e) bail(`"${name}" n'est pas dans le coffre.`);
  fs.unlinkSync(path.join(BLOBS, e.blob));
  manifest.entries = manifest.entries.filter(x => x.name !== name);
  saveManifest(manifest);
  console.log(`✓ "${name}" retiré du coffre.`);
}

function cmdSync(msg) {
  spawnSync('git', ['add', '-A'], { cwd: HOME, stdio: 'inherit' });
  const c = spawnSync('git', ['commit', '-m', msg || 'sync vault'], { cwd: HOME, stdio: 'inherit' });
  if (c.status !== 0 && !/nothing to commit/.test(c.stderr + c.stdout)) process.exit(c.status || 1);
  spawnSync('git', ['push'], { cwd: HOME, stdio: 'inherit' });
}

/* ----------------------------- CLI ------------------------------- */

const [cmd, ...args] = process.argv.slice(2);
try {
  await sodium.ready;
  switch (cmd) {
    case 'init': await cmdInit(); break;
    case 'add': args[0] ? await cmdAdd(args[0]) : bail('Usage: vault add <fichier>'); break;
    case 'list': await cmdList(); break;
    case 'get': args[0] ? await cmdGet(args[0], args[1] === '-o' ? args[2] : undefined) : bail('Usage: vault get <nom> [-o sortie]'); break;
    case 'remove': args[0] ? await cmdRemove(args[0]) : bail('Usage: vault remove <nom>'); break;
    case 'sync': cmdSync(args.join(' ')); break;
    default:
      console.log('Central Vault — coffre-fort chiffré local (zéro connaissance)');
      console.log('  vault init              Créer le coffre');
      console.log('  vault add <fichier>     Chiffrer et ajouter un fichier');
      console.log('  vault list              Lister le contenu');
      console.log('  vault get <nom>         Déchiffrer un fichier');
      console.log('  vault remove <nom>      Retirer un fichier');
      console.log('  vault sync              Pousser les blobs chiffrés vers GitHub');
  }
} catch (err) {
  bail(err.message);
}