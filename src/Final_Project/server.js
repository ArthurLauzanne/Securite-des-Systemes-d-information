const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const bodyParser = require('body-parser');
const path = require('path');
const fs = require('fs');
const { exec } = require('child_process');
const session = require('express-session');

const app = express();
const port = 3000;

app.use(bodyParser.urlencoded({ extended: true }));


// Configuration des sessions sécurisées
app.use(session({
    secret: 'SuperSecretBlueTeamKey', // Clé de chiffrement du cookie
    resave: false,
    saveUninitialized: false
}));

// Fonction utilitaire pour contrer le XSS
function escapeHTML(str) {
    if (!str) return '';
    return str.replace(/[&<>'"]/g, 
        tag => ({
            '&': '&amp;',
            '<': '&lt;',
            '>': '&gt;',
            "'": '&#39;',
            '"': '&quot;'
        }[tag])
    );
}

// --- BASE DE DONNÉES SQLITE ---
const db = new sqlite3.Database(':memory:');
db.serialize(() => {
    db.run("CREATE TABLE users (id INT, username TEXT, password TEXT, role TEXT)");
    db.run("INSERT INTO users VALUES (1, 'admin', 'SuperSecret123', 'admin')");
    db.run("INSERT INTO users VALUES (2, 'student', 'Moodle2026', 'student')");

    db.run("CREATE TABLE comments (id INTEGER PRIMARY KEY AUTOINCREMENT, text TEXT)");
    db.run("INSERT INTO comments (text) VALUES ('Premier test du cours !')");
});

app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'login.html'));
});

app.post('/', (req, res) => {
    const { username, password } = req.body;
    
    // FAILLE 1 (SQLi) CORRIGÉE : Utilisation de requêtes préparées
    const query = `SELECT * FROM users WHERE username = ? AND password = ?`;

    db.get(query, [username, password], (err, row) => {
        if (err) return res.send("Erreur BDD !");
        
        if (row) {
            // FAILLE 4 (IDOR) CORRIGÉE : On stocke l'identité dans la session serveur (pas dans l'URL)
            req.session.user = row.username;
            req.session.role = row.role;

            // FAILLE 8 (Open Redirect) CORRIGÉE : On force la redirection vers une URL relative uniquement
            let redirectUrl = req.query.next;
            if (!redirectUrl || !redirectUrl.startsWith('/')) {
                redirectUrl = '/calendar'; 
            }
            res.redirect(redirectUrl);
        } else {
            res.send("<h1>Identifiants incorrects. <a href='/'>Réessayer</a></h1>");
        }
    });
});

app.get('/calendar', (req, res) => {
    // Vérification de sécurité : l'utilisateur est-il connecté ?
    if (!req.session.user) return res.redirect('/');

    const motRecherche = req.query.recherche; 
    const role = req.session.role; // IDOR CORRIGÉ : On lit le rôle depuis la session, pas depuis req.query.user

    let pageHtml = fs.readFileSync(path.join(__dirname, 'calendar.html'), 'utf8');

    if (role === 'admin') {
         pageHtml = pageHtml.replace('<h2>Rechercher un cours', '<h2 style="color:red;">⚠️ AGENDA SECRET DES PROFESSEURS AFFICHÉ ⚠️<br>Rechercher un cours');
    }

    if (motRecherche) {
        // FAILLE 2 (XSS Réfléchi) CORRIGÉE : Échappement des caractères dangereux
        const safeRecherche = escapeHTML(motRecherche);
        const texteAffiche = `<span style="color: red;">Résultats pour : ${safeRecherche}</span>`;
        pageHtml = pageHtml.replace('Resultat de recherche', texteAffiche);
    }

    db.all("SELECT text FROM comments", [], (err, rows) => {
        // FAILLE 3 (XSS Stocké) CORRIGÉE : On échappe le contenu de la base de données avant affichage
        let commentairesHtml = rows.map(r => `<p>- ${escapeHTML(r.text)}</p>`).join('');
        pageHtml = pageHtml.replace('REMPLACEMENT_COMMENTAIRES', commentairesHtml);
        res.send(pageHtml);
    });
});

app.post('/add-comment', (req, res) => {
    if (!req.session.user) return res.redirect('/');
    const comment = req.body.comment;
    
    // FAILLE 3 (XSS Stocké) CORRIGÉE : Requête préparée pour l'insertion
    db.run(`INSERT INTO comments (text) VALUES (?)`, [comment], () => {
        res.redirect('/calendar');
    });
});

app.get('/download', (req, res) => {
    if (!req.session.user) return res.redirect('/');
    const file = req.query.file;
    if(!file) return res.send("Aucun fichier spécifié.");
    
    // FAILLE 5 (Path Traversal & LFI) CORRIGÉE : Utilisation d'une Liste Blanche (Whitelist)
    const fichiersAutorises = ['syllabus.pdf']; // Seuls les fichiers de cette liste sont téléchargeables

    if (!fichiersAutorises.includes(file)) {
        return res.status(403).send("<h1>Accès Interdit. Tentative de téléchargement non autorisée bloquée.</h1>");
    }
    
    const filePath = path.join(__dirname, file); 
    
    if (fs.existsSync(filePath)) {
        res.download(filePath);
    } else {
        res.send("Le fichier n'existe pas physiquement sur le serveur.");
    }
});

app.get('/admin', (req, res) => {
    // FAILLE 6 (Broken Access Control) CORRIGÉE : On vérifie que c'est bien l'administrateur
    if (req.session.role !== 'admin') {
        return res.status(403).send("<h1>Accès Interdit. Vous n'êtes pas professeur.</h1>");
    }
    res.sendFile(path.join(__dirname, 'admin.html'));
});

app.post('/ping', (req, res) => {
    if (req.session.role !== 'admin') return res.status(403).send("Interdit");
    const ip = req.body.ip;
    
    // FAILLE 9 (OS Command Injection) CORRIGÉE : Regex stricte qui n'accepte QUE les formats IP ou nom de domaine simple, aucun caractère spécial comme & ou |
    if (!/^[a-zA-Z0-9.\-]+$/.test(ip)) {
        return res.send("Format IP/Domaine invalide. Tentative de piratage bloquée.");
    }

    exec(`ping -n 1 ${ip}`, (error, stdout, stderr) => {
        let pageHtml = fs.readFileSync(path.join(__dirname, 'admin.html'), 'utf8');
        pageHtml = pageHtml.replace('REMPLACEMENT_PING', stdout || stderr || "Erreur réseau.");
        res.send(pageHtml);
    });
});

// FAILLE 10 (CSRF) CORRIGÉE : Changement de GET vers POST + vérification Admin
app.post('/delete-all', (req, res) => { // CHANGÉ en app.post
    if (req.session.role !== 'admin') return res.status(403).send("Interdit");
    db.run("DELETE FROM comments"); 
    res.send("<h1>🚨 TOUTES LES DONNÉES ONT ÉTÉ SUPPRIMÉES ! 🚨</h1> <a href='/calendar'>Retour à l'espace Admin</a>");
});

// =========================================================================

app.listen(port, () => {
    console.log(`Serveur démarré sur http://localhost:${port}`);
});