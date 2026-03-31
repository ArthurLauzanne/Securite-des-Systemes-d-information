const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const bodyParser = require('body-parser');
const path = require('path');
const fs = require('fs');
const { exec } = require('child_process'); // Requis pour l'injection de commandes

const app = express();
const port = 3000;

app.use(bodyParser.urlencoded({ extended: true }));

// --- BASE DE DONNÉES SQLITE ---
const db = new sqlite3.Database(':memory:');
db.serialize(() => {
    db.run("CREATE TABLE users (id INT, username TEXT, password TEXT, role TEXT)");
    db.run("INSERT INTO users VALUES (1, 'admin', 'SuperSecret123', 'admin')");
    db.run("INSERT INTO users VALUES (2, 'student', 'Moodle2026', 'student')");

    db.run("CREATE TABLE comments (id INTEGER PRIMARY KEY AUTOINCREMENT, text TEXT)");
    db.run("INSERT INTO comments (text) VALUES ('Premier test du cours !')");
});

// =========================================================================
// VULNÉRABILITÉS INTÉGRÉES POUR LE CYBER CHALLENGE
// =========================================================================

// Faille 8 : Open Redirect (Redirection Ouverte)
// Si l'URL est /?next=http://malicious.com, l'utilisateur sera redirigé là-bas après le login
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'login.html'));
});

// Faille 1 : Injection SQL (Authentification)
app.post('/', (req, res) => {
    const { username, password } = req.body;
    const redirectUrl = req.query.next || '/calendar?user=student'; // Open Redirect suite
    
    const query = `SELECT * FROM users WHERE username = '${username}' AND password = '${password}'`;
    console.log("Requête SQL : ", query);

    db.get(query, (err, row) => {
        if (err) res.send("Erreur BDD !");
        else if (row) res.redirect(redirectUrl);
        else res.send("<h1>Identifiants incorrects. <a href='/'>Réessayer</a></h1>");
    });
});

// Faille 4 : IDOR (Insecure Direct Object Reference)
// Faille 2 : XSS Réfléchi (Barre de recherche)
app.get('/calendar', (req, res) => {
    const motRecherche = req.query.recherche; 
    const requestedUser = req.query.user; // IDOR : On lit l'utilisateur depuis l'URL sans vérifier l'authentification

    let pageHtml = fs.readFileSync(path.join(__dirname, 'calendar.html'), 'utf8');

    // IDOR Payload : Si on change ?user=student en ?user=admin
    if (requestedUser === 'admin') {
         pageHtml = pageHtml.replace('<h2>Rechercher un cours', '<h2 style="color:red;">⚠️ AGENDA SECRET DES PROFESSEURS AFFICHÉ ⚠️<br>Rechercher un cours');
    }

    // XSS Réfléchi Payload
    if (motRecherche) {
        const texteAffiche = `<span style="color: red;">Résultats pour : ${motRecherche}</span>`;
        pageHtml = pageHtml.replace('Resultat de recherche', texteAffiche);
    }

    // Faille 3 : XSS Stocké (Affichage des commentaires)
    db.all("SELECT text FROM comments", [], (err, rows) => {
        let commentairesHtml = rows.map(r => `<p>- ${r.text}</p>`).join(''); // AUCUN nettoyage (pas d'échappement HTML)
        pageHtml = pageHtml.replace('REMPLACEMENT_COMMENTAIRES', commentairesHtml);
        res.send(pageHtml);
    });
});

// Faille 3 : XSS Stocké (Ajout du commentaire)
app.post('/add-comment', (req, res) => {
    const comment = req.body.comment;
    // On insère le commentaire en base sans le nettoyer
    db.run(`INSERT INTO comments (text) VALUES ('${comment}')`, () => {
        res.redirect('/calendar?user=student');
    });
});

// Faille 5 : Path Traversal / LFI (Local File Inclusion)
// L'attaquant peut demander /download?file=../../../server.js
app.get('/download', (req, res) => {
    const file = req.query.file;
    if(!file) return res.send("Aucun fichier spécifié.");
    
    // VULNÉRABILITÉ : On lit n'importe quel fichier système sans vérifier le chemin
    const filePath = path.join(__dirname, file); 
    
    if (fs.existsSync(filePath)) {
        res.download(filePath);
    } else {
        res.send("Fichier introuvable.");
    }
});

// Faille 6 : Contrôle d'Accès Défaillant (Broken Access Control)
// Il n'y a aucune vérification de session pour accéder à cette page critique !
app.get('/admin', (req, res) => {
    res.sendFile(path.join(__dirname, 'admin.html'));
});

// Faille 9 : Injection de Commandes (OS Command Injection)
app.post('/ping', (req, res) => {
    const ip = req.body.ip;
    
    // VULNÉRABILITÉ : On exécute directement l'entrée utilisateur dans le terminal du serveur Windows/Linux
    // Payload Red Team : 127.0.0.1 & dir (ou & ls)
    exec(`ping -n 1 ${ip}`, (error, stdout, stderr) => {
        let pageHtml = fs.readFileSync(path.join(__dirname, 'admin.html'), 'utf8');
        pageHtml = pageHtml.replace('REMPLACEMENT_PING', stdout || stderr || error.message);
        res.send(pageHtml);
    });
});

// Faille 10 : CSRF (Cross-Site Request Forgery)
app.get('/delete-all', (req, res) => {
    db.run("DELETE FROM comments"); 
    res.send("<h1>🚨 TOUTES LES DONNÉES ONT ÉTÉ SUPPRIMÉES ! 🚨</h1> <a href='/calendar?user=admin'>Retour à l'espace Admin</a>");
});

// Faille 7 : Information Disclosure (Divulgation d'informations)
// Une route de "debug" oubliée par les développeurs
app.get('/debug/db', (req, res) => {
    db.all("SELECT * FROM users", [], (err, rows) => {
        res.json(rows);
    });
});

// =========================================================================

app.listen(port, () => {
    console.log(`Serveur "Gruyère" démarré sur http://localhost:${port}`);
    console.log(`10 VULNÉRABILITÉS PRÊTES POUR LA RED TEAM !`);
});