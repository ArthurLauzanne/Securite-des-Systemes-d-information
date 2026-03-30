const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const bodyParser = require('body-parser');
const path = require('path');

const fs = require('fs');

const app = express();
const port = 3000;

// Configuration pour lire les données des formulaires
app.use(bodyParser.urlencoded({ extended: true }));

// Création d'une base de données SQLite en mémoire
const db = new sqlite3.Database(':memory:');

db.serialize(() => {
    // Création de la table des utilisateurs
    db.run("CREATE TABLE users (id INT, username TEXT, password TEXT)");
    // Insertion d'un utilisateur "légitime" pour tester
    db.run("INSERT INTO users VALUES (1, 'admin', 'SuperSecret123')");
    db.run("INSERT INTO users VALUES (2, 'arthur', 'Moodle2026')");
});

// Route 1 : Afficher la page de connexion quand on arrive sur le site
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'login.html'));
});

// Route 2 : Afficher la page agenda
app.get('/calendar', (req, res) => {
    // On lit le mot tapé dans la barre de recherche
    const motRecherche = req.query.recherche; 
    
    // On charge le fichier HTML de l'agenda
    let pageHtml = fs.readFileSync(path.join(__dirname, 'calendar.html'), 'utf8');

    // S'il y a eu une recherche, on l'injecte DIRECTEMENT dans le HTML
    if (motRecherche) {
        // ATTENTION VULNÉRABILITÉ INTENTIONNELLE
        // On ne filtre pas les balises <script> avant d'afficher le texte
        const texteAffiche = `<span style="color: red;">Résultats pour : ${motRecherche}</span>`;
        pageHtml = pageHtml.replace('Resultat de recherche', texteAffiche);
    }

    res.send(pageHtml);
});

// Route 3 : Le traitement du formulaire de connexion
app.post('/login', (req, res) => {
    const username = req.body.username;
    const password = req.body.password;

    // ATTENTION VULNÉRABILITÉ INTENTIONNELLE : Injection SQL classique
    // On concatène directement les variables dans la requête au lieu de les sécuriser.
    const query = `SELECT * FROM users WHERE username = '${username}' AND password = '${password}'`;
    
    console.log("Requête exécutée : ", query); // Pour que tu voies l'attaque dans le terminal !

    db.get(query, (err, row) => {
        if (err) {
            res.send("Erreur de base de données !");
        } else if (row) {
            // Si on trouve un utilisateur, on l'envoie vers l'agenda
            res.redirect('/calendar');
        } else {
            // Si les identifiants sont faux
            res.send("<h1>Identifiants incorrects. <a href='/'>Réessayer</a></h1>");
        }
    });
});

// Démarrage du serveur
app.listen(port, () => {
    console.log(`Serveur Moodle (Vulnérable) démarré sur http://localhost:${port}`);
});