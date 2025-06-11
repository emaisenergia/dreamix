// server.js - Versão Final com GrapesJS Editor

const express = require('express');
const path = require('path');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcrypt');
const session = require('express-session');
const axios = require('axios');
const archiver = require('archiver');
const cheerio = require('cheerio'); // Nova dependência para ler o HTML

const app = express();
const PORT = 3000;

// ... (Toda a configuração da Base de Dados e do Express continua igual) ...
const dbPath = path.join(__dirname, 'data');
require('fs').mkdirSync(dbPath, { recursive: true });
const db = new sqlite3.Database(path.join(dbPath, 'dreamix.db'), (err) => {
    if (err) console.error("Erro ao abrir a base de dados", err.message);
    else console.log("Conectado à base de dados SQLite.");
    db.run(`CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT, email TEXT NOT NULL UNIQUE, password TEXT NOT NULL)`);
    db.run(`CREATE TABLE IF NOT EXISTS clone_history (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL, original_url TEXT NOT NULL, cloned_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP, FOREIGN KEY (user_id) REFERENCES users (id))`);
});
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));
app.use(express.static('public'));
app.use(express.json({ limit: '50mb' })); // Aumenta o limite para o corpo do pedido para o editor
app.use(express.urlencoded({ extended: true, limit: '50mb' }));
app.use(session({
    secret: 'dreamix-app-secret-key-muito-segura',
    resave: false,
    saveUninitialized: true,
    cookie: { secure: false, maxAge: 24 * 60 * 60 * 1000 }
}));
app.use((req, res, next) => {
    res.locals.user = req.session.user;
    next();
});
function requireLogin(req, res, next) {
    if (!req.session.user) return res.redirect('/login');
    next();
}

// --- ROTAS DE AUTENTICAÇÃO E DA APLICAÇÃO (sem alterações) ---
app.get('/login', (req, res) => res.render('login', { error: req.query.error, success: req.query.success }));
app.get('/registo', (req, res) => res.render('register', { error: req.query.error }));
app.post('/registo', async (req, res) => { /* ...código igual... */
    const { name, email, password } = req.body;
    if (!name || !email || !password) return res.redirect('/registo?error=Todos os campos são obrigatórios.');
    try {
        const hashedPassword = await bcrypt.hash(password, 10);
        db.run(`INSERT INTO users (name, email, password) VALUES (?, ?, ?)`, [name, email, hashedPassword], (err) => {
            if (err) return res.redirect('/registo?error=Este email já está em uso.');
            res.redirect('/login?success=Conta criada com sucesso! Pode fazer o login.');
        });
    } catch { res.redirect('/registo?error=Ocorreu um erro no servidor.'); }
});
app.post('/login', (req, res) => { /* ...código igual... */
    const { email, password } = req.body;
    db.get(`SELECT * FROM users WHERE email = ?`, [email], async (err, user) => {
        if (!user || !(await bcrypt.compare(password, user.password))) return res.redirect('/login?error=Email ou senha inválidos.');
        req.session.user = { id: user.id, name: user.name, email: user.email };
        res.redirect('/');
    });
});
app.get('/logout', (req, res) => req.session.destroy(() => res.redirect('/login')));
app.get('/', requireLogin, (req, res) => res.render('dashboard'));
app.get('/historico', requireLogin, (req, res) => { /* ...código igual... */
    const userId = req.session.user.id;
    db.all(`SELECT * FROM clone_history WHERE user_id = ? ORDER BY cloned_at DESC`, [userId], (err, rows) => {
        if (err) return res.status(500).send("Não foi possível carregar o seu histórico.");
        res.render('history', { history: rows });
    });
});
// --- FIM DAS ROTAS SEM ALTERAÇÕES ---


// --- ROTAS DAS FERRAMENTAS E EDITOR (ATUALIZADAS) ---

// ATUALIZADA: Rota para abrir o editor GrapesJS
app.get('/editar', requireLogin, async (req, res) => {
    const { url } = req.query;
    if (!url) return res.status(400).send("URL de destino é obrigatória.");

    try {
        const response = await axios.get(url, { headers: { 'User-Agent': 'Mozilla/5.0' }});
        let htmlContent = response.data;

        // Usa o Cheerio para encontrar e carregar o CSS
        const $ = cheerio.load(htmlContent);
        let cssContent = '';
        const cssPromises = [];

        $('link[rel="stylesheet"]').each((i, link) => {
            let href = $(link).attr('href');
            if (href) {
                // Constrói um URL absoluto para o ficheiro CSS
                const cssUrl = new URL(href, url).href;
                cssPromises.push(
                    axios.get(cssUrl).then(cssRes => cssRes.data).catch(() => '')
                );
            }
        });

        const cssResults = await Promise.all(cssPromises);
        cssContent = cssResults.join('\n');
        
        // Remove as tags <link> do HTML para não carregar o CSS externo no editor
        $('link[rel="stylesheet"]').remove();
        htmlContent = $.html();

        res.render('editor', { htmlContent, cssContent });

    } catch (error) {
        console.error("Erro ao carregar site no editor:", error.message);
        res.status(500).send("Não foi possível carregar o conteúdo do site para edição.");
    }
});

// NOVA: Rota para exportar o conteúdo do GrapesJS
app.post('/exportar', requireLogin, (req, res) => {
    const { html, css } = req.body;

    try {
        res.setHeader('Content-Type', 'application/zip');
        res.setHeader('Content-Disposition', 'attachment; filename="site_editado.zip"');

        const archive = archiver('zip');
        archive.pipe(res);
        archive.append(html, { name: 'index.html' });
        archive.append(css, { name: 'style.css' });
        archive.finalize();

    } catch (error) {
        console.error("Erro ao exportar ZIP:", error.message);
        res.status(500).json({ error: 'Falha ao gerar o ficheiro ZIP.' });
    }
});


// As rotas antigas de download direto continuam a funcionar
app.get('/clonar-e-baixar', requireLogin, async (req, res) => { /* ...código anterior... */
    const { url } = req.query;
    if (!url) return res.status(400).json({ error: 'URL é obrigatória.' });
    try {
        const response = await axios.get(url, { headers: { 'User-Agent': 'Mozilla/5.0' } });
        const htmlContent = response.data;
        const fileName = new URL(url).hostname.replace(/\./g, '_') + '.zip';
        db.run(`INSERT INTO clone_history (user_id, original_url) VALUES (?, ?)`, [req.session.user.id, url]);
        res.setHeader('Content-Type', 'application/zip');
        res.setHeader('Content-Disposition', `attachment; filename="${fileName}"`);
        const archive = archiver('zip');
        archive.pipe(res);
        archive.append(htmlContent, { name: 'index.html' });
        await archive.finalize();
    } catch (error) { res.status(500).json({ error: 'Falha ao aceder ou processar o URL fornecido.' }); }
});
app.get('/gerar-tema-wp', requireLogin, async (req, res) => { /* ...código anterior... */
    const { url } = req.query;
    if (!url) return res.status(400).json({ error: 'URL é obrigatória.' });
    try {
        const pageResponse = await axios.get(url, { headers: { 'User-Agent': 'Mozilla/5.0' } });
        const htmlContent = pageResponse.data;
        const themeName = new URL(url).hostname.replace(/\./g, '_').replace(/-/g, ' ');
        const zipFileName = `${themeName.replace(/\s/g, '-')}-wp-theme.zip`;
        const cssContent = `/*\nTheme Name: ${themeName}\nAuthor: Dreamix Cloner\nDescription: Um tema gerado a partir de ${url}\nVersion: 1.0\n*/`;
        db.run(`INSERT INTO clone_history (user_id, original_url) VALUES (?, ?)`, [req.session.user.id, `[WP Theme] ${url}`]);
        res.setHeader('Content-Type', 'application/zip');
        res.setHeader('Content-Disposition', `attachment; filename="${zipFileName}"`);
        const archive = archiver('zip');
        archive.pipe(res);
        archive.append(htmlContent, { name: 'index.php' });
        archive.append(cssContent, { name: 'style.css' });
        await archive.finalize();
    } catch (error) { res.status(500).json({ error: 'Falha ao gerar o tema WordPress.' }); }
});

app.listen(PORT, () => console.log(`🚀 Servidor da Aplicação Dreamix a correr em http://localhost:${PORT}`));