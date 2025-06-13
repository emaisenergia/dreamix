// server.js - Versão Final com todas as funcionalidades e GrapesJS Editor

const express = require('express');
const path = require('path');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcrypt');
const session = require('express-session');
const axios = require('axios');
const archiver = require('archiver');
const cheerio = require('cheerio');
const fs = require('fs-extra'); // <<< ESSENCIAL: Biblioteca para manipulação de arquivos/pastas

const app = express();
const PORT = 3000;

// --- CONFIGURAÇÃO DA BASE DE DADOS E EXPRESS ---
// Garante que a pasta 'data' exista para o SQLite
const dbPath = path.join(__dirname, 'data');
require('fs').mkdirSync(dbPath, { recursive: true });

const db = new sqlite3.Database(path.join(dbPath, 'dreamix.db'), (err) => {
    if (err) {
        console.error("Erro ao abrir a base de dados", err.message);
    } else {
        console.log("Conectado à base de dados SQLite.");
    }
    // Criação das tabelas se não existirem
    // ATUALIZADO: Adicionando 'isAdmin', 'subscription_level', 'isActive' e 'whatsapp_number' na tabela 'users'
    db.run(`CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT,
        email TEXT NOT NULL UNIQUE,
        password TEXT NOT NULL,
        whatsapp_number TEXT,                      -- <<< NOVO: Número de WhatsApp do usuário
        isAdmin INTEGER DEFAULT 0,                 -- 0 para não admin, 1 para admin
        subscription_level TEXT DEFAULT 'Free',    -- Nível de assinatura (ex: 'Free', 'Basic', 'Premium')
        isActive INTEGER DEFAULT 1                 -- 1 para ativo, 0 para bloqueado
    )`);
    db.run(`CREATE TABLE IF NOT EXISTS clone_history (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL, original_url TEXT NOT NULL, cloned_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP, FOREIGN KEY (user_id) REFERENCES users (id))`);
});

// Configuração do EJS como view engine e localização das views
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

// Middleware para servir arquivos estáticos da pasta 'public'
app.use(express.static('public'));

// Middleware para parsing de JSON e URL-encoded bodies com limite aumentado para o editor
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ extended: true, limit: '50mb' }));

// Configuração da sessão
app.use(session({
    secret: 'dreamix-app-secret-key-muito-segura', // Chave secreta para assinar o cookie de sessão
    resave: false,                                 // Não salva a sessão se não houver modificações
    saveUninitialized: true,                       // Salva sessões novas (não inicializadas)
    cookie: { secure: false, maxAge: 24 * 60 * 60 * 1000 } // Configurações do cookie (secure: true em HTTPS)
}));

// Middleware para tornar as informações do usuário logado disponíveis nas views EJS
// ATUALIZADO: Inclui isAdmin e isActive na sessão para uso direto no EJS, e busca no DB para garantir que esteja atualizado.
app.use(async (req, res, next) => {
    if (req.session.user && req.session.user.id) {
        // Busca os dados do usuário no DB a cada request para garantir que os dados estejam atualizados
        try {
            const userFromDb = await new Promise((resolve, reject) => {
                db.get(`SELECT id, name, email, isAdmin, subscription_level, isActive, whatsapp_number FROM users WHERE id = ?`, [req.session.user.id], (err, user) => { // <<< SELECIONA whatsapp_number
                    if (err) reject(err);
                    resolve(user);
                });
            });
            if (userFromDb) {
                req.session.user = { // Atualiza a sessão com dados frescos do DB
                    id: userFromDb.id,
                    name: userFromDb.name,
                    email: userFromDb.email,
                    isAdmin: userFromDb.isAdmin,
                    subscription_level: userFromDb.subscription_level,
                    isActive: userFromDb.isActive,
                    whatsapp_number: userFromDb.whatsapp_number // <<< ARMAZENA whatsapp_number NA SESSÃO
                };
            } else {
                // Usuário não encontrado no DB, talvez tenha sido deletado. Limpa a sessão.
                req.session.destroy();
                return res.redirect('/login');
            }
        } catch (error) {
            console.error("Erro ao buscar dados do usuário na sessão:", error.message);
            // Continua, mas o res.locals.user pode não ter dados corretos
        }
    }
    res.locals.user = req.session.user; // Torna user disponível nas views EJS
    next();
});

// Middleware de autenticação: exige que o usuário esteja logado para acessar certas rotas
// ATUALIZADO: Verifica se o usuário está ativo
function requireLogin(req, res, next) {
    if (!req.session.user) {
        return res.redirect('/login');
    }
    // Verifica se o usuário está ativo
    if (req.session.user.isActive === 0) { // Se isActive for 0 (bloqueado)
        req.session.destroy(() => { // Destrói a sessão
            res.redirect('/login?error=Sua conta está bloqueada.'); // Redireciona com mensagem de erro
        });
        return; // Sai da função
    }
    next();
}

// NOVO: Middleware de autenticação para ADMINISTRADORES
function requireAdmin(req, res, next) {
    if (!req.session.user || req.session.user.isAdmin !== 1) {
        console.warn(`Tentativa de acesso admin negada para user_id: ${req.session.user ? req.session.user.id : 'N/A'}`);
        return res.status(403).send("Acesso negado. Você não tem permissão de administrador."); // 403 Forbidden
    }
    next(); // Se for admin, continua
}


// --- ROTAS DE AUTENTICAÇÃO E DA APLICAÇÃO ---
app.get('/login', (req, res) => {
    const whatsappLink = req.query.whatsapp || null; // Pega o link do WhatsApp da URL, ou null se não existir
    res.render('login', { 
        error: req.query.error, 
        success: req.query.success,
        whatsapp: whatsappLink // <<< PASSA O LINK DO WHATSAPP PARA O TEMPLATE
    });
});
app.get('/registo', (req, res) => res.render('register', { error: req.query.error }));

app.post('/registo', async (req, res) => {
    const { name, email, password, confirm_password, whatsapp_number } = req.body; // <<< Recebe novos campos
    
    // Validação de campos obrigatórios
    if (!name || !email || !password || !confirm_password || !whatsapp_number) { 
        return res.redirect('/registo?error=Todos os campos são obrigatórios.');
    }

    // Validação de Confirmação de Senha (Backend)
    if (password !== confirm_password) {
        return res.redirect('/registo?error=As senhas não coincidem.');
    }

    // Validação básica de WhatsApp (Backend) - apenas dígitos, ajuste conforme necessário
    const cleanedWhatsappNumber = whatsapp_number.replace(/[\s-()]/g, ''); // Limpa o número
    if (!/^\d+$/.test(cleanedWhatsappNumber) || cleanedWhatsappNumber.length < 10) {
        return res.redirect('/registo?error=Número de WhatsApp inválido. Use apenas dígitos (com DDD).');
    }

    try {
        const hashedPassword = await bcrypt.hash(password, 10); // Hash da senha
        // ATUALIZADO: Usuários novos são criados com isActive=0 (pendente) e whatsapp_number
        db.run(`INSERT INTO users (name, email, password, whatsapp_number, isAdmin, subscription_level, isActive) VALUES (?, ?, ?, ?, ?, ?, ?)`, 
            [name, email, hashedPassword, cleanedWhatsappNumber, 0, 'Free', 0], // <<< AGORA isActive É 0 POR PADRÃO, com whatsapp_number
            function (err) {
                if (err) {
                    return res.redirect('/registo?error=Este email já está em uso.');
                }

                // --- ATUALIZADO: Redirecionamento para WhatsApp com o número e mensagem fornecidos ---
                const adminWhatsAppNumber = '5584998920707'; // SEU NÚMERO DE WHATSAPP
                const whatsappMessage = encodeURIComponent(
                    `Olá, sou um novo usuário (a) ${name} (${email}) acabei de me cadastrar no Dreamix e preciso de aprovação do meu cadastro.\n\n` +
                    `Número de WhatsApp do usuário: ${cleanedWhatsappNumber}\n\n` + 
                    `Obrigada`
                );
                const whatsappRedirectUrl = `https://wa.me/${adminWhatsAppNumber}?text=${whatsappMessage}`;

                // Redireciona para a página de login com mensagem de sucesso e link do WhatsApp
                res.redirect(`/login?success=Cadastro realizado! Sua conta está pendente de aprovação. Por favor, clique no botão para entrar em contato pelo WhatsApp para liberação. &whatsapp=${encodeURIComponent(whatsappRedirectUrl)}`);
                // --- FIM DO REDIRECIONAMENTO ---
            }
        );
    } catch (error) {
        console.error("Erro ao registrar usuário:", error);
        res.redirect('/registo?error=Ocorreu um erro no servidor.');
    }
});

app.post('/login', (req, res) => {
    const { email, password } = req.body;
    db.get(`SELECT * FROM users WHERE email = ?`, [email], async (err, user) => {
        if (!user || !(await bcrypt.compare(password, user.password))) {
            return res.redirect('/login?error=Email ou senha inválidos.');
        }
        // ATUALIZADO: Armazena isAdmin, subscription_level, isActive E whatsapp_number na sessão no login
        req.session.user = { 
            id: user.id, 
            name: user.name, 
            email: user.email, 
            isAdmin: user.isAdmin,
            subscription_level: user.subscription_level,
            isActive: user.isActive,
            whatsapp_number: user.whatsapp_number // <<< ARMAZENA whatsapp_number NA SESSÃO NO LOGIN
        };
        res.redirect('/');
    });
});

app.get('/logout', (req, res) => {
    req.session.destroy(() => {
        res.redirect('/login');
    });
});

// Rota principal (dashboard) - exige login
app.get('/', requireLogin, (req, res) => {
    res.render('dashboard');
});

// Rota do histórico - exige login
app.get('/historico', requireLogin, (req, res) => {
    const userId = req.session.user.id;
    db.all(`SELECT * FROM clone_history WHERE user_id = ? ORDER BY cloned_at DESC`, [userId], (err, rows) => {
        if (err) {
            console.error("Erro ao carregar histórico:", err.message);
            return res.status(500).send("Não foi possível carregar o seu histórico.");
        }
        // CORREÇÃO: Passar 'rows' como 'history' para o template EJS
        res.render('history', { history: rows }); // <<< CORREÇÃO AQUI
    });
});

// --- ROTAS PARA PERFIL E ASSINATURA ---

// Rota para a página de Perfil do usuário
app.get('/perfil', requireLogin, (req, res) => {
    // res.locals.user já terá os dados atualizados (name, email, isAdmin, subscription_level, isActive, whatsapp_number)
    res.render('profile', { user: res.locals.user }); 
});

// Rota para a página de Assinatura
app.get('/assinatura', requireLogin, (req, res) => {
    res.render('subscription'); 
});

// Rota para a página de Tutoriais
app.get('/tutoriais', requireLogin, (req, res) => {
    res.render('tutorials'); // Renderiza a página de tutoriais
});


// --- ROTAS PARA ADMINISTRADORES ---
app.get('/admin/dashboard', requireAdmin, async (req, res) => { // Use async/await para facilitar
    try {
        // Busca todos os usuários, incluindo o nível de assinatura, status de ativo e whatsapp_number
        const users = await new Promise((resolve, reject) => {
            db.all(`SELECT id, name, email, isAdmin, subscription_level, isActive, whatsapp_number FROM users ORDER BY id ASC`, (err, rows) => { // <<< SELECIONA whatsapp_number
                if (err) reject(err);
                resolve(rows);
            });
        });

        // Busca todo o histórico de clonagem (de todos os usuários)
        const history = await new Promise((resolve, reject) => {
            db.all(`SELECT ch.original_url, ch.cloned_at, u.email as user_email FROM clone_history ch JOIN users u ON ch.user_id = u.id ORDER BY ch.cloned_at DESC`, (err, rows) => {
                if (err) reject(err);
                resolve(rows);
            });
        });

        // --- Estatísticas Gerais ---
        const userCount = await new Promise((resolve, reject) => {
            db.get(`SELECT COUNT(*) as count FROM users`, (err, row) => {
                if (err) reject(err);
                resolve(row.count);
            });
        });

        const cloneCount = await new Promise((resolve, reject) => {
            db.get(`SELECT COUNT(*) as count FROM clone_history`, (err, row) => {
                if (err) reject(err); 
                resolve(row.count);
            });
        });

        // Contagem de assinaturas por nível
        const subscriptionCounts = await new Promise((resolve, reject) => {
            db.all(`SELECT subscription_level, COUNT(*) as count FROM users GROUP BY subscription_level`, (err, rows) => {
                if (err) reject(err);
                const counts = {};
                rows.forEach(row => { counts[row.subscription_level] = row.count; });
                resolve(counts);
            });
        });

        // NOVO: Contagem de usuários com isActive = 0 (pendentes)
        const pendingUsersCount = await new Promise((resolve, reject) => {
            db.get(`SELECT COUNT(*) as count FROM users WHERE isActive = 0`, (err, row) => {
                if (err) reject(err);
                resolve(row.count);
            });
        });


        // Renderiza o template 'admin_dashboard' passando todos os dados
        res.render('admin_dashboard', {
            users: users,
            history: history,
            stats: {
                userCount: userCount,
                cloneCount: cloneCount,
                pendingUsersCount: pendingUsersCount, // <<< PASSA A NOVA CONTAGEM
                subscriptionCounts: subscriptionCounts
            }
        });

    } catch (error) {
        console.error("Erro ao carregar dados para admin dashboard:", error.message);
        res.status(500).send("Não foi possível carregar o dashboard do administrador.");
    }
});

// Rota para exibir o formulário de edição de usuário (Admin)
app.get('/admin/users/edit/:id', requireAdmin, async (req, res) => {
    const userId = req.params.id;
    try {
        const userToEdit = await new Promise((resolve, reject) => {
            // Busca o usuário pelo ID, incluindo o status de ativo e whatsapp_number
            db.get(`SELECT id, name, email, isAdmin, subscription_level, isActive, whatsapp_number FROM users WHERE id = ?`, [userId], (err, user) => { // <<< SELECIONA whatsapp_number
                if (err) reject(err);
                resolve(user);
            });
        });

        if (!userToEdit) {
            return res.status(404).send("Usuário não encontrado.");
        }

        res.render('admin_user_edit', { userToEdit: userToEdit }); // Renderiza a página de edição
    } catch (error) {
        console.error("Erro ao carregar formulário de edição de usuário:", error.message);
        res.status(500).send("Não foi possível carregar a página de edição do usuário.");
    }
});

// Rota para processar a edição de usuário (Admin)
app.post('/admin/users/edit/:id', requireAdmin, async (req, res) => {
    const userId = req.params.id;
    const { name, email, isAdmin, subscription_level, isActive, whatsapp_number } = req.body; // <<< Recebe whatsapp_number do formulário
    const isAdminValue = isAdmin === 'on' ? 1 : 0; 
    const isActiveValue = isActive === 'on' ? 1 : 0; 

    // Validação de WhatsApp (Backend) para edição - apenas dígitos, ajuste conforme necessário
    const cleanedWhatsappNumber = whatsapp_number.replace(/[\s-()]/g, ''); // Limpa o número
    if (!/^\d+$/.test(cleanedWhatsappNumber) || cleanedWhatsappNumber.length < 10) {
        return res.status(400).send("Número de WhatsApp inválido. Use apenas dígitos (com DDD).");
    }

    if (!name || !email || !subscription_level) { 
        return res.status(400).send("Nome, Email e Nível de Assinatura são obrigatórios.");
    }

    try {
        await new Promise((resolve, reject) => {
            db.run(`UPDATE users SET name = ?, email = ?, isAdmin = ?, subscription_level = ?, isActive = ?, whatsapp_number = ? WHERE id = ?`, // <<< ATUALIZA whatsapp_number
                [name, email, isAdminValue, subscription_level, isActiveValue, cleanedWhatsappNumber, userId], // <<< NOVO VALOR whatsapp_number
                function (err) {
                    if (err) reject(err);
                    resolve();
                }
            );
        });
        res.redirect('/admin/dashboard#usuarios'); 
    } catch (error) {
        console.error("Erro ao atualizar usuário:", error.message);
        res.status(500).send("Não foi possível atualizar as informações do usuário.");
    }
});

// Rota para excluir um usuário (Admin)
app.post('/admin/users/delete/:id', requireAdmin, async (req, res) => {
    const userId = req.params.id;

    try {
        // Primeiro, deletar registros relacionados (histórico de clonagem) para manter a integridade referencial
        await new Promise((resolve, reject) => {
            db.run(`DELETE FROM clone_history WHERE user_id = ?`, [userId], function(err) {
                if (err) reject(err);
                resolve();
            });
        });

        // Agora deleta o usuário
        await new Promise((resolve, reject) => {
            db.run(`DELETE FROM users WHERE id = ?`, [userId], function (err) {
                if (err) reject(err);
                resolve();
            });
        });
        res.redirect('/admin/dashboard#usuarios'); 
    } catch (error) {
        console.error("Erro ao excluir usuário:", error.message);
        res.status(500).send("Não foi possível excluir o usuário.");
    }
});

// Rota para visualizar detalhes de um usuário específico (Admin)
app.get('/admin/users/view/:id', requireAdmin, async (req, res) => {
    const userId = req.params.id;
    try {
        const userToView = await new Promise((resolve, reject) => {
            db.get(`SELECT id, name, email, isAdmin, subscription_level, isActive, whatsapp_number FROM users WHERE id = ?`, [userId], (err, user) => { // <<< SELECIONA whatsapp_number
                if (err) reject(err);
                resolve(user);
            });
        });

        if (!userToView) {
            return res.status(404).send("Usuário não encontrado.");
        }

        // Busca o histórico de clonagem SOMENTE para este usuário
        const userHistory = await new Promise((resolve, reject) => {
            db.all(`SELECT original_url, cloned_at FROM clone_history WHERE user_id = ? ORDER BY cloned_at DESC`, [userId], (err, rows) => {
                if (err) reject(err);
                resolve(rows);
            });
        });

        res.render('admin_user_view', { userToView: userToView, userHistory: userHistory });
    }
    catch (error) {
        console.error("Erro ao carregar detalhes do usuário:", error.message);
        res.status(500).send("Não foi possível carregar os detalhes do usuário.");
    }
});

// Rota para alternar o status (ativo/bloqueado) de um usuário (Admin)
app.post('/admin/users/toggle-status/:id', requireAdmin, async (req, res) => {
    const userId = req.params.id;
    const { currentStatus } = req.body; // Recebe o status atual (1 para ativo, 0 para bloqueado)

    // Calcula o novo status (se era 1, vira 0; se era 0, vira 1)
    const newStatus = currentStatus === '1' ? 0 : 1; 

    try {
        await new Promise((resolve, reject) => {
            db.run(`UPDATE users SET isActive = ? WHERE id = ?`,
                [newStatus, userId],
                function (err) {
                    if (err) reject(err);
                    resolve();
                }
            );
        });
        res.redirect('/admin/dashboard#usuarios'); 
    } catch (error) {
        console.error("Erro ao alternar status do usuário:", error.message);
        res.status(500).send("Não foi possível alternar o status do usuário.");
    }
});

// Rota para o formulário de cadastro de novo usuário para admin (simplesmente redireciona para o registro normal)
app.get('/admin/users/add', requireAdmin, (req, res) => {
    res.redirect('/registo'); // Reutiliza a página de registro existente
});


// --- ROTAS PARA GERENCIAMENTO DE ASSINATURAS (ADMIN) ---

// REMOVIDO: Rotas para gerenciar assinaturas diretamente, conforme solicitado.


// --- ROTAS DAS FERRAMENTAS E EDITOR ---

// Rota para abrir o editor GrapesJS
app.get('/editar', requireLogin, async (req, res) => {
    const { url } = req.query;
    if (!url) {
        return res.status(400).send("URL de destino é obrigatória.");
    }

    try {
        const response = await axios.get(url, { headers: { 'User-Agent': 'Mozilla/5.0' }});
        let htmlContent = response.data;

        // Usa o Cheerio para encontrar e carregar o CSS (apenas o que está em <link>)
        const $ = cheerio.load(htmlContent);
        let cssContent = '';
        const cssPromises = [];

        $('link[rel="stylesheet"]').each((i, link) => {
            let href = $(link).attr('href');
            if (href) {
                const cssUrl = new URL(href, url).href;
                cssPromises.push(
                    axios.get(cssUrl).then(res => res.data).catch(err => {
                        console.warn(`Não foi possível baixar CSS externo: ${cssUrl} - ${err.message}`); // Corrigido aqui para usar cssUrl
                        return ''; 
                    })
                );
            }
        });

        const cssResults = await Promise.all(cssPromises);
        cssContent = cssResults.join('\n');
        
        // Remove as tags <link> do HTML para não carregar o CSS externo no editor (evita duplicação)
        $('link[rel="stylesheet"]').remove();
        htmlContent = $.html(); // Pega o HTML modificado

        // Renderiza a view do editor (editor.ejs) passando o HTML e CSS
        res.render('editor', { htmlContent, cssContent });

    } catch (error) {
        console.error("Erro ao carregar site no editor:", error.message);
        res.status(500).send("Não foi possível carregar o conteúdo do site para edição.");
    }
});

// Rota para exportar o conteúdo do GrapesJS
app.post('/exportar', requireLogin, (req, res) => {
    const { html, css } = req.body; // Recebe o HTML e CSS do editor

    try {
        // Define os cabeçalhos para o download do arquivo ZIP
        res.setHeader('Content-Type', 'application/zip');
        res.setHeader('Content-Disposition', 'attachment; filename="site_editado.zip"');

        // Cria um novo arquivador ZIP
        const archive = archiver('zip');
        archive.pipe(res); // Conecta o arquivador à resposta HTTP

        archive.append(html, { name: 'index.html' });
        archive.append(css, { name: 'style.css' });
        
        archive.finalize();

    } catch (error) {
        console.error("Erro ao exportar ZIP:", error.message);
        res.status(500).json({ error: 'Falha ao gerar o ficheiro ZIP.' });
    }
});


// Rota para clonar e baixar um site como HTML
app.get('/clonar-e-baixar', requireLogin, async (req, res) => {
    const { url } = req.query;
    if (!url) {
        return res.status(400).json({ error: 'URL é obrigatória.' });
    }
    try {
        const response = await axios.get(url, { headers: { 'User-Agent': 'Mozilla/5.0' } }); // Adiciona User-Agent
        const htmlContent = response.data;
        const fileName = new URL(url).hostname.replace(/\./g, '_') + '.zip';
        db.run(`INSERT INTO clone_history (user_id, original_url) VALUES (?, ?)`, [req.session.user.id, url]);
        
        res.setHeader('Content-Type', 'application/zip');
        res.setHeader('Content-Disposition', `attachment; filename="${fileName}"`);
        
        const archive = archiver('zip');
        archive.pipe(res); // Conecta o arquivador à resposta HTTP
        archive.append(htmlContent, { name: 'index.html' }); // Adiciona o HTML ao ZIP
        await archive.finalize(); // Finaliza o arquivamento e envia o ZIP
    } catch (error) {
        console.error("Erro ao clonar e baixar:", error);
        res.status(500).json({ error: 'Falha ao aceder ou processar o URL fornecido.' });
    }
});


// ROTA PRINCIPAL PARA GERAR TEMA WORDPRESS FUNCIONAL
app.get('/gerar-tema-wp', requireLogin, async (req, res) => {
    const targetUrl = req.query.url; // Pega a URL enviada do frontend (do script.js)

    if (!targetUrl) {
        return res.status(400).json({ error: 'URL da página de destino é obrigatória.' });
    }

    let tempDir; // Variável para armazenar o caminho da pasta temporária do tema
    let zipFilePath; // Variável para armazenar o caminho do arquivo ZIP temporário

    try {
        // 1. Baixar o conteúdo HTML da URL
        // Adiciona um User-Agent para evitar bloqueios de alguns servidores
        const response = await axios.get(targetUrl, { headers: { 'User-Agent': 'Mozilla/5.0' } });
        const html = response.data;
        const $ = cheerio.load(html); // Carrega o HTML no Cheerio para manipulação

        // Obter o nome do host para ajudar a resolver caminhos relativos de assets
        const urlObj = new URL(targetUrl);
        const baseUrl = urlObj.origin; // Ex: 'https://exemplo.com'

        // Gerar um nome de tema único e criar o caminho da pasta temporária
        // Formato: 'cloned-theme-timestamp'
        const themeName = 'cloned-theme-' + Date.now(); 
        const rootTempDir = path.join(__dirname, 'temp_wp_themes'); // Pasta raiz para temas temporários
        tempDir = path.join(rootTempDir, themeName); // Pasta específica para este tema
        
        // Garante que a pasta temporária para o tema exista
        await fs.ensureDir(tempDir); 

        // Coletar conteúdo para os arquivos PHP do WordPress
        let headerContentHead = ''; // Conteúdo da tag <head> (para header.php)
        let headerContentBody = ''; // Conteúdo da tag <header> ou similar (para header.php)
        let footerContent = '';     // Conteúdo da tag <footer> (para footer.php)
        let mainContent = '';       // Conteúdo principal (para index.php)
        let allStyles = '';         // Para coletar todos os estilos CSS (para style.css)
        const externalScriptUrls = []; // Para coletar URLs de scripts externos (para functions.php)


        // --- EXTRAÇÃO E PREPARAÇÃO DO CONTEÚDO ---

        // A. Extrair conteúdo do <head>
        // Clonamos a tag <head> para manipulá-la sem afetar o HTML original usado para o body
        const $head = $('head').clone();

        // Remover elementos que não precisamos no header.php ou que serão tratados separadamente
        $head.find('link[rel="stylesheet"]').remove(); // Estilos CSS externos
        $head.find('style').remove();                   // Estilos CSS inline
        $head.find('script').remove();                  // Scripts JS
        $head.find('title').remove();                   // O título será gerado pelo WP
        
        headerContentHead = $head.html();

        // B. Extrair conteúdo do <header> (se existir)
        const $header = $('header').clone();
        if ($header.length > 0) {
            headerContentBody = $.html($header); // Pega o HTML completo da tag <header>
            $('header').remove(); // Remove do HTML original
        } else {
            const bodyChildren = $('body').children();
            let tempHeaderHtml = '';
            bodyChildren.each((i, el) => {
                const $el = $(el);
                if ($el.is('main') || $el.is('section') || $el.hasClass('content') || $el.attr('id') === 'content') {
                    return false; 
                }
                if (!$el.is('script') && !$el.is('style') && !$el.is('link')) {
                    tempHeaderHtml += $.html($el);
                }
            });
            headerContentBody = tempHeaderHtml;
        }

        // C. Extrair conteúdo do <footer> (se existir)
        const $footer = $('footer').clone();
        if ($footer.length > 0) {
            footerContent = $.html($footer); 
            $('footer').remove(); 
        } else {
            const bodyChildren = $('body').children();
            let tempFooterHtml = '';
            for (let i = bodyChildren.length - 1; i >= 0; i--) {
                const $el = bodyChildren.eq(i);
                if ($el.is('script')) { 
                    $el.remove(); 
                    continue;
                }
                if ($el.is('style') || $el.is('link')) { 
                    $el.remove(); 
                    continue;
                }
                tempFooterHtml = $.html($el) + tempFooterHtml; 
                $el.remove(); 
                break; 
            }
            footerContent = tempFooterHtml;
        }

        // D. Extrair e Consolidar Estilos (inline e externos)
        $('style').each((i, el) => {
            allStyles += $(el).html() + '\n';
            $(el).remove(); 
        });

        const fetchedExternalStyles = [];
        const externalStylePromises = [];
        $('link[rel="stylesheet"]').each((i, el) => {
            const href = $(el).attr('href');
            if (href) {
                const absoluteHref = new URL(href, baseUrl).href;
                externalStylePromises.push(
                    axios.get(absoluteHref)
                        .then(res => res.data)
                        .catch(err => {
                            console.warn(`Não foi possível baixar CSS externo: ${absoluteHref} - ${err.message}`);
                            return ''; 
                        })
                );
            }
            $(el).remove(); 
        });
        const resolvedStyles = await Promise.all(externalStylePromises);
        allStyles += resolvedStyles.join('\n');


        // E. Extrair Scripts (serão enfileirados em functions.php)
        $('script').each((i, el) => {
            const src = $(el).attr('src');
            if (src) {
                const absoluteSrc = new URL(src, baseUrl).href;
                externalScriptUrls.push(absoluteSrc);
            } else {
            }
            $(el).remove(); 
        });


        // F. Extrair o Conteúdo Principal (Corpo)
        mainContent = $('body').html(); 
        
        // G. Reescrever caminhos de assets (imagens, links, etc.) dentro do mainContent
        const $mainContent = cheerio.load(mainContent);
        $mainContent('*').each((i, el) => {
            const element = $mainContent(el);
            if (element.is('img') && element.attr('src')) {
                let src = element.attr('src');
                if (src.startsWith('//')) src = 'http:' + src; 
                element.attr('src', new URL(src, baseUrl).href); 
            }
            if (element.is('a') && element.attr('href')) {
                let href = element.attr('href');
                if (href.startsWith('//')) href = 'http:' + href;
                element.attr('href', new URL(href, baseUrl).href);
            }
        });
        mainContent = $mainContent.html(); 

        // --- GERAÇÃO DOS ARQUIVOS DO TEMA WORDPRESS ---

        // 1. style.css
        const styleCssContent = `/*
Theme Name: ${themeName.split('-').map(word => word.charAt(0).toUpperCase() + word.slice(1)).join(' ')}
Theme URI: ${targetUrl}
Author: Dreamix AI
Author URI: #
Description: Tema WordPress gerado automaticamente a partir de ${targetUrl}
Version: 1.0.0
License: GPLv2 or later
License URI: http://www.gnu.org/licenses/gpl-2.0.html
Text Domain: ${themeName.replace(/-/g, '_')}
*/

${allStyles}

/* Estilos adicionais para garantir que o tema se pareça com o original */
body {
    margin: 0;
    padding: 0;
}
`;
        await fs.writeFile(path.join(tempDir, 'style.css'), styleCssContent);

        // 2. header.php
        const headerPhpContent = `<!DOCTYPE html>
<html <?php language_attributes(); ?>>
<head>
    <meta charset="<?php bloginfo( 'charset' ); ?>">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <?php wp_head(); ?>
    ${headerContentHead}
</head>
<body <?php body_class(); ?>>
${headerContentBody}
`;
        await fs.writeFile(path.join(tempDir, 'header.php'), headerPhpContent);

        // 3. footer.php
        const footerPhpContent = `
${footerContent}
<?php wp_footer(); ?>
</body>
</html>
`;
        await fs.writeFile(path.join(tempDir, 'footer.php'), footerPhpContent);

        // 4. index.php
        const indexPhpContent = `<?php get_header(); ?>

<div id="primary" class="content-area">
    <main id="main" class="site-main" role="main">
        ${mainContent}
    </main></div><?php get_footer(); ?>
`;
        await fs.writeFile(path.join(tempDir, 'index.php'), indexPhpContent);

        // 5. functions.php
        const functionsPhpContent = `<?php
/**
 * Funções do Tema ${themeName.split('-').map(word => word.charAt(0).toUpperCase() + word.slice(1)).join(' ')}
 */

if ( ! function_exists( '${themeName.replace(/-/g, '_')}_setup' ) ) :
    function ${themeName.replace(/-/g, '_')}_setup() {
        // Suporte para título dinâmico
        add_theme_support( 'title-tag' );

        // Adiciona suporte para RSS feeds nos posts e comentários.
        add_theme_support( 'automatic-feed-links' );

        // Habilita o suporte a miniaturas em posts e páginas.
        add_theme_support( 'post-thumbnails' );

        // Registra menus de navegação (opcional, mas bom ter)
        register_nav_menus( array(
            'primary' => esc_html__( 'Primary Menu', '${themeName.replace(/-/g, '_')}' ),
        ) );

        // Adiciona suporte para HTML5 para formulários de pesquisa, comentários, galeria e legendas.
        add_theme_support( 'html5', array(
            'search-form',
            'comment-form',
            'comment-list',
            'gallery',
            'caption',
        ) );
    }
endif;
add_action( 'after_setup_theme', '${themeName.replace(/-/g, '_')}_setup' );

/**
 * Enfileira scripts e estilos.
 */
function ${themeName.replace(/-/g, '_')}_scripts() {
    // Enfileira o style.css principal do tema
    wp_enqueue_style( '${themeName.replace(/-/g, '_')}-style', get_stylesheet_uri() );

    // Enfileira scripts JavaScript externos que foram encontrados na página original
    <?php
    // Node.js insere o array JS como uma string JSON aqui. PHP então decodifica.
    $external_script_urls = json_decode('${JSON.stringify(externalScriptUrls)}', true); 
    if (!empty($external_script_urls)) {
        foreach ($external_script_urls as $script_url) {
            wp_enqueue_script(
                // Usa concatenação PHP para o nome único do script
                '${themeName.replace(/-/g, '_')}_script_' . md5($script_url), 
                // Sanitiza a URL com função PHP para segurança
                esc_url($script_url), 
                array(), // Dependências, pode ser 'jquery' se necessário
                null, // Versão do script (null para usar versão do arquivo)
                true // Carregar no footer
            );
        }
    }
    ?>

    // Exemplo de como enfileirar jQuery do WordPress, se o site original depender dele
    // wp_enqueue_script( 'jquery' );
}
add_action( 'wp_enqueue_scripts', '${themeName.replace(/-/g, '_')}_scripts' );

// Desabilitar o editor de blocos (Gutenberg) para manter o layout original (opcional)
// function ${themeName.replace(/-/g, '_')}_disable_gutenberg() {
//     add_filter( 'use_block_editor_for_post', '__return_false' );
// }
// add_action( 'admin_init', '${themeName.replace(/-/g, '_')}_disable_gutenberg', 20 );

`;
        await fs.writeFile(path.join(tempDir, 'functions.php'), functionsPhpContent);

        // --- COMPACTAR E ENVIAR O TEMA ---

        const tempZipDir = path.join(__dirname, 'temp_wp_zips'); // Pasta para os ZIPs temporários
        await fs.ensureDir(tempZipDir); // Garante que a pasta exista
        zipFilePath = path.join(tempDir, `${themeName}.zip`);

        const output = fs.createWriteStream(zipFilePath);
        const archive = archiver('zip', {
            zlib: { level: 9 } // Nível de compressão
        });

        output.on('close', async () => {
            console.log(`Tema ZIP gerado: ${archive.pointer()} bytes totais. Caminho: ${zipFilePath}`);
            // Enviar o ZIP de volta para o cliente
            res.download(zipFilePath, async (err) => {
                if (err) {
                    console.error('Erro ao enviar o arquivo ZIP:', err);
                }
                // Limpar arquivos temporários após o envio (ou após erro no envio)
                if (tempDir) {
                    await fs.remove(tempDir).catch(e => console.error(`Erro ao remover ${tempDir}:`, e));
                }
                if (zipFilePath) {
                    await fs.remove(zipFilePath).catch(e => console.error(`Erro ao remover zip file após falha:`, e));
                }
            });
        });

        archive.on('warning', (err) => {
            if (err.code === 'ENOENT') {
                console.warn('Arquivador avisou:', err);
            } else {
                console.error('Erro no arquivador:', err);
                throw err;
            }
        });

        archive.on('error', (err) => {
            console.error('Erro fatal no arquivador:', err);
            throw err;
        });

        archive.pipe(output);
        // Adiciona a pasta do tema (com todo o seu conteúdo) ao ZIP, com o nome do tema como a raiz dentro do ZIP
        archive.directory(tempDir, themeName); 
        await archive.finalize();

        // Registra a geração do tema no histórico (apenas se tudo correu bem)
        db.run(`INSERT INTO clone_history (user_id, original_url) VALUES (?, ?)`, [req.session.user.id, `[WP Theme] ${targetUrl}`]);

    } catch (error) {
        console.error('Erro completo ao gerar tema WordPress:', error);
        res.status(500).json({ error: `Erro interno ao gerar tema WordPress: ${error.message}` });
        // Limpar pasta temporária em caso de erro também
        if (tempDir) {
            await fs.remove(tempDir).catch(e => console.error(`Erro ao remover ${tempDir}:`, e));
        }
        if (zipFilePath) {
            await fs.remove(zipFilePath).catch(e => console.error(`Erro ao remover zip file após falha:`, e));
        }
    }
});

// Garante que as pastas temporárias existam ao iniciar o servidor
fs.ensureDirSync(path.join(__dirname, 'temp_wp_themes'));
fs.ensureDirSync(path.join(__dirname, 'temp_wp_zips'));

app.listen(PORT, () => console.log(`🚀 Servidor da Aplicação Dreamix a correr em http://localhost:${PORT}`));