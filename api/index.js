const express = require('express');
const path = require('path');
const fs = require('fs');
const cors = require('cors');
const admin = require('firebase-admin');
const crypto = require('crypto');
const axios = require('axios');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3001; // Usamos uma porta diferente para a API

// --- CONFIGURAÇÃO E MIDDLEWARES ---
app.use(cors()); // Permite que o nosso futuro frontend se comunique com esta API
app.use(express.json());

// --- INICIALIZAÇÃO DO FIREBASE ADMIN ---
try {
    // A inicialização continua a mesma, lendo a variável de ambiente
    const serviceAccount = JSON.parse(process.env.FIREBASE_SERVICE_ACCOUNT_KEY);
    admin.initializeApp({
        credential: admin.credential.cert(serviceAccount),
    });
    console.log('[API] Firebase Admin SDK inicializado com sucesso.');
} catch (e) {
    console.error('[API ERROR] Falha ao inicializar Firebase Admin SDK.', e);
    process.exit(1);
}
const db = admin.firestore();

// --- MIDDLEWARES DE SEGURANÇA ---
const requireAuth = async (req, res, next) => {
    const idToken = req.headers.authorization?.split('Bearer ')[1];
    if (!idToken) return res.status(401).json({ error: 'Token de autenticação ausente.' });
    try {
        req.user = await admin.auth().verifyIdToken(idToken);
        next();
    } catch (error) {
        return res.status(403).json({ error: 'Falha na autenticação.' });
    }
};

const requireAdmin = (req, res, next) => {
    if (req.user.uid !== process.env.ADMIN_UID) {
        return res.status(403).json({ error: 'Acesso negado. Apenas administradores.' });
    }
    next();
};

const requirePremium = async (req, res, next) => {
    try {
        const userDoc = await db.collection('users').doc(req.user.uid).get();
        if (userDoc.exists && userDoc.data().subscriptionTier === 'premium') {
            const expiration = userDoc.data().subscriptionExpiresAt;
            if (!expiration || expiration.toDate() > new Date()) {
                return next();
            }
        }
        return res.status(403).json({ error: 'Recurso exclusivo para assinantes premium.' });
    } catch (error) {
        return res.status(500).json({ error: 'Erro ao verificar a assinatura.' });
    }
};

// ===========================================
// ** PONTO DE ENTRADA DA API **
// ===========================================
app.get('/api', (req, res) => {
    res.json({ message: 'Bem-vindo à API do MULTCONTROL!' });
});

// --- ROTAS DE ADMINISTRAÇÃO ---
app.get('/api/admin/users', requireAuth, requireAdmin, async (req, res) => {
    // ... (Sua lógica original aqui)
});
app.post('/api/admin/grant-premium', requireAuth, requireAdmin, async (req, res) => {
    // ... (Sua lógica original aqui)
});

// --- API DE CONFIGURAÇÕES DO USUÁRIO ---
app.get('/api/user/settings', requireAuth, async (req, res) => {
    // ... (Sua lógica original aqui)
});
app.post('/api/user/settings', requireAuth, requirePremium, async (req, res) => {
    // ... (Sua lógica original aqui)
});

// --- APIs PARA GERENCIADOR DE PERFIS E ATRIBUIÇÕES ---
app.get('/api/build-orders', requireAuth, async (req, res) => {
    // ... (Sua lógica original aqui)
});
app.post('/api/build-orders', requireAuth, async (req, res) => {
    // ... (Sua lógica original aqui)
});
app.delete('/api/build-orders/:id', requireAuth, async (req, res) => {
    // ... (Sua lógica original aqui)
});
app.get('/api/nicknames', requireAuth, async (req, res) => {
    // ... (Sua lógica original aqui)
});
app.post('/api/nicknames/register', requireAuth, async (req, res) => {
    // ... (Sua lógica original aqui)
});
app.get('/api/assignments', requireAuth, async (req, res) => {
    // ... (Sua lógica original aqui)
});
app.post('/api/assignments', requireAuth, async (req, res) => {
    // ... (Sua lógica original aqui)
});
app.get('/api/active-profile-id/:nickname', requireAuth, async (req, res) => {
    // ... (Sua lógica original aqui)
});
app.get('/api/build-orders/:id', requireAuth, async (req, res) => {
    // ... (Sua lógica original aqui)
});

// --- API DE ALERTA ---
app.post('/api/alert', requireAuth, async (req, res) => {
    // ... (Sua lógica original aqui, mas agora sem a parte do WhatsApp Worker)
});

// --- API DE AUTENTICAÇÃO PARA SCRIPTS ---
app.post('/api/get_fresh_id_token', async (req, res) => {
    // ... (Sua lógica original aqui)
});

// --- INICIAR SERVIDOR DA API ---
app.listen(PORT, () => {
    console.log(`[API] Servidor da API rodando na porta ${PORT}`);
});

// Exporta o app para a Vercel
module.exports = app;
