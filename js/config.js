const SUPABASE_CONFIG = {
    EDGE_URL:     'https://rwvmzncnxvxdafonabfh.supabase.co/functions/v1/api',
    SUPABASE_URL: 'https://rwvmzncnxvxdafonabfh.supabase.co'
    // ✅ ANON_KEY REMOVED FOR SECURITY - All API calls now proxied through Edge Function
};

const CONFIG = {
    VERSION: '20260224000000',
    ROLES: { ADMIN:'admin', MANAGER:'manager', STUDIO:'studio', COMEDIAN:'comedian', CLIENT:'client' },
    ROLE_LABELS: { admin:'Administrateur', manager:'Manager', studio:'Équipe Studio', comedian:'Comédien', client:'Client' },
    CLASSEMENT: { INTERNE:'interne', EXTERNE:'externe' },
    LIMITS: { MAX_FILE_SIZE:5*1024*1024, MAX_LOGS:100, MAX_CLIENT_SELECTION:3, PASSWORD_MIN_LENGTH:12 },
    LOG_TYPES: {
        CREATION:'creation', MODIFICATION:'modification', ACTIVATION:'activation',
        DESACTIVATION:'desactivation', SUPPRESSION:'suppression', PASSWORD_RESET:'reinitialisation_mdp',
        EMAIL_SENT:'envoi_email', ABSENCE:'gestion_absence', LOGIN:'connexion', LOGOUT:'deconnexion'
    },
    DEFAULT_EMAIL_TEMPLATES: {
        identifiants: {
            id:'identifiants', name:'Envoi identifiants',
            subject:'Vos identifiants de connexion — {{studio}}',
            body:'Bonjour {{prenom}},\n\nBienvenue ! Voici vos identifiants :\n\nIdentifiant : {{username}}\nMot de passe : {{password}}\n\nLien : {{lien}}\n\nCordialement,\n{{studio}}'
        },
        reset_password: {
            id:'reset_password', name:'Réinitialisation mot de passe',
            subject:'Votre nouveau mot de passe — {{studio}}',
            body:'Bonjour {{prenom}},\n\nVotre mot de passe a été réinitialisé.\n\nNouveau mot de passe : {{password}}\n\nLien : {{lien}}\n\nCordialement,\n{{studio}}'
        }
    }
};

const Utils = {
    formatDate(d) {
        if (!d) return '';
        return new Date(d).toLocaleDateString('fr-FR',{day:'2-digit',month:'2-digit',year:'numeric'});
    },
    formatDateTime(d) { if (!d) return ''; return new Date(d).toLocaleString('fr-FR'); },
    capitalize(s) { if (!s) return ''; return s.charAt(0).toUpperCase()+s.slice(1).toLowerCase(); },
    generateId() { return Date.now()+Math.floor(Math.random()*1000); },
    generateSecurePassword(length=12) {
        const upper  = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
        const lower  = 'abcdefghijklmnopqrstuvwxyz';
        const digits = '0123456789';
        const special= '!@#$%&*';
        const all    = upper + lower + digits + special;
        const rand   = (charset) => charset[crypto.getRandomValues(new Uint32Array(1))[0] % charset.length];
        let chars = [rand(upper), rand(lower), rand(digits), rand(special)];
        const extra = new Uint32Array(length - 4);
        crypto.getRandomValues(extra);
        for (let i = 0; i < length - 4; i++) chars.push(all[extra[i] % all.length]);
        const shuffleArr = new Uint32Array(chars.length);
        crypto.getRandomValues(shuffleArr);
        for (let i = chars.length - 1; i > 0; i--) {
            const j = shuffleArr[i] % (i + 1);
            [chars[i], chars[j]] = [chars[j], chars[i]];
        }
        return chars.join('');
    },
    simulateEmail(to,subject,body) {
        // ✅ SECURITY: Validate email before opening mailto
        if (!this.isValidEmail(to)) {
            alert('Email invalide');
            return;
        }
        const a=document.createElement('a');
        a.href='mailto:'+encodeURIComponent(to)+'?subject='+encodeURIComponent(subject)+'&body='+encodeURIComponent(body);
        a.style.display='none'; document.body.appendChild(a); a.click();
        setTimeout(()=>document.body.removeChild(a),200);
    },
    replaceEmailVariables(tpl,vars) {
        let r=tpl;
        for(const[k,v] of Object.entries(vars)) {
            // ✅ SECURITY: Escape HTML before injecting variables
            const safeValue = this.escapeHtml(String(v || ''));
            r=r.replace(new RegExp(`{{${k}}}`,'g'),safeValue);
        }
        return r;
    },
    // ✅ SECURITY: Enhanced escapeHtml to prevent XSS
    escapeHtml(str) {
        if (str == null) return '';
        const map = {
            '&': '&amp;',
            '<': '&lt;',
            '>': '&gt;',
            '"': '&quot;',
            "'": '&#039;',
            '/': '&#x2F;'
        };
        return String(str).replace(/[&<>"'\/]/g, (s) => map[s]);
    },
    
    // ✅ SECURITY: NEW - Validate email format
    isValidEmail(email) {
        const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        return emailRegex.test(email);
    },
    
    // ✅ SECURITY: NEW - Sanitize URLs
    sanitizeUrl(url) {
        if (!url) return '';
        try {
            const u = new URL(url);
            if (!['http:', 'https:', 'mailto:'].includes(u.protocol)) {
                return '';
            }
            return url;
        } catch {
            if (url.startsWith('/') || url.startsWith('./') || url.startsWith('../')) {
                return url;
            }
            return '';
        }
    },
    
    // ✅ SECURITY: NEW - Validate JSON
    isValidJSON(str) {
        try {
            JSON.parse(str);
            return true;
        } catch {
            return false;
        }
    }
};

function addLog(username,role,action) {
    // ✅ SECURITY: Escape log entries
    const safeUsername = Utils.escapeHtml(username || 'système');
    const safeRole = Utils.escapeHtml(role || '');
    const safeAction = Utils.escapeHtml(action || '');
    
    SupabaseDB.insertLog({
        timestamp:new Date().toISOString(),
        username:safeUsername,
        role:safeRole,
        action:safeAction
    }).catch(()=>{});
}
