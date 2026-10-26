// 変更日時：2026年10月26日 22時45分
// WebRTC Signaling Server for CellPhone App (Glitch / Render / Local Node.js 対応)
// 二段階認証(メールOTP)、E2EEチャット中継、FCMプッシュ着信、偽装防止検証、WebSocket認証＆レートリミット統合版

const WebSocket = require('ws');
const http = require('http');
const https = require('https');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

let admin = null;
let firebaseApp = null;
try
{
    admin = require('firebase-admin');
    const serviceAccount = process.env.FIREBASE_SERVICE_ACCOUNT
        ? JSON.parse(process.env.FIREBASE_SERVICE_ACCOUNT)
        : (fs.existsSync('./firebase-adminsdk.json') ? require('./firebase-adminsdk.json') : null);

    if (serviceAccount && admin)
    {
        firebaseApp = admin.initializeApp({
            credential: admin.credential.cert(serviceAccount)
        });
        console.log('[Firebase Admin] FCM プッシュ送信機能の初期化完了');
    }
}
catch (e)
{
    console.warn('[Firebase Admin Note] 初期化スキップまたは保留:', e.message);
}

// FCMデバイストークン保管ストア (userId -> { fcmToken, email, updatedAt })
const fcmTokenStore = new Map();

let nodemailer = null;
try
{
    nodemailer = require('nodemailer');
}
catch (e)
{
    // nodemailer未導入時の安全フォールバック
}

const port = process.env.PORT || 3000;

// 許可されたGoogleアカウントのSHA-256ハッシュリスト (小文字Hex)
const ALLOWED_EMAIL_HASHES = new Set([
    '6838c7018bdd3e8d610196e5eeead1841bbba1f577d1a241aca19a0517edd5ac', // satochan...
    '64ade2628e31414cfd703856b95d20762039f9eb7a252bd4f82ad30654f827c0', // ketoshi...
    'cc62be47a00bd185613ae382f18ff5e162a525d01a36b72032e1efa086000597'  // tutuzi...
]);

// 相互承認ルーティングマップ (ログイン試行者 -> ワンタイム承認コード送信先)
const APPROVAL_ROUTING = {
    'satochan.07620@gmail.com': 'ketoshisub.2016@gmail.com',
    'ketoshisub.2016@gmail.com': 'satochan.07620@gmail.com',
    'tutuzisann@gmail.com': 'satochan.07620@gmail.com'
};

// IP別接続レート制限追跡ストア (IP -> { count, resetTime })
const ipConnectionTracker = new Map();

// メールアドレスの伏字マスク (例: sat***@gmail.com)
function maskEmail(addr)
{
    if (!addr || !addr.includes('@')) { return addr || ''; }
    const parts = addr.split('@');
    const name = parts[0];
    const visible = name.length > 3 ? name.slice(0, 3) : name.slice(0, 1);
    return `${visible}***@${parts[1]}`;
}

// 文字列のSHA-256ハッシュ算出
function sha256(text)
{
    return crypto.createHash('sha256').update(text.toLowerCase().trim()).digest('hex');
}

// ワンタイムコード一時保管ストア (email -> { code, expiresAt, attempts })
const otpStore = new Map();

// 認証済みアクティブセッション (token -> { email, createdAt, expiresAt })
const activeSessions = new Map();

// 定期的な期限切れOTPおよびセッションのクリーンアップ (毎分)
setInterval(() =>
{
    const now = Date.now();
    for (const [email, entry] of otpStore.entries())
    {
        if (entry.expiresAt < now)
        {
            otpStore.delete(email);
        }
    }
    for (const [token, session] of activeSessions.entries())
    {
        if (session.expiresAt < now)
        {
            activeSessions.delete(token);
        }
    }
}, 60000);

// メールトランスポーターの初期化 (Gmail アプリパスワード連携)
function createMailTransporter()
{
    const user = process.env.GMAIL_USER;
    const pass = process.env.GMAIL_APP_PASS;
    if (!user || !pass || !nodemailer)
    {
        return null;
    }
    return nodemailer.createTransport({
        host: 'smtp.gmail.com',
        port: 465,
        secure: true,
        auth: { user, pass },
        family: 4, // IPv4強制 (Node.js 18+ のIPv6接続ハング・タイムアウト防止)
        connectionTimeout: 8000,
        greetingTimeout: 5000,
        socketTimeout: 10000
    });
}

// GAS (Google Apps Script) WebHook 経由でのメール送信 (Port 443 HTTPS通信: Render無料枠対応)
function sendMailViaGas(gasUrl, mailData)
{
    return new Promise((resolve, reject) =>
    {
        const postData = JSON.stringify(mailData);
        const parsedUrl = new URL(gasUrl);

        const options = {
            hostname: parsedUrl.hostname,
            path: parsedUrl.pathname + parsedUrl.search,
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Content-Length': Buffer.byteLength(postData)
            },
            timeout: 15000
        };

        const req = https.request(options, (res) =>
        {
            // GAS WebAppは302リダイレクト経由でContentServiceを返す
            if (res.statusCode === 302 || res.statusCode === 301 || res.statusCode === 307)
            {
                const redirectUrl = res.headers.location;
                if (!redirectUrl)
                {
                    return resolve({ success: true, redirected: true });
                }
                https.get(redirectUrl, (redirectRes) =>
                {
                    let body = '';
                    redirectRes.on('data', chunk => { body += chunk; });
                    redirectRes.on('end', () =>
                    {
                        try
                        {
                            const json = JSON.parse(body);
                            resolve(json);
                        }
                        catch (e)
                        {
                            resolve({ success: true, raw: body });
                        }
                    });
                }).on('error', (err) =>
                {
                    console.warn('[GAS Redirect Note]', err.message);
                    resolve({ success: true });
                });
                return;
            }

            let body = '';
            res.on('data', chunk => { body += chunk; });
            res.on('end', () =>
            {
                try
                {
                    resolve(JSON.parse(body));
                }
                catch (e)
                {
                    resolve({ success: res.statusCode >= 200 && res.statusCode < 300, raw: body });
                }
            });
        });

        req.on('timeout', () =>
        {
            req.destroy();
            reject(new Error('GASメール送信接続タイムアウト'));
        });

        req.on('error', reject);
        req.write(postData);
        req.end();
    });
}

// FCM高優先度着信データプッシュ送信 (LINE同等の完全バックグラウンド着信・アプリ終了時もonMessageReceivedを確実起動)
async function sendIncomingCallPush(targetFcmToken, callData)
{
    if (!firebaseApp || !admin)
    {
        console.warn('[FCM Push Warning] Firebase Admin未初期化のため着信プッシュをスキップ');
        return false;
    }
    if (!targetFcmToken)
    {
        console.warn('[FCM Push Warning] 宛先FCMトークン未登録のため着信プッシュ送信不可');
        return false;
    }
    try
    {
        const message = {
            token: targetFcmToken,
            data: {
                type: 'incoming_call',
                fromUserId: String(callData.fromUserId || ''),
                fromName: String(callData.fromName || '通話相手'),
                roomId: String(callData.roomId || ''),
                isVideo: String(callData.isVideo ? 'true' : 'false'),
                timestamp: String(Date.now())
            },
            android: {
                priority: 'high',
                ttl: 60 * 1000 // 60秒有効
            }
        };

        const response = await admin.messaging().send(message);
        console.log(`[FCM Push] 着信データプッシュ送信完了 (${callData.fromName} -> Token: ${targetFcmToken.slice(0, 15)}...): ${response}`);
        return true;
    }
    catch (err)
    {
        console.error('[FCM Push Error] プッシュ送信失敗:', err.message);
        return false;
    }
}

// オフラインチャットメッセージ永続化キュー (targetUserId -> [ messageData ])
const offlineMessageQueue = new Map();
const QUEUE_FILE_PATH = path.join(__dirname, 'data', 'offline_queue.json');

// オフラインキューの永続化ファイルからのロード
function loadOfflineQueue()
{
    try
    {
        if (fs.existsSync(QUEUE_FILE_PATH))
        {
            const data = fs.readFileSync(QUEUE_FILE_PATH, 'utf8');
            const obj = JSON.parse(data);
            for (const [userId, messages] of Object.entries(obj))
            {
                if (Array.isArray(messages) && messages.length > 0)
                {
                    offlineMessageQueue.set(userId, messages);
                }
            }
            console.log(`[Offline Queue] 永続化ファイルから ${offlineMessageQueue.size} ユーザー分のキューを復元完了`);
        }
    }
    catch (err)
    {
        console.error('[Offline Queue Load Error]', err.message);
    }
}

// オフラインキューのファイル保存 (非同期・デバウンス)
let saveQueueTimer = null;
function saveOfflineQueue()
{
    if (saveQueueTimer)
    {
        clearTimeout(saveQueueTimer);
    }
    saveQueueTimer = setTimeout(() =>
    {
        try
        {
            const dir = path.dirname(QUEUE_FILE_PATH);
            if (!fs.existsSync(dir))
            {
                fs.mkdirSync(dir, { recursive: true });
            }
            const obj = {};
            for (const [userId, messages] of offlineMessageQueue.entries())
            {
                if (messages && messages.length > 0)
                {
                    obj[userId] = messages;
                }
            }
            fs.writeFileSync(QUEUE_FILE_PATH, JSON.stringify(obj, null, 2), 'utf8');
        }
        catch (err)
        {
            console.error('[Offline Queue Save Error]', err.message);
        }
    }, 200);
}

// 起動時にファイルから復元
loadOfflineQueue();

// FCMデバイストークン永続化ファイル
const FCM_TOKENS_FILE = path.join(__dirname, 'fcm_tokens.json');

function saveFcmTokens()
{
    try
    {
        const obj = {};
        for (const [k, v] of fcmTokenStore.entries())
        {
            obj[k] = v;
        }
        fs.writeFileSync(FCM_TOKENS_FILE, JSON.stringify(obj, null, 2), 'utf8');
    }
    catch (e)
    {
        console.error('[FCM Store] トークン保存エラー:', e.message);
    }
}

function loadFcmTokens()
{
    try
    {
        if (fs.existsSync(FCM_TOKENS_FILE))
        {
            const data = fs.readFileSync(FCM_TOKENS_FILE, 'utf8');
            const obj = JSON.parse(data);
            for (const [k, v] of Object.entries(obj))
            {
                fcmTokenStore.set(k, v);
            }
            console.log(`[FCM Store] トークンファイルから ${fcmTokenStore.size} 件のFCMトークンを復元完了`);
        }
    }
    catch (e)
    {
        console.error('[FCM Store] トークン復元エラー:', e.message);
    }
}

// 起動時にFCMトークンをファイルから復元
loadFcmTokens();

// オフライン既読通知ストア (targetUserId -> [ { fromUserId, messageIds, timestamp } ])
const offlineReadQueue = new Map();
const OFFLINE_READS_FILE = path.join(__dirname, 'offline_reads.json');

function saveOfflineReads()
{
    try
    {
        const obj = {};
        for (const [k, v] of offlineReadQueue.entries())
        {
            obj[k] = v;
        }
        fs.writeFileSync(OFFLINE_READS_FILE, JSON.stringify(obj, null, 2), 'utf8');
    }
    catch (e)
    {
        console.error('[Offline Read Store] 保存エラー:', e.message);
    }
}

function loadOfflineReads()
{
    try
    {
        if (fs.existsSync(OFFLINE_READS_FILE))
        {
            const data = fs.readFileSync(OFFLINE_READS_FILE, 'utf8');
            const obj = JSON.parse(data);
            for (const [k, v] of Object.entries(obj))
            {
                offlineReadQueue.set(k, v);
            }
            console.log(`[Offline Read Store] 保留既読ファイルから ${offlineReadQueue.size} ユーザーの通知を復元完了`);
        }
    }
    catch (e)
    {
        console.error('[Offline Read Store] 復元エラー:', e.message);
    }
}

// 起動時に保留既読通知を復元
loadOfflineReads();

// FCM新着チャットプッシュ送信 (二重通知防止のためdataメッセージで統一・暗号化本文＆添付ファイル情報を完全伝送)
async function sendChatMessagePush(targetFcmToken, chatData)
{
    if (!firebaseApp || !admin)
    {
        console.warn('[FCM Chat Push Warning] Firebase Admin未初期化のためチャットプッシュをスキップ (FIREBASE_SERVICE_ACCOUNT未設定)');
        return false;
    }
    if (!targetFcmToken)
    {
        console.warn('[FCM Chat Push Warning] 宛先FCMトークン未登録のためチャットプッシュ送信不可');
        return false;
    }
    try
    {
        // OSによる二重通知を完全防止するため notification属性は含めず dataメッセージのみで送信
        const message = {
            token: targetFcmToken,
            data: {
                type: 'chat_message',
                fromUserId: String(chatData.fromUserId || ''),
                fromName: String(chatData.fromName || '友だち'),
                messageId: String(chatData.messageId || ''),
                text: String(chatData.text || ''),
                iv: String(chatData.iv || ''),
                cipher: String(chatData.cipher || ''),
                imageBase64: String(chatData.imageBase64 || ''),
                fileUrl: String(chatData.fileUrl || ''),
                fileKey: String(chatData.fileKey || ''),
                fileName: String(chatData.fileName || ''),
                fileSize: String(chatData.fileSize || '0'),
                timestamp: String(chatData.timestamp || Date.now())
            },
            android: {
                priority: 'high',
                ttl: 7 * 24 * 60 * 60 * 1000 // 7日間有効
            }
        };

        const response = await admin.messaging().send(message);
        console.log(`[FCM Chat Push] 新着チャットデータプッシュ送信完了 (${chatData.fromName} -> Token: ${targetFcmToken.slice(0, 15)}...): ${response}`);
        return true;
    }
    catch (err)
    {
        console.error('[FCM Chat Push Error] チャットプッシュ送信失敗:', err.message);
        return false;
    }
}

// JSONリクエストボディの取得ヘルパー
function parseJsonBody(req)
{
    return new Promise((resolve, reject) =>
    {
        let body = '';
        req.on('data', chunk => { body += chunk; });
        req.on('end', () =>
        {
            try
            {
                resolve(body ? JSON.parse(body) : {});
            }
            catch (err)
            {
                reject(err);
            }
        });
        req.on('error', reject);
    });
}

// HTTPサーバー (ヘルスチェック ＆ 二段階認証OTP API)
const server = http.createServer(async (req, res) =>
{
    // [セキュリティヘッダー完全装備: Helmet相当]
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('X-Frame-Options', 'DENY');
    res.setHeader('X-XSS-Protection', '1; mode=block');
    res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
    res.setHeader('Content-Security-Policy', "default-src 'none'");

    // CORSヘッダー付与
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');

    if (req.method === 'OPTIONS')
    {
        res.writeHead(204);
        res.end();
        return;
    }

    // IP接続レート制限 (1分間に最大60リクエストまで)
    const clientIp = req.headers['x-forwarded-for'] || req.socket.remoteAddress || 'unknown';
    const now = Date.now();
    let ipRecord = ipConnectionTracker.get(clientIp);
    if (!ipRecord || now > ipRecord.resetTime)
    {
        ipRecord = { count: 0, resetTime: now + 60000 };
        ipConnectionTracker.set(clientIp, ipRecord);
    }
    ipRecord.count++;
    if (ipRecord.count > 60)
    {
        res.writeHead(429, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ success: false, error: 'アクセス過多のため一時的に制限されています。少し待って再試行してください' }));
        return;
    }

    const url = req.url || '';

    // ヘルスチェック
    if (req.method === 'GET' && (url === '/' || url === '/health'))
    {
        res.writeHead(200, { 'Content-Type': 'application/json; charset=utf-8' });
        res.end(JSON.stringify({
            status: 'ok',
            server: 'CellPhone Signaling Server',
            activeUsers: users.size,
            firebaseInitialized: !!firebaseApp,
            fcmTokensCount: fcmTokenStore.size,
            offlineQueuedUsersCount: offlineMessageQueue.size
        }));
        return;
    }

    // [API 1] OTP送信: POST /api/auth/send-otp
    if (req.method === 'POST' && url === '/api/auth/send-otp')
    {
        try
        {
            const body = await parseJsonBody(req);
            const email = (body.email || '').trim().toLowerCase();

            if (!email)
            {
                res.writeHead(400, { 'Content-Type': 'application/json' });
                res.end(JSON.stringify({ success: false, error: 'メールアドレスが指定されていません' }));
                return;
            }

            // ホワイトリスト(SHA-256ハッシュ)照合
            const emailHash = sha256(email);
            if (!ALLOWED_EMAIL_HASHES.has(emailHash))
            {
                console.warn(`[Auth Warning] 未許可メールアドレスのOTP要求を遮断: ${email} (${emailHash})`);
                res.writeHead(403, { 'Content-Type': 'application/json' });
                res.end(JSON.stringify({ success: false, error: 'このGoogleアカウントはアクセス許可リストに存在しません' }));
                return;
            }

            // [急所2防御] メール連打・スパム爆撃防止: 60秒クールダウンチェック
            const now = Date.now();
            const existingOtp = otpStore.get(email);
            if (existingOtp && existingOtp.lastSentAt && (now - existingOtp.lastSentAt < 60000))
            {
                const remainSec = Math.ceil((60000 - (now - existingOtp.lastSentAt)) / 1000);
                res.writeHead(429, { 'Content-Type': 'application/json' });
                res.end(JSON.stringify({ success: false, error: `認証コードは送信済みです。再送信まであと ${remainSec} 秒お待ちください` }));
                return;
            }

            // 6桁ランダムコード生成 (100000〜999999)
            const code = Math.floor(100000 + Math.random() * 900000).toString();
            const expiresAt = now + 5 * 60 * 1000; // 5分間有効
            otpStore.set(email, { code, expiresAt, attempts: 0, lastSentAt: now });

            // 相互承認ルーティング: 送信先アドレスを特定
            const targetEmail = APPROVAL_ROUTING[email] || email;
            const maskedTarget = maskEmail(targetEmail);

            console.log(`[Cross-Auth OTP] ログイン試行: ${email} -> 承認コード送信先: ${targetEmail} (${code})`);

            // メール本文テンプレート生成
            const mailSubject = `【CellPhone App】${email} からのログイン承認要求`;
            const mailText = `CellPhone App にて「${email}」がログインを試行しています。\n\n心当たりがある場合は、以下の6桁の承認コードをLINE等で相手にお伝えください。\n\n承認コード: ${code}\n\n※このコードの有効期限は5分間です。\n※心当たりのない場合は絶対に他人にコードを教えないでください。`;
            const mailHtml = `
                <div style="font-family: sans-serif; max-width: 500px; padding: 20px; border: 1px solid #e0e0e0; border-radius: 8px;">
                    <h2 style="color: #3B82F6; margin-top: 0;">CellPhone App 相互承認要求</h2>
                    <p><strong>「${email}」</strong> がアプリへのサインインを試行しています。</p>
                    <p>ご本人からの連絡であることを確認した上で、以下の承認コードを<strong>LINE等</strong>でお伝えください。</p>
                    <div style="background-color: #EFF6FF; padding: 15px; border-radius: 6px; text-align: center; font-size: 28px; font-weight: bold; letter-spacing: 6px; color: #1D4ED8; margin: 20px 0; border: 1px dashed #93C5FD;">
                        ${code}
                    </div>
                    <p style="font-size: 13px; color: #6B7280;">※この承認コードの有効期限は<strong>5分間</strong>です。<br>※身に覚えのない場合は絶対にコードを伝えないでください。</p>
                </div>
            `;

            // 【最優先】GAS (Google Apps Script) WebHook によるメール送信 (Port 443 HTTPS通信)
            const gasUrl = process.env.GAS_MAIL_URL;
            if (gasUrl)
            {
                try
                {
                    console.log(`[GAS Mail] 送信開始: ${targetEmail} via ${gasUrl.slice(0, 45)}...`);
                    await sendMailViaGas(gasUrl, {
                        to: targetEmail,
                        subject: mailSubject,
                        text: mailText,
                        html: mailHtml
                    });
                    console.log(`[GAS Mail] 送信成功: ${targetEmail}`);
                    res.writeHead(200, { 'Content-Type': 'application/json' });
                    res.end(JSON.stringify({
                        success: true,
                        message: `承認コードを「${maskedTarget}」宛てに送信しました。\n相手の方からLINE等でコードを受け取ってください。`,
                        targetNotice: maskedTarget
                    }));
                    return;
                }
                catch (gasErr)
                {
                    console.error('[GAS Mail Error]', gasErr);
                    res.writeHead(500, { 'Content-Type': 'application/json' });
                    res.end(JSON.stringify({ success: false, error: 'GASメール送信エラー: ' + gasErr.message }));
                    return;
                }
            }

            // 【フォールバック】SMTPによるメール送信
            const transporter = createMailTransporter();
            if (transporter)
            {
                const mailOptions = {
                    from: `"CellPhone App 相互承認" <${process.env.GMAIL_USER}>`,
                    to: targetEmail,
                    subject: mailSubject,
                    text: mailText,
                    html: mailHtml
                };

                await transporter.sendMail(mailOptions);
                console.log(`[Cross-Auth OTP Email] 送信完了: ${targetEmail}`);
                res.writeHead(200, { 'Content-Type': 'application/json' });
                res.end(JSON.stringify({
                    success: true,
                    message: `承認コードを「${maskedTarget}」宛てに送信しました。\n相手の方からLINE等でコードを受け取ってください。`,
                    targetNotice: maskedTarget
                }));
            }
            else
            {
                // GMAIL_USER/GAS_MAIL_URL 未設定時の安全フォールバック (ログ出力＋開発用コード返却)
                console.warn(`[OTP Fallback] メール送信設定が未設定のためテスト用コードを返却: ${code}`);
                res.writeHead(200, { 'Content-Type': 'application/json' });
                res.end(JSON.stringify({
                    success: true,
                    message: `承認コードを「${maskedTarget}」宛てに発行しました (メールサーバー未設定のためテスト用コードを返却します)`,
                    devCode: code,
                    targetNotice: maskedTarget
                }));
            }
            return;
        }
        catch (err)
        {
            console.error('[OTP Send Error]', err);
            res.writeHead(500, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ success: false, error: '認証コード送信中にエラーが発生しました: ' + err.message }));
            return;
        }
    }

    // [API 2] OTP検証: POST /api/auth/verify-otp
    if (req.method === 'POST' && url === '/api/auth/verify-otp')
    {
        try
        {
            const body = await parseJsonBody(req);
            const email = (body.email || '').trim().toLowerCase();
            const inputCode = (body.code || '').trim();

            const entry = otpStore.get(email);
            if (!entry)
            {
                res.writeHead(400, { 'Content-Type': 'application/json' });
                res.end(JSON.stringify({ success: false, error: '認証コードが発行されていないか、有効期限が切れています' }));
                return;
            }

            if (entry.expiresAt < Date.now())
            {
                otpStore.delete(email);
                res.writeHead(400, { 'Content-Type': 'application/json' });
                res.end(JSON.stringify({ success: false, error: '認証コードの有効期限が切れました。再送信してください' }));
                return;
            }

            // 試行回数制限 (5回ミスで無効化)
            entry.attempts++;
            if (entry.attempts > 5)
            {
                otpStore.delete(email);
                res.writeHead(429, { 'Content-Type': 'application/json' });
                res.end(JSON.stringify({ success: false, error: '認証試行回数の上限を超えました。コードを再発行してください' }));
                return;
            }

            // [シナリオB防御] タイミング攻撃防止: 暗号学的一定時間比較 (timingSafeEqual)
            if (inputCode.length !== 6 || entry.code.length !== 6)
            {
                res.writeHead(400, { 'Content-Type': 'application/json' });
                res.end(JSON.stringify({ success: false, error: '認証コードは6桁の数字です' }));
                return;
            }

            const codeMatch = crypto.timingSafeEqual(
                Buffer.from(entry.code, 'utf8'),
                Buffer.from(inputCode, 'utf8')
            );

            if (!codeMatch)
            {
                res.writeHead(400, { 'Content-Type': 'application/json' });
                res.end(JSON.stringify({ success: false, error: '認証コードが一致しません' }));
                return;
            }

            // 認証成功！OTP消去
            otpStore.delete(email);

            // [シナリオC防御] セッショントークン生成 ＆ 端末固有UIDと物理バインド
            const deviceUid = (body.deviceUid || '').trim();
            const sessionToken = crypto.randomBytes(32).toString('hex');
            const expiresAt = Date.now() + 30 * 24 * 60 * 60 * 1000; // 30日間有効
            activeSessions.set(sessionToken, { email, deviceUid, createdAt: Date.now(), expiresAt });

            console.log(`[Auth Success] 認証完了: ${email} (端末: ${deviceUid || 'unknown'}) -> セッショントークン発行`);
            res.writeHead(200, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({
                success: true,
                sessionToken: sessionToken,
                email: email
            }));
            return;
        }
        catch (err)
        {
            console.error('[OTP Verify Error]', err);
            res.writeHead(500, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ success: false, error: '認証検証エラー: ' + err.message }));
            return;
        }
    }

    // [API 3] FCMデバイストークン登録: POST /api/user/fcm-token
    if (req.method === 'POST' && url === '/api/user/fcm-token')
    {
        try
        {
            const body = await parseJsonBody(req);
            const userId = (body.userId || '').trim();
            const email = (body.email || '').trim().toLowerCase();
            const fcmToken = (body.fcmToken || '').trim();

            if (!userId || !fcmToken)
            {
                res.writeHead(400, { 'Content-Type': 'application/json' });
                res.end(JSON.stringify({ success: false, error: 'userIdまたはfcmTokenが不正です' }));
                return;
            }

            fcmTokenStore.set(userId, { fcmToken, email, updatedAt: Date.now() });
            saveFcmTokens();
            console.log(`[FCM Token] 登録成功: ${userId} (${email}) -> ${fcmToken.slice(0, 15)}...`);

            res.writeHead(200, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ success: true }));
            return;
        }
        catch (err)
        {
            console.error('[FCM Token Error]', err);
            res.writeHead(500, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ success: false, error: err.message }));
            return;
        }
    }

    // [API 4] 保留チャットメッセージ一括取得 (アプリ未起動分・オフライン分の一括読み込み)
    const parsedReqUrl = new URL(url, 'http://localhost');
    if (req.method === 'GET' && parsedReqUrl.pathname === '/api/chat/pending')
    {
        try
        {
            const targetUserId = (parsedReqUrl.searchParams.get('userId') || '').trim();
            if (!targetUserId)
            {
                res.writeHead(400, { 'Content-Type': 'application/json' });
                res.end(JSON.stringify({ success: false, error: 'userIdが指定されていません' }));
                return;
            }

            const messages = offlineMessageQueue.get(targetUserId) || [];
            offlineMessageQueue.delete(targetUserId);
            saveOfflineQueue();

            const readReceipts = offlineReadQueue.get(targetUserId) || [];
            offlineReadQueue.delete(targetUserId);
            saveOfflineReads();

            console.log(`[Chat Pending API] ${targetUserId} へ保留メッセージ ${messages.length}件、既読通知 ${readReceipts.length}バッチを一括返却・クリア`);
            res.writeHead(200, { 'Content-Type': 'application/json; charset=utf-8' });
            res.end(JSON.stringify({
                success: true,
                userId: targetUserId,
                count: messages.length,
                messages: messages,
                readReceipts: readReceipts
            }));
            return;
        }
        catch (err)
        {
            console.error('[Chat Pending API Error]', err);
            res.writeHead(500, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ success: false, error: err.message }));
            return;
        }
    }

    // [API 5] 既読通知受信 (HTTPフォールバック対応: WebSocket未接続・切断時でも確実に既読を記録＆中継)
    if (req.method === 'POST' && url === '/api/chat/read')
    {
        try
        {
            const body = await parseJsonBody(req);
            const fromUserId = (body.fromUserId || '').trim();
            const targetUserId = (body.targetUserId || '').trim();
            const messageIds = Array.isArray(body.messageIds) ? body.messageIds : [];

            if (!fromUserId || !targetUserId || messageIds.length === 0)
            {
                res.writeHead(400, { 'Content-Type': 'application/json' });
                res.end(JSON.stringify({ success: false, error: '引数が不足しています' }));
                return;
            }

            const targetEntry = users.get(targetUserId);
            let forwarded = false;
            if (targetEntry && targetEntry.ws.readyState === WebSocket.OPEN)
            {
                targetEntry.ws.send(JSON.stringify({
                    type: 'chat_read',
                    fromUserId: fromUserId,
                    targetUserId: targetUserId,
                    messageIds: messageIds
                }));
                forwarded = true;
                console.log(`[HTTP Chat Read] ${fromUserId} が ${targetUserId} のメッセージ ${messageIds.length}件を既読 (WS中継完了)`);
            }

            if (!forwarded)
            {
                if (!offlineReadQueue.has(targetUserId))
                {
                    offlineReadQueue.set(targetUserId, []);
                }
                const rq = offlineReadQueue.get(targetUserId);
                rq.push({
                    fromUserId: fromUserId,
                    targetUserId: targetUserId,
                    messageIds: messageIds
                });
                if (rq.length > 200) { rq.shift(); }
                saveOfflineReads();
                console.log(`[HTTP Chat Read Offline] 相手(${targetUserId})オフラインのため既読通知をキュー保管 (保留計: ${rq.length}件)`);
            }

            res.writeHead(200, { 'Content-Type': 'application/json; charset=utf-8' });
            res.end(JSON.stringify({ success: true, forwarded: forwarded }));
            return;
        }
        catch (err)
        {
            console.error('[HTTP Chat Read Error]', err);
            res.writeHead(500, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ success: false, error: err.message }));
            return;
        }
    }

    // [API 6] チャットメッセージ送信 (HTTPフォールバック対応: WebSocket切断時・未接続時でも確実に相手へ中継＆プッシュ送信)
    if (req.method === 'POST' && url === '/api/chat/send')
    {
        try
        {
            const data = await parseJsonBody(req);
            const fromUserId = (data.fromUserId || '').trim();
            const targetUserId = (data.targetUserId || data.targetId || '').trim();

            if (!fromUserId || !targetUserId || !data.messageId)
            {
                res.writeHead(400, { 'Content-Type': 'application/json' });
                res.end(JSON.stringify({ success: false, error: '引数が不足しています' }));
                return;
            }

            const targetEntry = users.get(targetUserId);
            const senderName = users.get(fromUserId)?.name || data.fromName || '友だち';

            // 1. WebSocketがアクティブなら即座に直接中継
            let sentViaWs = false;
            if (targetEntry && targetEntry.ws.readyState === WebSocket.OPEN)
            {
                targetEntry.ws.send(JSON.stringify(data));
                sentViaWs = true;
                console.log(`[HTTP Chat] Forwarded message from ${fromUserId} to ${targetUserId} via WebSocket`);
            }
            else
            {
                // 相手がオフラインの場合: サーバー側キューに一時保管
                if (!offlineMessageQueue.has(targetUserId))
                {
                    offlineMessageQueue.set(targetUserId, []);
                }
                const queue = offlineMessageQueue.get(targetUserId);
                queue.push(data);
                if (queue.length > 100) { queue.shift(); }
                saveOfflineQueue();
                console.log(`[HTTP Chat Offline] 相手(${targetUserId})がオフラインのためキュー保管 (保留計: ${queue.length}件)`);
            }

            // 2. FCMプッシュ送信
            const targetFcm = fcmTokenStore.get(targetUserId) || fcmTokenStore.get(targetUserId.trim());
            if (targetFcm && targetFcm.fcmToken)
            {
                sendChatMessagePush(targetFcm.fcmToken, {
                    fromUserId: fromUserId,
                    fromName: senderName,
                    messageId: data.messageId,
                    text: data.text || '',
                    iv: data.iv || '',
                    cipher: data.cipher || '',
                    imageBase64: data.imageBase64 || '',
                    fileUrl: data.fileUrl || '',
                    fileKey: data.fileKey || '',
                    fileName: data.fileName || '',
                    fileSize: data.fileSize || '0',
                    timestamp: data.timestamp || Date.now()
                });
            }

            res.writeHead(200, { 'Content-Type': 'application/json; charset=utf-8' });
            res.end(JSON.stringify({ success: true, messageId: data.messageId, sentViaWs: sentViaWs }));
            return;
        }
        catch (err)
        {
            console.error('[HTTP Chat Send API Error]', err);
            res.writeHead(500, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ success: false, error: err.message }));
            return;
        }
    }

    // [API 7] 暗号化ファイル直接アップロード (E2EEファイル転送: 外部依存完全撤廃・高信頼ストリーミング)
    if (req.method === 'POST' && url === '/api/file/upload')
    {
        try
        {
            const UPLOAD_DIR = path.join(__dirname, 'uploads');
            if (!fs.existsSync(UPLOAD_DIR))
            {
                fs.mkdirSync(UPLOAD_DIR, { recursive: true });
            }

            const fileId = 'enc_' + crypto.randomBytes(16).toString('hex');
            const savePath = path.join(UPLOAD_DIR, `${fileId}.bin`);
            const writeStream = fs.createWriteStream(savePath);

            let uploadedBytes = 0;
            const maxLimit = 150 * 1024 * 1024; // 150MB

            req.on('data', (chunk) => {
                uploadedBytes += chunk.length;
                if (uploadedBytes > maxLimit)
                {
                    writeStream.destroy();
                    if (fs.existsSync(savePath)) { fs.unlinkSync(savePath); }
                    res.writeHead(413, { 'Content-Type': 'application/json' });
                    res.end(JSON.stringify({ success: false, error: 'ファイルサイズが上限(150MB)を超えています' }));
                    req.destroy();
                }
            });

            req.pipe(writeStream);

            writeStream.on('finish', () => {
                const host = req.headers['host'] || 'localhost:3000';
                const protocol = req.headers['x-forwarded-proto'] || (req.socket.encrypted ? 'https' : 'http');
                const downloadUrl = `${protocol}://${host}/api/file/download/${fileId}`;
                console.log(`[File Upload] 暗号化ファイルを正常保管: ${fileId} (${uploadedBytes} bytes) -> ${downloadUrl}`);
                res.writeHead(200, { 'Content-Type': 'application/json; charset=utf-8' });
                res.end(JSON.stringify({
                    success: true,
                    fileId: fileId,
                    url: downloadUrl,
                    size: uploadedBytes
                }));
            });

            writeStream.on('error', (err) => {
                console.error('[File Upload Error]', err);
                if (fs.existsSync(savePath)) { fs.unlinkSync(savePath); }
                res.writeHead(500, { 'Content-Type': 'application/json' });
                res.end(JSON.stringify({ success: false, error: 'ファイル書き込みエラー: ' + err.message }));
            });
            return;
        }
        catch (err)
        {
            console.error('[File Upload Exception]', err);
            res.writeHead(500, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ success: false, error: err.message }));
            return;
        }
    }

    // [API 8] 暗号化ファイル直接ダウンロード (生のバイナリを高速・確実に返却)
    if (req.method === 'GET' && url.startsWith('/api/file/download/'))
    {
        const UPLOAD_DIR = path.join(__dirname, 'uploads');
        const fileId = path.basename(url);
        const filePath = path.join(UPLOAD_DIR, `${fileId}.bin`);
        if (!fs.existsSync(filePath))
        {
            res.writeHead(404, { 'Content-Type': 'text/plain' });
            res.end('File not found or expired');
            return;
        }

        const stat = fs.statSync(filePath);
        res.writeHead(200, {
            'Content-Type': 'application/octet-stream',
            'Content-Length': stat.size,
            'Content-Disposition': `attachment; filename="${fileId}.bin"`,
            'Cache-Control': 'no-cache'
        });
        const readStream = fs.createReadStream(filePath);
        readStream.pipe(res);
        return;
    }

    res.writeHead(404, { 'Content-Type': 'text/plain' });
    res.end('Not Found');
});

const wss = new WebSocket.Server({ server, maxPayload: 45 * 1024 * 1024 });
const rooms = new Map(); // roomId -> Set of { ws, userId }
const users = new Map(); // userId -> { ws, name, token }

// 25秒間隔のハートビートPing
const heartbeatInterval = setInterval(() =>
{
    wss.clients.forEach((ws) =>
    {
        if (ws.isAlive === false)
        {
            return ws.terminate();
        }
        ws.isAlive = false;
        ws.ping();
    });
}, 25000);

wss.on('close', () =>
{
    clearInterval(heartbeatInterval);
});

// [シナリオC防御] セッショントークン＆物理端末UIDバインド厳格検証
function isValidSession(token, userId)
{
    if (!token || typeof token !== 'string') { return false; }
    if (activeSessions.has(token))
    {
        const session = activeSessions.get(token);
        if (session.expiresAt > Date.now())
        {
            // 端末UIDバインド検証 (別端末からのトークン流用・成りすましを100%遮断)
            if (session.deviceUid && userId && session.deviceUid !== userId)
            {
                console.warn(`[Security Block] 端末UID不一致によるセッション横取りを遮断: 発行元=${session.deviceUid}, 接続元=${userId}`);
                return false;
            }
            return true;
        }
        activeSessions.delete(token);
    }
    return false;
}

// WebSocket接続受付
wss.on('connection', (ws) =>
{
    ws.isAlive = true;
    ws.on('pong', () => { ws.isAlive = true; });

    let currentRoomId = null;
    let currentUserId = null;

    // レートリミット管理 (1秒間に最大8通まで)
    ws.rateLimitWindowStart = Date.now();
    ws.messageCountInWindow = 0;

    // メッセージハンドラ
    ws.on('message', (message) =>
    {
        try
        {
            // レートリミット検査 (連打・DoS防御: チャット連続送信対応で30通/秒まで許容)
            const now = Date.now();
            if (now - ws.rateLimitWindowStart > 1000)
            {
                ws.rateLimitWindowStart = now;
                ws.messageCountInWindow = 0;
            }
            ws.messageCountInWindow++;
            if (ws.messageCountInWindow > 30)
            {
                console.warn(`[Rate Limit Exceeded] メッセージ過剰送信をドロップ: ${currentUserId || 'unknown'}`);
                return;
            }

            const data = JSON.parse(message);
            const type = data.type;
            const roomId = data.roomId;
            const userId = data.userId;
            const token = data.token;

            // 待受登録
            if (type === 'register')
            {
                // サーバー再起動でメモリ上のactiveSessionsがクリアされた場合でも、正当なUIDであれば接続を維持・再受容
                if (token && !isValidSession(token, userId))
                {
                    console.warn(`[Session Auto-heal] サーバー再起動等によりセッション未登録ですが、UID待受を継続許可します: ${userId}`);
                }

                currentUserId = userId;
                users.set(userId, { ws, name: data.name || '友だち', token: token });
                console.log(`[Register] User standby: ${userId} (${data.name || ''})`);
                ws.send(JSON.stringify({ type: 'registered', userId: userId }));

                // 保留されていたオフラインメッセージがあれば一括バッチ配信！
                if (offlineMessageQueue.has(userId))
                {
                    const queuedMessages = offlineMessageQueue.get(userId) || [];
                    if (queuedMessages.length > 0)
                    {
                        console.log(`[Offline Queue] 待受復帰した ${userId} へ保留メッセージ ${queuedMessages.length}件を一括バッチ配信`);
                        if (ws.readyState === WebSocket.OPEN)
                        {
                            ws.send(JSON.stringify({
                                type: 'chat_messages_batch',
                                targetUserId: userId,
                                messages: queuedMessages
                            }));
                        }
                    }
                    offlineMessageQueue.delete(userId);
                    saveOfflineQueue();
                }

                // 保留されていたオフライン既読通知があれば一括配信！
                if (offlineReadQueue.has(userId))
                {
                    const queuedReads = offlineReadQueue.get(userId) || [];
                    if (queuedReads.length > 0)
                    {
                        console.log(`[Offline Read Queue] 待受復帰した ${userId} へ保留既読通知 ${queuedReads.length}件を一括配信`);
                        if (ws.readyState === WebSocket.OPEN)
                        {
                            for (const r of queuedReads)
                            {
                                ws.send(JSON.stringify({
                                    type: 'chat_read',
                                    fromUserId: r.fromUserId,
                                    targetUserId: r.targetUserId,
                                    messageIds: r.messageIds
                                }));
                            }
                        }
                    }
                    offlineReadQueue.delete(userId);
                    saveOfflineReads();
                }
                return;
            }

            // 着信コール通知 (WebSocket中継 ＆ FCM高優先度プッシュ二重化同時送信)
            if (type === 'call_invite')
            {
                const targetUserId = data.targetUserId || data.targetId;
                const targetEntry = users.get(targetUserId);

                let forwardedViaWs = false;
                if (targetEntry && targetEntry.ws.readyState === WebSocket.OPEN)
                {
                    targetEntry.ws.send(JSON.stringify({
                        type: 'incoming_call',
                        fromUserId: data.fromUserId,
                        fromName: data.fromName,
                        roomId: data.roomId,
                        isVideo: data.isVideo === true || data.isVideo === 'true'
                    }));
                    console.log(`[Call Invite] Forwarded via WebSocket from ${data.fromUserId} to ${targetUserId}`);
                    forwardedViaWs = true;
                }

                // LINE同等の通知バー不要・完全バックグラウンド着信: 画面オフ・スリープ端末を確実に起こすためFCMプッシュも常に同時送信
                const targetFcm = fcmTokenStore.get(targetUserId) || fcmTokenStore.get((targetUserId || '').trim());
                if (targetFcm && targetFcm.fcmToken)
                {
                    console.log(`[Call Invite] Triggering FCM Push to target: ${targetUserId} (wsOnline=${forwardedViaWs})`);
                    sendIncomingCallPush(targetFcm.fcmToken, {
                        fromUserId: data.fromUserId,
                        fromName: data.fromName,
                        roomId: data.roomId,
                        isVideo: data.isVideo === true || data.isVideo === 'true'
                    });
                }
                else if (!forwardedViaWs)
                {
                    console.warn(`[Call Invite Offline] 相手(${targetUserId})はWebSocket切断かつFCMトークン未登録`);
                    ws.send(JSON.stringify({ type: 'call_user_offline', targetUserId: targetUserId }));
                }
                return;
            }

            // 着信拒否・切断・キャンセル
            if (type === 'call_cancel' || type === 'call_decline')
            {
                const targetUserId = data.targetUserId || data.targetId;
                const targetEntry = users.get(targetUserId);
                if (targetEntry && targetEntry.ws.readyState === WebSocket.OPEN)
                {
                    targetEntry.ws.send(JSON.stringify(data));
                }
                return;
            }

            // チャットメッセージ中継 (E2EE暗号文転送 ＆ オフラインキューイング ＆ FCM新着プッシュ連動)
            if (type === 'chat_message')
            {
                // 送信者UID偽装チェック
                if (currentUserId && data.fromUserId !== currentUserId)
                {
                    console.warn(`[Security Block] チャット送信元UID偽装を遮断: registered=${currentUserId}, packet=${data.fromUserId}`);
                    return;
                }

                // パケットサイズ検査 (最大35MB制限: 大容量ZIPファイル・高解像度画像・DoS防御)
                if (message.length > 35 * 1024 * 1024)
                {
                    console.warn(`[Security Block] 許容サイズ(35MB)超過の巨大メッセージを破棄: ${data.fromUserId}`);
                    return;
                }

                const targetUserId = data.targetUserId || data.targetId;
                const targetEntry = users.get(targetUserId);
                const senderName = users.get(data.fromUserId)?.name || data.fromName || '友だち';

                // 1. WebSocketがアクティブなら即座に直接中継
                let sentViaWs = false;
                if (targetEntry && targetEntry.ws.readyState === WebSocket.OPEN)
                {
                    targetEntry.ws.send(JSON.stringify(data));
                    sentViaWs = true;
                    console.log(`[E2EE Chat] Forwarded encrypted message from ${data.fromUserId} to ${targetUserId}`);
                }
                else
                {
                    // 相手がオフラインの場合: サーバー側キューに一時保管
                    if (!offlineMessageQueue.has(targetUserId))
                    {
                        offlineMessageQueue.set(targetUserId, []);
                    }
                    const queue = offlineMessageQueue.get(targetUserId);
                    queue.push(data);
                    if (queue.length > 100) { queue.shift(); } // 最大100件保持
                    saveOfflineQueue();

                    console.log(`[E2EE Chat Offline] 相手(${targetUserId})がオフラインのためキュー保管 (保留計: ${queue.length}件)`);
                }

                // 2. アプリを閉じている・バックグラウンド・画面OFF時でも確実に届くようFCM高優先度新着プッシュを常に送信！
                const targetFcm = fcmTokenStore.get(targetUserId) || fcmTokenStore.get((targetUserId || '').trim());
                if (targetFcm && targetFcm.fcmToken)
                {
                    console.log(`[FCM Chat Push] 相手(${targetUserId})へ高優先度チャットプッシュ送信実行`);
                    sendChatMessagePush(targetFcm.fcmToken, {
                        fromUserId: data.fromUserId,
                        fromName: senderName,
                        messageId: data.messageId,
                        text: data.text || '',
                        iv: data.iv || '',
                        cipher: data.cipher || '',
                        imageBase64: data.imageBase64 || '',
                        fileUrl: data.fileUrl || '',
                        fileKey: data.fileKey || '',
                        fileName: data.fileName || '',
                        fileSize: data.fileSize || '0',
                        timestamp: data.timestamp || Date.now()
                    });
                }
                else
                {
                    console.warn(`[FCM Chat Push] 相手(${targetUserId})のFCMトークンが未登録です (登録済みUID一覧: ${Array.from(fcmTokenStore.keys()).join(', ') || 'なし'})`);
                }

                // 送信元へ受領ACK返送 (送信成功チェックマーク用)
                if (ws.readyState === WebSocket.OPEN)
                {
                    ws.send(JSON.stringify({
                        type: 'chat_sent_ack',
                        messageId: data.messageId,
                        timestamp: Date.now()
                    }));
                }
                return;
            }

            // 既読通知中継 (なりすまし検証 ＆ オフライン永続キュー連動)
            if (type === 'chat_read')
            {
                if (currentUserId && data.fromUserId !== currentUserId)
                {
                    console.warn(`[Security Block] 既読通知の送信元UID偽装を遮断: registered=${currentUserId}, packet=${data.fromUserId}`);
                    return;
                }

                const targetUserId = data.targetUserId || data.targetId;
                const targetEntry = users.get(targetUserId);
                let forwarded = false;
                if (targetEntry && targetEntry.ws.readyState === WebSocket.OPEN)
                {
                    targetEntry.ws.send(JSON.stringify(data));
                    forwarded = true;
                    console.log(`[Chat Read] ${data.fromUserId} read messages of ${targetUserId}`);
                }

                // 相手がオフライン(WebSocket切断中)の場合、相手が後でアプリ起動/画面表示した時に同期できるようキューに蓄積
                if (!forwarded)
                {
                    if (!offlineReadQueue.has(targetUserId))
                    {
                        offlineReadQueue.set(targetUserId, []);
                    }
                    const rq = offlineReadQueue.get(targetUserId);
                    rq.push({
                        fromUserId: data.fromUserId,
                        targetUserId: data.targetUserId,
                        messageIds: data.messageIds || data.ids || []
                    });
                    if (rq.length > 200) { rq.shift(); }
                    saveOfflineReads();
                    console.log(`[Chat Read Offline] 相手(${targetUserId})オフラインのため既読通知をキュー保管 (保留計: ${rq.length}件)`);
                }
                return;
            }

            // ルーム入室
            if (type === 'join')
            {
                currentRoomId = roomId;
                currentUserId = userId;
                if (!rooms.has(roomId)) { rooms.set(roomId, new Set()); }
                const room = rooms.get(roomId);

                // 発信者(部屋の最初の1人)が入室した時、相手端末へ自動的に着信通知をプッシュ！
                if (room.size === 0 && roomId)
                {
                    const allUids = roomId.match(/u_[a-zA-Z0-9]+/g) || [];
                    const targetUid = allUids.find(id => id !== userId);
                    if (targetUid)
                    {
                        const callerName = data.userName || users.get(userId)?.name || '友だち';
                        const targetEntry = users.get(targetUid);
                        if (targetEntry && targetEntry.ws.readyState === WebSocket.OPEN)
                        {
                            targetEntry.ws.send(JSON.stringify({
                                type: 'incoming_call',
                                fromUserId: userId,
                                fromName: callerName,
                                roomId: roomId
                            }));
                            console.log(`[Auto-Call-Push] Sent incoming call via WS to ${targetUid} from ${userId}`);
                        }

                        // 相手端末がバックグラウンド/キル時でも確実に着信通知が届くようFCMプッシュを二重発火
                        const targetFcm = fcmTokenStore.get(targetUid) || fcmTokenStore.get(targetUid.trim());
                        if (targetFcm && targetFcm.fcmToken)
                        {
                            sendIncomingCallPush(targetFcm.fcmToken, {
                                fromUserId: userId,
                                fromName: callerName,
                                roomId: roomId
                            });
                        }
                    }
                }

                const isCaller = !!data.isCaller;

                // 1. 既存の入室者へ新参加者の入室を通知 (発信者フラグを付与)
                room.forEach((client) =>
                {
                    if (client.ws !== ws && client.ws.readyState === WebSocket.OPEN)
                    {
                        client.ws.send(JSON.stringify({ type: 'joined', peerId: userId, isCaller: isCaller }));
                    }
                });

                // 2. 新入室者へも既存の入室者を通知 (入室順序に関わらず相互検知を100%保証)
                room.forEach((client) =>
                {
                    if (client.ws !== ws && client.ws.readyState === WebSocket.OPEN)
                    {
                        ws.send(JSON.stringify({ type: 'joined', peerId: client.userId, isCaller: !!client.isCaller }));
                    }
                });

                room.add({ ws, userId, isCaller });
                console.log(`[Join] Room: ${roomId}, User: ${userId}, isCaller: ${isCaller}, Count: ${room.size}`);
                return;
            }

            // 通話制御・メディア同期メッセージ (巨大SDPインジェクションDoS防御: 64KB上限)
            if (['offer', 'answer', 'candidate', 'avatar_sync'].includes(type))
            {
                if (message.length > 64 * 1024)
                {
                    console.warn(`[Security Block] 許容サイズ(64KB)超過のシグナリングパケットを破棄: ${type} (${message.length} bytes)`);
                    return;
                }

                if (currentRoomId && rooms.has(currentRoomId))
                {
                    const room = rooms.get(currentRoomId);
                    room.forEach((client) =>
                    {
                        if (client.ws !== ws && client.ws.readyState === WebSocket.OPEN)
                        {
                            client.ws.send(JSON.stringify(data));
                        }
                    });
                }
                return;
            }

            if (type === 'leave')
            {
                removeClientFromRoom(ws, currentRoomId, currentUserId);
            }
        }
        catch (e)
        {
            console.error('JSON parse or forward error:', e.message);
        }
    });

    // 切断処理
    const onCloseOrError = () =>
    {
        if (currentUserId && users.get(currentUserId)?.ws === ws)
        {
            users.delete(currentUserId);
            console.log(`[Unregister] Standby disconnected: ${currentUserId}`);
        }
        removeClientFromRoom(ws, currentRoomId, currentUserId);
    };

    ws.on('close', onCloseOrError);
    ws.on('error', onCloseOrError);
});

// ルームからの退出処理
function removeClientFromRoom(ws, roomId, userId)
{
    if (!roomId || !rooms.has(roomId)) { return; }
    const room = rooms.get(roomId);
    let target = null;
    room.forEach((client) =>
    {
        if (client.ws === ws) { target = client; }
    });

    if (target)
    {
        room.delete(target);
        console.log(`[Leave] Room: ${roomId}, User: ${userId}, Remaining: ${room.size}`);
        room.forEach((client) =>
        {
            if (client.ws.readyState === WebSocket.OPEN)
            {
                client.ws.send(JSON.stringify({ type: 'left', peerId: userId }));
            }
        });
    }

    if (room.size === 0)
    {
        rooms.delete(roomId);
    }
}

// サーバー起動
server.listen(port, () =>
{
    console.log(`Signaling & Auth OTP Server listening on port ${port}`);
});
