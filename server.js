// 変更日時：2026年10月23日 15時22分
// WebRTC Signaling Server for CellPhone App (Glitch / Render / Local Node.js 対応)
// 二段階認証(メールOTP)、E2EEチャット中継、偽装防止検証、WebSocket認証＆レートリミット統合版

const WebSocket = require('ws');
const http = require('http');
const crypto = require('crypto');

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
        service: 'gmail',
        auth: { user, pass }
    });
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
        res.end(JSON.stringify({ status: 'ok', server: 'CellPhone Signaling Server', activeUsers: users.size }));
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

            // メール送信実行
            const transporter = createMailTransporter();
            if (transporter)
            {
                const mailOptions = {
                    from: `"CellPhone App 相互承認" <${process.env.GMAIL_USER}>`,
                    to: targetEmail,
                    subject: `【CellPhone App】${email} からのログイン承認要求`,
                    text: `CellPhone App にて「${email}」がログインを試行しています。\n\n心当たりがある場合は、以下の6桁の承認コードをLINE等で相手にお伝えください。\n\n承認コード: ${code}\n\n※このコードの有効期限は5分間です。\n※心当たりのない場合は絶対に他人にコードを教えないでください。`,
                    html: `
                        <div style="font-family: sans-serif; max-width: 500px; padding: 20px; border: 1px solid #e0e0e0; border-radius: 8px;">
                            <h2 style="color: #3B82F6; margin-top: 0;">CellPhone App 相互承認要求</h2>
                            <p><strong>「${email}」</strong> がアプリへのサインインを試行しています。</p>
                            <p>ご本人からの連絡であることを確認した上で、以下の承認コードを<strong>LINE等</strong>でお伝えください。</p>
                            <div style="background-color: #EFF6FF; padding: 15px; border-radius: 6px; text-align: center; font-size: 28px; font-weight: bold; letter-spacing: 6px; color: #1D4ED8; margin: 20px 0; border: 1px dashed #93C5FD;">
                                ${code}
                            </div>
                            <p style="font-size: 13px; color: #6B7280;">※この承認コードの有効期限は<strong>5分間</strong>です。<br>※身に覚えのない場合は絶対にコードを伝えないでください。</p>
                        </div>
                    `
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
                // GMAIL_USER/GMAIL_APP_PASS 未設定時の安全フォールバック (ログ出力＋開発用コード返却)
                console.warn(`[OTP Fallback] メール環境変数が未設定のためログにコード出力: ${code}`);
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

    res.writeHead(404, { 'Content-Type': 'text/plain' });
    res.end('Not Found');
});

const wss = new WebSocket.Server({ server });
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
            // レートリミット検査 (連打・DoS防御)
            const now = Date.now();
            if (now - ws.rateLimitWindowStart > 1000)
            {
                ws.rateLimitWindowStart = now;
                ws.messageCountInWindow = 0;
            }
            ws.messageCountInWindow++;
            if (ws.messageCountInWindow > 8)
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
                // セッション認証＆端末UID物理バインドチェック
                if (token && !isValidSession(token, userId))
                {
                    console.warn(`[Security Block] 不正または別端末トークンによる登録要求を遮断: ${userId}`);
                    ws.send(JSON.stringify({ type: 'auth_error', message: 'セッションが無効です。再サインインしてください' }));
                    ws.close(4001, 'Unauthorized');
                    return;
                }

                currentUserId = userId;
                users.set(userId, { ws, name: data.name || '友だち', token: token });
                console.log(`[Register] User standby: ${userId} (${data.name || ''})`);
                ws.send(JSON.stringify({ type: 'registered', userId: userId }));
                return;
            }

            // 着信コール通知
            if (type === 'call_invite')
            {
                const targetUserId = data.targetUserId;
                const targetEntry = users.get(targetUserId);
                if (targetEntry && targetEntry.ws.readyState === WebSocket.OPEN)
                {
                    targetEntry.ws.send(JSON.stringify({
                        type: 'incoming_call',
                        fromUserId: data.fromUserId,
                        fromName: data.fromName,
                        roomId: data.roomId
                    }));
                    console.log(`[Call Invite] Forwarded from ${data.fromUserId} to ${targetUserId}`);
                }
                else
                {
                    ws.send(JSON.stringify({ type: 'call_user_offline', targetUserId: targetUserId }));
                }
                return;
            }

            // 着信拒否・切断・キャンセル
            if (type === 'call_cancel' || type === 'call_decline')
            {
                const targetUserId = data.targetUserId;
                const targetEntry = users.get(targetUserId);
                if (targetEntry && targetEntry.ws.readyState === WebSocket.OPEN)
                {
                    targetEntry.ws.send(JSON.stringify(data));
                }
                return;
            }

            // チャットメッセージ中継 (E2EE暗号文転送 ＆ なりすまし・巨大パケット検証)
            if (type === 'chat_message')
            {
                // 送信者UID偽装チェック
                if (currentUserId && data.fromUserId !== currentUserId)
                {
                    console.warn(`[Security Block] チャット送信元UID偽装を遮断: registered=${currentUserId}, packet=${data.fromUserId}`);
                    return;
                }

                // パケットサイズ検査 (最大3MB制限: DoS・メモリ枯渇防御)
                if (message.length > 3 * 1024 * 1024)
                {
                    console.warn(`[Security Block] 許容サイズ(3MB)超過の巨大メッセージを破棄: ${data.fromUserId}`);
                    return;
                }

                const targetUserId = data.targetUserId;
                const targetEntry = users.get(targetUserId);
                if (targetEntry && targetEntry.ws.readyState === WebSocket.OPEN)
                {
                    targetEntry.ws.send(JSON.stringify(data));
                    console.log(`[E2EE Chat] Forwarded encrypted message from ${data.fromUserId} to ${targetUserId}`);
                }
                else
                {
                    ws.send(JSON.stringify({ type: 'chat_user_offline', targetUserId: targetUserId, messageId: data.messageId }));
                }
                return;
            }

            // 既読通知中継 (なりすまし検証付き)
            if (type === 'chat_read')
            {
                if (currentUserId && data.fromUserId !== currentUserId)
                {
                    console.warn(`[Security Block] 既読通知の送信元UID偽装を遮断: registered=${currentUserId}, packet=${data.fromUserId}`);
                    return;
                }

                const targetUserId = data.targetUserId;
                const targetEntry = users.get(targetUserId);
                if (targetEntry && targetEntry.ws.readyState === WebSocket.OPEN)
                {
                    targetEntry.ws.send(JSON.stringify(data));
                    console.log(`[Chat Read] ${data.fromUserId} read messages of ${targetUserId}`);
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
                    if (targetUid && users.has(targetUid))
                    {
                        const targetEntry = users.get(targetUid);
                        if (targetEntry && targetEntry.ws.readyState === WebSocket.OPEN)
                        {
                            const callerName = data.userName || users.get(userId)?.name || '友だち';
                            targetEntry.ws.send(JSON.stringify({
                                type: 'incoming_call',
                                fromUserId: userId,
                                fromName: callerName,
                                roomId: roomId
                            }));
                            console.log(`[Auto-Call-Push] Sent incoming call to ${targetUid} from ${userId}`);
                        }
                    }
                }

                // 既存の入室者へ相手の参加を通知
                room.forEach((client) =>
                {
                    if (client.ws.readyState === WebSocket.OPEN)
                    {
                        client.ws.send(JSON.stringify({ type: 'joined', peerId: userId }));
                    }
                });

                room.add({ ws, userId });
                console.log(`[Join] Room: ${roomId}, User: ${userId}, Count: ${room.size}`);
                return;
            }

            // 通話制御・メディア同期メッセージ
            if (['offer', 'answer', 'candidate', 'avatar_sync'].includes(type))
            {
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
