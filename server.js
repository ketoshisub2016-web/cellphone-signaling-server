// 変更日時：2026年10月23日 01時28分
// WebRTC Signaling Server for CellPhone App (Glitch / Render / Local Node.js 対応)

const WebSocket = require('ws');
const http = require('http');
const port = process.env.PORT || 3000;

// HTTPヘルスチェック用サーバー (RenderやGlitchの生存監視に対応)
const server = http.createServer((req, res) => {
    res.writeHead(200, { 'Content-Type': 'text/plain; charset=utf-8' });
    res.end('CellPhone App WebRTC Signaling Server is active!
');
});

const wss = new WebSocket.Server({ server });
const rooms = new Map(); // roomId -> Set of { ws, userId }
const users = new Map(); // userId -> { ws, name } (待受クライアント管理)

// 接続受付
wss.on('connection', (ws) => {
    let currentRoomId = null;
    let currentUserId = null;

    // メッセージハンドラ
    ws.on('message', (message) => {
        try {
            const data = JSON.parse(message);
            const type = data.type;
            const roomId = data.roomId;
            const userId = data.userId;

            // 待受登録 (アプリ起動時のユーザーUID登録)
            if (type === 'register') {
                currentUserId = userId;
                users.set(userId, { ws, name: data.name || '友だち' });
                console.log(`[Register] User standby: ${userId} (${data.name || ''})`);
                ws.send(JSON.stringify({ type: 'registered', userId: userId }));
                return;
            }

            // 着信コール通知 (明示的プッシュ)
            if (type === 'call_invite') {
                const targetUserId = data.targetUserId;
                const targetEntry = users.get(targetUserId);
                if (targetEntry && targetEntry.ws.readyState === WebSocket.OPEN) {
                    targetEntry.ws.send(JSON.stringify({
                        type: 'incoming_call',
                        fromUserId: data.fromUserId,
                        fromName: data.fromName,
                        roomId: data.roomId
                    }));
                    console.log(`[Call Invite] Forwarded from ${data.fromUserId} to ${targetUserId}`);
                } else {
                    console.log(`[Call Invite] Target ${targetUserId} offline`);
                    ws.send(JSON.stringify({ type: 'call_user_offline', targetUserId: targetUserId }));
                }
                return;
            }

            // 着信拒否・切断・キャンセル通知
            if (type === 'call_cancel' || type === 'call_decline') {
                const targetUserId = data.targetUserId;
                const targetEntry = users.get(targetUserId);
                if (targetEntry && targetEntry.ws.readyState === WebSocket.OPEN) {
                    targetEntry.ws.send(JSON.stringify(data));
                }
                return;
            }

            // ルーム入室
            if (type === 'join') {
                currentRoomId = roomId;
                currentUserId = userId;

                if (!rooms.has(roomId)) {
                    rooms.set(roomId, new Set());
                }
                const room = rooms.get(roomId);

                // 発信者(部屋の最初の1人)が入室した時、相手端末へ自動的に着信通知をプッシュ！
                if (room.size === 0 && roomId) {
                    const allUids = roomId.match(/u_[a-zA-Z0-9]+/g) || [];
                    const targetUid = allUids.find(id => id !== userId);
                    if (targetUid && users.has(targetUid)) {
                        const targetEntry = users.get(targetUid);
                        if (targetEntry && targetEntry.ws.readyState === WebSocket.OPEN) {
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
                room.forEach((client) => {
                    if (client.ws.readyState === WebSocket.OPEN) {
                        client.ws.send(JSON.stringify({ type: 'joined', peerId: userId }));
                    }
                });

                room.add({ ws, userId });
                console.log(`[Join] Room: ${roomId}, User: ${userId}, Count: ${room.size}`);
                return;
            }

            // 通話制御・メディア同期メッセージ（Offer, Answer, Candidate, Avatar）の相手転送
            if (['offer', 'answer', 'candidate', 'avatar_sync'].includes(type)) {
                if (currentRoomId && rooms.has(currentRoomId)) {
                    const room = rooms.get(currentRoomId);
                    room.forEach((client) => {
                        if (client.ws !== ws && client.ws.readyState === WebSocket.OPEN) {
                            client.ws.send(JSON.stringify(data));
                        }
                    });
                }
                return;
            }

            if (type === 'leave') {
                removeClientFromRoom(ws, currentRoomId, currentUserId);
            }

        } catch (e) {
            console.error('JSON parse or forward error:', e.message);
        }
    });

    // 切断処理
    const onCloseOrError = () => {
        if (currentUserId && users.get(currentUserId)?.ws === ws) {
            users.delete(currentUserId);
            console.log(`[Unregister] Standby disconnected: ${currentUserId}`);
        }
        removeClientFromRoom(ws, currentRoomId, currentUserId);
    };

    ws.on('close', onCloseOrError);
    ws.on('error', onCloseOrError);
});

// ルームからの退出処理
function removeClientFromRoom(ws, roomId, userId) {
    if (!roomId || !rooms.has(roomId)) {
        return;
    }
    const room = rooms.get(roomId);
    let target = null;
    room.forEach((client) => {
        if (client.ws === ws) {
            target = client;
        }
    });

    if (target) {
        room.delete(target);
        console.log(`[Leave] Room: ${roomId}, User: ${userId}, Remaining: ${room.size}`);

        // 残りのメンバーへ退出を通知
        room.forEach((client) => {
            if (client.ws.readyState === WebSocket.OPEN) {
                client.ws.send(JSON.stringify({ type: 'left', peerId: userId }));
            }
        });
    }

    if (room.size === 0) {
        rooms.delete(roomId);
    }
}

// サーバー起動
server.listen(port, () => {
    console.log(`Signaling server listening on port ${port}`);
});
