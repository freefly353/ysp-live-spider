"use strict";
/**
 * YSP Live Spider for JSTV — 央视频直播 spider（CatVod spider，Node.js 版）
 *
 * 来源：
 *   - 频道与三协议逻辑移植自 ysp-live-v9.5.py（Gary's Club）与它的 NanoTV JS 移植版
 *     ysp-service_2.0.13.txt（YSP Live v9.5 / v2.0.13）。频道表 64 个频道、别名、
 *     回看与强制 BK 清单逐字提取，未改动任何上游编号。
 *   - 目标接口形状来自 JSTV 下发的 CatVodSpider iOS 服务端 bundle（index.js，
 *     CatVodSpiderios 0.1.0，Node.js Fastify，127.0.0.1:9988）：每个 spider 以
 *     { meta, init, home, homeVod, category, detail, play, search, proxy } 的对象
 *     挂在 /spider/<key> 与 /spider/<key>/<type> 下；站点 key 为 nodejs_<meta.key>。
 *
 * 安装（已确认的约束，见研究记录）：
 *   - 本 bundle 的 qtr() 只保留 key 能对应内置 spider meta 的站点配置，配置里
 *     加一个新站点不会凭空出现一个 spider；新 spider 必须随 bundle 一起打包，
 *     即把本文件作为一个内置 spider 编进重建的 index.js，再托管 index.js + .md5
 *     供 JSTV 拉取。本文件导出一个 spider 对象（meta + 方法集），可直接放进
 *     bundle 的内置 spider 列表；也可以由兼容的加载器以 require() 载入。
 *   - 站点配置示例：{ "key": "nodejs_ysp", "name": "央视频", "type": 3,
 *     "searchable": 1, "quickSearch": 1, "filterable": 0 }。
 *   - ext（可选，JSON 字符串或对象）：{ "debug": false, "storePath": "<绝对路径>",
 *     "defaultRate": "36p" }。storePath 用于持久化设备身份与 JCE guid；
 *     不填时默认写本文件同目录的 ysp-store.json，写失败则只保存在内存里。
 *
 * 频道呈现（bundle 没有 /live 路由，故不用 live() 交付频道）：
 *   - home() 给出“央视 / 卫视 / 全部”三个分类；category() 返回频道卡片；
 *     detail() 给出播放线路（自动 / Device / BK / JCE）；play() 在点播时
 *     实时解析出带签名的播放地址并返回 { parse: 0, url, header }。
 *   - live() 按 CatVod 文档实现（返回分组频道结构），但本 bundle 不暴露
 *     /live 路由，JSTV 侧是否调用它未知；频道以分类条目 + play() 呈现为准。
 *   - 回看：JCE 直播窗口的 play() 回应附 timeshift { url, start, window }，
 *     回看地址走 spider 的 proxy()（do=timeshift），按请求时间实时解析 JCE。
 *     timeshift 的 URL 形状与 proxy() 参数格式按 bundle 的 /proxy 路由推断，
 *     未经实机验证。
 *
 * 未验证（静态分析 + 官方文档对照，未实机）：
 *   - 本文件尚未在真实 JSTV / bundle 环境跑通过；Device 会话、JCE 回看、
 *     timeshift proxy 均需实机验证。
 *   - 设备身份持久化路径与 bundle 的工作目录有关；写失败时每次重启都会
 *     重新注册设备（功能不受影响，只是多一次 app/start + cloud/get）。
 */

const crypto = require("node:crypto");
const zlib = require("node:zlib");
const fs = require("node:fs");
const path = require("node:path");

// ---------------------------------------------------------------------------
// 通用工具
// ---------------------------------------------------------------------------

let DEBUG = false;

function log(message) {
    // 关键事件始终输出；调试细节只在 ext.debug 时输出。
    console.log("[ysp] " + message);
}

function debugLog(message) {
    if (DEBUG) console.log("[ysp-debug] " + message);
}

/** randomHex(n)：n 字节 → 2n 个十六进制字符（与 NanoTV host.randomHex 一致）。 */
function randomHex(n) {
    return crypto.randomBytes(n).toString("hex");
}

function randomBytes(count) {
    return Array.from(crypto.randomBytes(count));
}

function sleep(ms) {
    return new Promise((resolve) => setTimeout(resolve, ms));
}

function sha1Hex(value) {
    return crypto.createHash("sha1").update(String(value), "utf8").digest("hex").toUpperCase();
}

function sha256Hex(value) {
    return crypto.createHash("sha256").update(String(value), "utf8").digest("hex");
}

function md5Hex(value) {
    return crypto.createHash("md5").update(String(value), "utf8").digest("hex");
}

// ---- AES-256-GCM，线格式与 Python 原版一致：base64(nonce[12] || ct || tag[16]) ----
// 密钥：utf8(key) 后补 0 截断到 32 字节（normalize_aes_key）。
function aesKeyBytes(key) {
    const raw = Buffer.from(String(key), "utf8");
    return Buffer.concat([raw, Buffer.alloc(32)]).subarray(0, 32);
}

function aesGcmDecryptB64(value, key) {
    const raw = Buffer.from(String(value), "base64");
    if (raw.length <= 12) throw new Error("AES-GCM payload too short");
    const nonce = raw.subarray(0, 12);
    const tag = raw.subarray(raw.length - 16);
    const ct = raw.subarray(12, raw.length - 16);
    const decipher = crypto.createDecipheriv("aes-256-gcm", aesKeyBytes(key), nonce);
    decipher.setAuthTag(tag);
    return Buffer.concat([decipher.update(ct), decipher.final()]).toString("utf8");
}

function aesGcmEncryptB64(value, key) {
    const nonce = crypto.randomBytes(12);
    const cipher = crypto.createCipheriv("aes-256-gcm", aesKeyBytes(key), nonce);
    const ct = Buffer.concat([cipher.update(Buffer.from(String(value), "utf8")), cipher.final()]);
    return Buffer.concat([nonce, ct, cipher.getAuthTag()]).toString("base64");
}

/** RSA-OAEP-SHA256（MGF1-SHA256），与 Python rsa_oaep_sha256_encrypt 一致。 */
function rsaEncryptOAEP(dataB64, publicKeyB64) {
    const key = crypto.createPublicKey({
        key: Buffer.from(String(publicKeyB64), "base64"),
        format: "der",
        type: "spki",
    });
    return crypto
        .publicEncrypt(
            { key, padding: crypto.constants.RSA_PKCS1_OAEP_PADDING, oaepHash: "sha256" },
            Buffer.from(String(dataB64), "base64"),
        )
        .toString("base64");
}

// ---- 简单键值持久化（设备身份、JCE guid）----
let storePath = null;
let storeCache = null;

function storeInit(customPath) {
    storePath = customPath || path.join(__dirname, "ysp-store.json");
    storeCache = null;
}

function storeGet(key) {
    if (storeCache === null) {
        try {
            storeCache = JSON.parse(fs.readFileSync(storePath, "utf8"));
        } catch (_) {
            storeCache = {};
        }
    }
    const value = storeCache[key];
    return value === undefined ? null : value;
}

function storeSet(key, value) {
    if (storeCache === null) storeCache = {};
    storeCache[key] = value;
    try {
        fs.writeFileSync(storePath, JSON.stringify(storeCache));
    } catch (e) {
        debugLog("store write failed: " + (e && e.message ? e.message : e));
    }
}

// ---- HTTP：fetch 封装，返回 { status, body }（body 为文本；JCE 用 base64 文本）----
async function httpRequest({ url, method, headers, body, timeoutSeconds }) {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), (timeoutSeconds || 15) * 1000);
    try {
        const response = await fetch(url, {
            method: method || "GET",
            headers: headers || {},
            body: body === undefined ? undefined : body,
            signal: controller.signal,
        });
        return { status: response.status, body: await response.text() };
    } finally {
        clearTimeout(timer);
    }
}

async function httpBinary({ url, method, headers, body, timeoutSeconds }) {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), (timeoutSeconds || 15) * 1000);
    try {
        const response = await fetch(url, {
            method: method || "GET",
            headers: headers || {},
            body: body === undefined ? undefined : body,
            signal: controller.signal,
        });
        const buffer = Buffer.from(await response.arrayBuffer());
        return { status: response.status, body: buffer.toString("base64") };
    } finally {
        clearTimeout(timer);
    }
}

/** 稳定 JSON：键排序后序列化（Device 协议 post 用）。 */
function stable(value, slash = false) {
    function sort(v) {
        if (Array.isArray(v)) return v.map(sort);
        if (v && typeof v === "object") {
            const o = {};
            Object.keys(v)
                .sort()
                .forEach((k) => (o[k] = sort(v[k])));
            return o;
        }
        return v;
    }
    const text = JSON.stringify(sort(value));
    return slash ? text.replace(/\//g, "\\/") : text;
}

function formEncode(value) {
    return encodeURIComponent(String(value))
        .replace(/[!'()*]/g, function (char) {
            return "%" + char.charCodeAt(0).toString(16).toUpperCase();
        })
        .replace(/%20/g, "+");
}

function queryString(values) {
    return Object.keys(values)
        .map(function (key) {
            return formEncode(key) + "=" + formEncode(values[key]);
        })
        .join("&");
}

// ---------------------------------------------------------------------------
// ① BK 协议 —— cKey 签名 + bkliveinfo，兜底来源
//    移植自 ysp-service_2.0.13.txt 的 createBKProtocol()（签名算法改编自
//    ysp-live-v9.5.py BK 部分）。仅把 native.http / native.randomHex / native.log
//    换成 Node 等价物，签名与请求参数未改动。
// ---------------------------------------------------------------------------

function createBKProtocol() {
    var PLATFORM = 4330403;
    var APP_VERSION = "V8.22.1035.3031";
    var TEA_KEY = fromHex("59b2f7cf725ef43c34fdd7c123411ed3");
    var GUARD_KEY = fromHex("110dbec10c23e7d2e56a1cad6914ef1b");
    var KEY_XOR = [132, 46, 237, 8, 240, 102, 230, 234, 72, 180, 202, 169, 145, 237, 111, 243];
    var GUARD_XOR = [179, 201, 83, 160, 105, 19, 173, 77];
    var PLAYBACK_HEADERS = { "User-Agent": "qqlive", "Referer": "https://live.cctv.cn/" };

    function fromHex(hex) {
        if (typeof hex !== "string" || hex.length % 2 || !/^[0-9a-f]*$/i.test(hex)) {
            throw new Error("Invalid hexadecimal bytes");
        }
        var result = [];
        for (var i = 0; i < hex.length; i += 2) result.push(parseInt(hex.slice(i, i + 2), 16));
        return result;
    }
    function toHex(bytes) {
        return bytes
            .map(function (byte) {
                return (byte < 16 ? "0" : "") + byte.toString(16);
            })
            .join("");
    }
    function utf8(value) {
        var encoded = encodeURIComponent(String(value));
        var result = [];
        for (var i = 0; i < encoded.length; i++) {
            if (encoded[i] === "%") {
                result.push(parseInt(encoded.slice(i + 1, i + 3), 16));
                i += 2;
            } else result.push(encoded.charCodeAt(i));
        }
        return result;
    }
    function u32(value) {
        return value >>> 0;
    }
    function uint32(bytes, offset) {
        return u32((bytes[offset] << 24) | (bytes[offset + 1] << 16) | (bytes[offset + 2] << 8) | bytes[offset + 3]);
    }
    function be32(value) {
        value = u32(value);
        return [value >>> 24, (value >>> 16) & 255, (value >>> 8) & 255, value & 255];
    }
    function lp(value) {
        var bytes = typeof value === "string" ? utf8(value) : value;
        if (bytes.length > 65535) throw new Error("Signature field too long");
        return [bytes.length >>> 8, bytes.length & 255].concat(bytes);
    }
    function checksum(bytes) {
        var value = 0;
        for (var i = 0; i < bytes.length; i++) value = (131 * value + bytes[i]) & 0x7fffffff;
        return value;
    }
    function teaBlock(block, key) {
        if (block.length !== 8 || key.length !== 16) throw new Error("Invalid TEA block/key size");
        var y = uint32(block, 0),
            z = uint32(block, 4),
            sum = 0;
        var k = [uint32(key, 0), uint32(key, 4), uint32(key, 8), uint32(key, 12)];
        for (var round = 0; round < 16; round++) {
            sum = u32(sum + 0x9e3779b9);
            y = u32(y + u32(u32(u32(z << 4) + k[0]) ^ u32(z + sum) ^ u32((z >>> 5) + k[1])));
            z = u32(z + u32(u32(u32(y << 4) + k[2]) ^ u32(y + sum) ^ u32((y >>> 5) + k[3])));
        }
        return be32(y).concat(be32(z));
    }
    function xorBytes(a, b) {
        return a.map(function (byte, i) {
            return byte ^ b[i];
        });
    }
    function teaPacket(data, key, randomBytesFn) {
        var pad = (8 - ((data.length + 10) % 8)) % 8;
        var plain = [(randomBytesFn(1)[0] & 248) | pad].concat(
            randomBytesFn(pad),
            randomBytesFn(2),
            data,
            [0, 0, 0, 0, 0, 0, 0],
        );
        var output = [],
            previousPlain = [0, 0, 0, 0, 0, 0, 0, 0],
            previousCipher = previousPlain.slice();
        for (var offset = 0; offset < plain.length; offset += 8) {
            var mixed = xorBytes(plain.slice(offset, offset + 8), previousCipher);
            var cipher = xorBytes(teaBlock(mixed, key), previousPlain);
            output = output.concat(cipher);
            previousPlain = mixed;
            previousCipher = cipher;
        }
        return output;
    }
    function base64(bytes) {
        var alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        var output = "";
        for (var i = 0; i < bytes.length; i += 3) {
            var a = bytes[i],
                b = bytes[i + 1],
                c = bytes[i + 2];
            output += alphabet[a >>> 2];
            output += alphabet[((a & 3) << 4) | (b === undefined ? 0 : b >>> 4)];
            output += b === undefined ? "=" : alphabet[((b & 15) << 2) | (c === undefined ? 0 : c >>> 6)];
            output += c === undefined ? "=" : alphabet[c & 63];
        }
        return output;
    }
    function guard(timestamp, guid, randomBytesFn) {
        function tail(value) {
            return value.length >= 5 ? value.slice(-5) : "";
        }
        var body = be32(timestamp).concat(lp(tail(guid)), lp(tail("null")), lp(tail("null")), lp("-1"));
        var plain = lp(body);
        var encrypted = teaPacket(plain, GUARD_KEY, randomBytesFn).concat(be32(checksum(plain)));
        return toHex(
            encrypted.map(function (byte, i) {
                return byte ^ GUARD_XOR[i & 7];
            }),
        ).toUpperCase();
    }
    function createCKey(channelID, timestamp, randomBytesFn) {
        var guid = toHex(randomBytesFn(16));
        var signatureGuard = guard(timestamp, guid, randomBytesFn);
        var uid = toHex(randomBytesFn(4)).toUpperCase();
        var body = fromHex("0000004200000004000004d2").concat(
            be32(PLATFORM),
            be32(0),
            be32(timestamp),
            lp("dcgh"),
            lp("_zj1A5Gh6QYcxWjIUGos2w=="),
            lp(APP_VERSION),
            lp(String(channelID)),
            lp(guid),
            be32(1),
            be32(1),
            lp(uid),
            lp("nil"),
            lp("57eab0c4-2c58-44c6-8ae9-dd2757525dc5"),
            lp("nil"),
            lp("v0.1.000"),
            lp("com.cctv.yangshipin.app.iphone"),
            lp(String(PLATFORM)),
            lp("ex_json_bus"),
            lp("ex_json_vs"),
            lp(signatureGuard),
        );
        var packet = lp(body);
        var packetChecksum = be32(checksum(packet));
        for (var i = 0; i < 4; i++) packet[18 + i] = packetChecksum[i];
        var encrypted = teaPacket(packet, TEA_KEY, randomBytesFn).concat(be32(checksum(packet)));
        encrypted = encrypted.map(function (byte, index) {
            return byte ^ KEY_XOR[index & 15];
        });
        var uuid = randomBytesFn(16);
        uuid[6] = (uuid[6] & 15) | 64;
        uuid[8] = (uuid[8] & 63) | 128;
        return {
            cKey: "--01" + base64(encrypted).replace(/\+/g, "_").replace(/\//g, "-").replace(/=+$/, ""),
            guid: guid,
            ts: timestamp,
            flowId: toHex(uuid).toUpperCase() + "_" + PLATFORM,
        };
    }
    function upstreamRequest(channel) {
        var key = createCKey(channel.channelID, Math.floor(Date.now() / 1000), randomBytes);
        var values = {
            atime: "120",
            livepid: channel.livePID,
            cnlid: channel.channelID,
            appVer: APP_VERSION,
            app_version: "300090",
            caplv: "1",
            cmd: "2",
            defn: channel.definition,
            device: "iPhone",
            encryptVer: "4.2",
            getpreviewinfo: "0",
            hevclv: "0",
            lang: "zh-Hans_CN",
            livequeue: "0",
            logintype: "1",
            nettype: "1",
            newnettype: "1",
            newplatform: String(PLATFORM),
            platform: String(PLATFORM),
            sdtfrom: "v3021",
            spacode: "23",
            spaudio: "1",
            spdemuxer: "6",
            spdrm: "2",
            spdynamicrange: "1",
            spflv: "1",
            spflvaudio: "1",
            sphdrfps: "60",
            sphttps: "1",
            spvcode: base64(utf8("H(30:1080,60:1080|30:1080,60:1080)")),
            spvideo: "4",
            stream: "1",
            system: "1",
            sysver: "ios18.2.1",
            uhd_flag: "0",
            cKey: key.cKey,
            guid: key.guid,
            fntick: String(key.ts),
            flowid: key.flowId,
            playbacktime: "0",
        };
        return {
            url: "https://bkliveinfo.ysp.cctv.cn/?" + queryString(values),
            method: "GET",
            headers: { "User-Agent": "qqlive", "Accept": "application/json" },
            timeoutSeconds: 15,
        };
    }
    function sanitizedDiagnostic(value) {
        return String(value || "源站网络请求失败")
            .replace(/https?:\/\/[^\s"'<>]+/gi, function (url) {
                var authority = /^https?:\/\/[^\/?#]+/i.exec(url);
                return authority ? authority[0] + "/[redacted]" : "[redacted-url]";
            })
            .replace(/\b(cKey|flowid|APPSIGN|token|sig|signature)\s*[=:]\s*[^\s,;]+/gi, "$1=[redacted]")
            .replace(/[\u0000-\u001f\u007f]+/g, " ")
            .slice(0, 400);
    }
    async function http(request) {
        const response = await httpRequest(request);
        if (response.status < 200 || response.status > 299) {
            throw new Error("源站 HTTP " + response.status);
        }
        return response;
    }
    function playbackHost(url) {
        if (typeof url !== "string" || /[\s\u0000-\u001f\u007f\\]/.test(url)) return null;
        var match = /^(https?):\/\/([^\/?#]+)(?:[\/?#]|$)/i.exec(url);
        if (!match || match[2].indexOf("@") !== -1 || match[2].indexOf("%") !== -1) return null;
        var authority = match[2].toLowerCase();
        var parts = /^([a-z0-9.-]+)(?::([0-9]{1,5}))?$/.exec(authority);
        if (!parts || (parts[2] && (Number(parts[2]) < 1 || Number(parts[2]) > 65535))) return null;
        var host = parts[1];
        if (
            host.length > 253 ||
            host.split(".").some(function (label) {
                return !label || label.length > 63 || !/^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/.test(label);
            })
        )
            return null;
        var suffixes = ["cctv.cn", "cctv.com", "cctvpic.com", "citvc.com", "yangshipin.cn", "cntv.cn", "cntv.com"];
        return suffixes.some(function (suffix) {
            return host === suffix || host.slice(-(suffix.length + 1)) === "." + suffix;
        })
            ? host
            : null;
    }
    function isAllowedPlaybackURL(url) {
        return playbackHost(url) !== null;
    }
    function collectCandidates(payload) {
        var all = [];
        if (typeof payload.playurl === "string") all.push(payload.playurl);
        var backup = payload.backurl_list || payload.backurlList || payload.backurl;
        if (Array.isArray(backup))
            backup.forEach(function (item) {
                if (typeof item === "string") all.push(item);
                else if (item && typeof item === "object") all.push(item.url || item.playurl || "");
            });
        else if (typeof backup === "string") all = all.concat(backup.split(/[;,]\s*(?=https?:\/\/)/i));
        var unique = [];
        all.forEach(function (candidate) {
            if (isAllowedPlaybackURL(candidate) && unique.indexOf(candidate) < 0) unique.push(candidate);
        });
        return unique.sort(function (a, b) {
            var scoreA = playbackHost(a).indexOf("bklive-") >= 0 ? 0 : 1;
            var scoreB = playbackHost(b).indexOf("bklive-") >= 0 ? 0 : 1;
            return scoreA - scoreB || (a < b ? -1 : a > b ? 1 : 0);
        });
    }
    function publicChannel(channel) {
        return {
            id: channel.id,
            name: channel.name,
            group: channel.group,
            tvgID: channel.tvgID,
            logo: channel.logo,
            definition: channel.definition,
            quality: channel.quality,
            note: channel.note,
        };
    }
    async function resolveChannel(channel) {
        log("BK resolve start: " + channel.id + " (" + channel.definition + ")");
        try {
            const response = await http(upstreamRequest(channel));
            var payload;
            try {
                payload = JSON.parse(response.body);
            } catch (_) {
                throw new Error("源站未返回有效 JSON");
            }
            if (!payload || typeof payload !== "object" || Array.isArray(payload))
                throw new Error("源站响应结构不正确");
            if (
                (typeof payload.iretcode !== "number" && typeof payload.iretcode !== "string") ||
                Number(payload.iretcode) !== 0 ||
                payload.iretcode === ""
            ) {
                var code = String(payload.iretcode === undefined ? "missing" : payload.iretcode)
                    .replace(/[^a-zA-Z0-9_-]/g, "")
                    .slice(0, 24);
                throw new Error("源站拒绝解析（iretcode=" + code + "）");
            }
            var candidates = collectCandidates(payload);
            if (!candidates.length) throw new Error("源站没有返回可接受的 HTTP(S) 播放 URL");
            log("BK resolve success: " + channel.id + "; candidates=" + candidates.length + "; host=" + playbackHost(candidates[0]));
            return {
                ok: true,
                channel: publicChannel(channel),
                url: candidates[0],
                candidates: candidates,
                headers: PLAYBACK_HEADERS,
                source: "BK live",
                quality: channel.quality,
                resolvedAt: new Date().toISOString(),
            };
        } catch (error) {
            var diagnostic = sanitizedDiagnostic(error.message);
            log("BK resolve failed: " + channel.id + "; " + diagnostic);
            return {
                ok: false,
                channel: publicChannel(channel),
                url: null,
                candidates: [],
                headers: {},
                source: "BK live",
                quality: channel.quality,
                resolvedAt: new Date().toISOString(),
                error: diagnostic,
            };
        }
    }

    return {
        resolve: resolveChannel,
        testing: {
            teaBlockHex: function (block, key) {
                return toHex(teaBlock(fromHex(block), fromHex(key)));
            },
            checksumHex: function (hex) {
                return checksum(fromHex(hex));
            },
            createCKeyVector: function (channelID, timestamp, initialByte) {
                var next = initialByte;
                return createCKey(channelID, timestamp, function (count) {
                    var bytes = [];
                    for (var i = 0; i < count; i++) bytes.push(next++ & 255);
                    return bytes;
                });
            },
            isAllowedPlaybackURL: isAllowedPlaybackURL,
            collectCandidates: collectCandidates,
        },
    };
}

// ---------------------------------------------------------------------------
// ② Device 协议 —— 模拟「央视频电视投屏助手」设备，取高码率直播地址（含 4K/8K）
//    移植自 ysp-service_2.0.13.txt 的 createDeviceProtocol()。仅把 host.* 换成
//    Node 等价物：host.crypto.seal/open → AES-256-GCM（nonce||ct||tag，base64，
//    与 Python 原版 aes_gcm_encrypt_b64 / aes_gcm_decrypt_b64 同格式）；
//    host.crypto.rsaEncrypt → RSA-OAEP-SHA256；host.crypto.digest → node:crypto；
//    host.http.request → fetch；host.storage → 本地 JSON 文件；
//    host.scheduler → setInterval / setTimeout。请求体与流程未改动。
// ---------------------------------------------------------------------------

function createDeviceProtocol() {
    const AK = "9f5c54c4ed0e50109b800f7e28fec205";
    const PUBLIC_KEY =
        "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAkKeLy4ywWLSnBkwRyqYgF3HMIj05V5uuh5HjyEsZOWnu1NHu3jPQv3sr32wwQNYv5qapsNXmNgLUDHtgHZxqPQAYXltjSRc0qhcD286t62wOIHId8zXS3s1Jy4rgU4qjQWzI9rp/1sE0pMsmwTaJa4zuJ5iz8VwF8Av5oJ1k+HxY+/HLnjNlW1hmWLpuDYmkZYuAoTHa1VGeHQh9FEKI8ZcL3GTQphShUoC+Kg3P1hGUVTtCYapmzPS5lkAdwebuzwvTCfGiTErYZCnPBUSeV7BVlgjtLYIi29KvF0a8FHsJMfe/UdHcyW/RihsIYOtDQcRRpFGXyPXbVrzFJse24QIDAQAB";
    const LIVE_IDS = {
        "cctv1": "Live1717729995180256",
        "cctv2": "Live1718261577870260",
        "cctv3": "Live1718261955077261",
        "cctv4": "Live1718276148119264",
        "cctv5": "Live1719474204987287",
        "cctv5p": "Live1719473996025286",
        "cctv7": "Live1718276412224269",
        "cctv8": "Live1718276458899270",
        "cctv9": "Live1718276503187272",
        "cctv10": "Live1718276550002273",
        "cctv11": "Live1718276603690275",
        "cctv12": "Live1718276623932276",
        "cctv13": "Live1718276575708274",
        "cctv14": "Live1718276498748271",
        "cctv15": "Live1718276319614267",
        "cctv16": "Live1718276256572265",
        "cctv17": "Live1718276138318263",
        "cctv4k": "Live1767871224782105",
        "cctv8k": "Live1688400593818102",
        "cctv164k": "Live1704966749996185",
        "cgtn": "Live1719392219423280",
        "cgtnfr": "Live1719392670442283",
        "cgtnru": "Live1719392779653284",
        "cgtnar": "Live1719392885692285",
        "cgtnes": "Live1719392560433282",
        "cgtndoc": "Live1719392360336281",
    };
    const DEFAULT_TEMPLATE = {
        "source": "sony_8k_pool.XR-85Z9K",
        "brand": "Sony",
        "manufacturer": "Sony",
        "model": "XR-85Z9K",
        "report_model": "XR85Z9K",
        "hardware": "mt5895",
        "board": "mt5895",
        "version_id": "SONYTV.2022.XR_85Z9K",
        "screen_param": "7680-4320-280",
        "cast_model": "XR-85Z9K",
    };
    const BASE = "https://ytpaddr.cctv.cn/gsnw/";
    let identity,
        session = null,
        initializing = null,
        transactions = Promise.resolve(),
        lastControl = 0,
        lastAccess = 0,
        blockedUntil = 0,
        lastFailure = null,
        cloudWarning = null,
        heartbeatTimer = null;
    const responses = new WeakMap();
    const links = new Map(),
        mediaLinks = new Map();
    function fail(stage, message, code, status) {
        const e = new Error(message);
        e.stage = stage;
        e.code = code;
        if (status) e.status = status;
        return e;
    }
    function hashcode(value) {
        let h = 0;
        for (const c of value) h = (Math.imul(h, 31) + c.codePointAt(0)) | 0;
        return h;
    }
    function signedHex32(value) {
        return (value < 0 ? "ffffffff" : "00000000") + (value >>> 0).toString(16).padStart(8, "0");
    }
    function uid(p) {
        const b =
            "1698" +
            [
                "hardware",
                "board",
                "brand",
                "device",
                "manufacturer",
                "model",
                "product",
                "tags",
                "build_type",
                "user",
                "resolution",
                "mac",
            ]
                .map((k) => p[k])
                .join("");
        return sha1Hex(p.android_id + "|" + signedHex32(hashcode(b)) + signedHex32(hashcode(p.model)));
    }
    function fingerprint(x, ms) {
        const day = Math.floor((Math.floor(ms / 1000) + 28800) / 86400) * 86400000 - 28800000;
        return sha256Hex(sha256Hex(AK + x + ms + day));
    }
    function uuid() {
        return crypto.randomUUID();
    }
    function createIdentity() {
        const t = DEFAULT_TEMPLATE,
            id = (t.brand + "_" + t.model)
                .toLowerCase()
                .replace(/[^a-z0-9]+/g, "_")
                .replace(/_$/, "");
        const mac = randomHex(6).match(/../g);
        mac[0] = ((parseInt(mac[0], 16) | 2) & 254).toString(16).padStart(2, "0");
        const p = {
            android_id: randomHex(8),
            mac: mac.join(":"),
            hardware: t.hardware,
            board: t.board,
            brand: t.brand,
            device: id,
            manufacturer: t.manufacturer,
            model: t.model,
            product: id,
            tags: "release-keys",
            build_type: "user",
            user: "build",
            resolution: t.screen_param.split("-").slice(0, 2).join("*"),
            display: t.model + "-user 13 " + t.version_id + " 2024 release-keys",
            version_id: t.version_id,
            host: t.brand.toLowerCase() + "-tv-build",
            fingerprint: t.manufacturer + "/" + id + "/" + id + ":13/" + t.version_id + "/2024:user/release-keys",
            report_model: t.report_model,
        };
        return {
            schema_version: 1,
            profile: p,
            profile_source: t.source,
            screen_param: t.screen_param,
            cast_model: t.cast_model,
            cloud_guid: "",
            registered_at: 0,
        };
    }
    function keyBytes(key) {
        return Buffer.from(aesKeyBytes(key)).toString("base64");
    }
    function decrypt(value, key) {
        try {
            return aesGcmDecryptB64(value, key);
        } catch (_) {
            throw fail("decrypt", "AES-GCM authentication or encoding failed");
        }
    }
    function encrypt(value, key) {
        return aesGcmEncryptB64(value, key);
    }
    function headers(context, content = "application/json", time) {
        return {
            "Accept": "application/json",
            "Accept-Language": "zh-CN,zh;q=0.8",
            "Referer": "api.cctv.cn",
            "User-Agent": "cctv_app_tv",
            "UID": context.profile.android_id,
            appChannel: "dangbei",
            "X-Uid": context.x_uid,
            "X-Fingerprint": context.x_fingerprint,
            "X-Version": "1.4.1",
            "X-Timestamp": String(time || Date.now()),
            "X-Nonce": uuid(),
            "Content-Type": content,
            "Cache-Control": "no-cache",
        };
    }
    function common(context, sdk = "") {
        const p = context.profile;
        const v = {
            cctv_id: context.x_uid,
            device_id: p.android_id,
            idfa: "",
            idfv: "",
            user_id: "",
            app_key: "1178c84d-4818-44ff-b415-02106e87e144",
            imei: "",
            android_id: p.android_id,
            mac: p.mac,
            device_builder_type: p.build_type,
            device_hardware: p.hardware,
            device_board: p.board,
            device_brand: p.brand,
            device_params: p.device,
            device_display: p.display,
            device_version_id: p.version_id,
            device_host: p.host,
            device_product: p.product,
            device_tags: p.tags,
            device_user: p.user,
            device_fingerprint: p.fingerprint,
            device_manufacturer: p.manufacturer,
            device_model: p.report_model || p.model.replace(p.manufacturer, "").replace(/ /g, ""),
            device_resolution: p.resolution,
            system_type: "Android",
            device_type: "TV",
            app_language: "CHINESE",
            app_version: "1.4.1",
            sdk_version: sdk,
            os_version: (p.fingerprint.split(":")[1] || "").split("/")[0],
            app_channel: "dangbei",
            data_time: String(Date.now()),
        };
        const limits = {
            device_host: 128,
            device_user: 30,
            device_fingerprint: 128,
            device_model: 50,
            device_resolution: 20,
            app_version: 30,
            sdk_version: 30,
            os_version: 20,
            app_channel: 50,
            data_time: 13,
        };
        Object.keys(v).forEach((k) => (v[k] = String(v[k]).slice(0, limits[k] || 64)));
        return v;
    }
    function transaction(task) {
        const pending = transactions.then(task, task);
        transactions = pending.catch(() => { });
        return pending;
    }
    async function post(
        stage,
        url,
        body,
        extra = {},
        form = false,
        slash = false,
        cloudResponse = false,
        context = identity,
    ) {
        const wait = 2000 - (Date.now() - lastControl);
        if (lastControl && wait > 0) await sleep(wait);
        const payload = typeof body === "function" ? body() : body;
        const additional = typeof extra === "function" ? extra() : extra;
        let response;
        try {
            response = await httpRequest({
                url,
                method: "POST",
                headers: Object.assign(
                    headers(context, form ? "application/x-www-form-urlencoded" : "application/json"),
                    additional,
                ),
                body: form ? payload : stable(payload, slash),
                timeoutSeconds: 15,
            });
        } catch (_) {
            throw fail(stage, stage + " network transport failed");
        } finally {
            lastControl = Date.now();
        }
        let value;
        try {
            value = JSON.parse(response.body);
        } catch (_) { }
        const business = resultCode(value);
        if (value && typeof value === "object")
            responses.set(value, { httpStatus: response.status, businessCode: business });
        if (cloudResponse)
            log(
                "DEVICE control stage=" +
                stage +
                " HTTP=" +
                response.status +
                " business=" +
                (business ?? "none") +
                " guidPresent=" +
                !!guid(value),
            );
        const registration = cloudResponse && response.status === 400 && [0, 2, 601, 694, 695].includes(business);
        if ((response.status < 200 || response.status >= 300) && !registration) {
            const e = fail(
                stage,
                stage + " HTTP " + response.status + (business !== null ? " (business " + business + ")" : ""),
                response.status,
            );
            e.httpStatus = response.status;
            e.businessCode = business;
            e.responseType = value && typeof value === "object" ? "json" : "non-json";
            throw e;
        }
        if (!value || typeof value !== "object") throw fail(stage, stage + " returned invalid JSON");
        return value;
    }
    function resultCode(v) {
        if (!v || typeof v !== "object") return null;
        for (const k of ["result", "code", "errCode", "errcode", "ret"]) {
            const n = v[k];
            if (typeof n === "number" && Number.isInteger(n)) return n;
            if (typeof n === "string" && /^-?\d+$/.test(n)) return Number(n);
        }
        for (const k of ["data", "error", "response"]) {
            const n = resultCode(v[k]);
            if (n !== null) return n;
        }
        return null;
    }
    function cloudGateway(e) {
        return (
            ["cloud/get", "cloud/register"].includes(e.stage) &&
            [502, 503, 504].includes(e.httpStatus) &&
            e.businessCode == null
        );
    }
    function guid(v) {
        return v && v.data && typeof v.data.guid === "string" ? v.data.guid : "";
    }
    async function heartbeatCurrent() {
        const s = session;
        if (!s || Date.now() - lastAccess > 120000) return;
        const v = await post(
            "heartbeat",
            "https://ytpdata.cctv.cn/das/app/data/message/single",
            () => ({
                key: "app_heartbeat",
                value: Object.assign(common(s.identity), { network_type: "WiFi", guid: s.guid, other: "" }),
            }),
            {},
            false,
            false,
            false,
            s.identity,
        );
        const code = resultCode(v);
        if (code !== null && code !== 0) {
            session = null;
            const e = fail("heartbeat", "Heartbeat rejected", code);
            Object.assign(e, responses.get(v) || {}, { responseType: "json" });
            throw e;
        }
    }
    function heartbeat() {
        return transaction(heartbeatCurrent);
    }
    async function bootstrap() {
        const context = JSON.parse(JSON.stringify(identity)),
            savedUID = identity.x_uid;
        let time;
        context.x_uid = uid(context.profile);
        const app = await post(
            "app/start",
            BASE + "api/app/start/v1/01",
            () => {
                time = Date.now();
                context.x_fingerprint = fingerprint(context.x_uid, time);
                return { key: "app_start_d1", value: common(context) };
            },
            () => ({ UID: "", "X-Timestamp": String(time) }),
            false,
            true,
            false,
            context,
        );
        const encrypted = typeof app.data === "string" ? app.data : app.data && app.data.key;
        if (typeof encrypted !== "string") throw fail("app/start", "Missing encrypted session key", resultCode(app));
        const key = decrypt(encrypted, context.x_fingerprint.slice(0, 32));
        const savedGUID =
            savedUID === context.x_uid && typeof context.cloud_guid === "string" && context.cloud_guid.trim()
                ? context.cloud_guid
                : "";
        cloudWarning = null;
        const body = {
            device_name: "央视频电视投屏助手",
            device_id: rsaEncryptOAEP(Buffer.from(context.x_uid, "utf8").toString("base64"), PUBLIC_KEY),
        };
        let retries = 0;
        const get = async () => {
            for (; ;) {
                try {
                    return await post(
                        "cloud/get",
                        "https://ytpcloudws.cctv.cn/cloudps/wssapi/device/v2/get",
                        body,
                        {},
                        false,
                        false,
                        true,
                        context,
                    );
                } catch (e) {
                    if (!savedGUID && cloudGateway(e) && retries < 1) {
                        retries++;
                        log("DEVICE cloud/get gateway retry=1/1 HTTP=" + e.httpStatus);
                        continue;
                    }
                    throw e;
                }
            }
        };
        let value,
            cloud = "",
            code = null;
        try {
            value = await get();
            cloud = guid(value);
            code = resultCode(value);
            if (!cloud && [601, 2].includes(code)) {
                for (let i = 0; i < 2; i++) {
                    value = await post(
                        "cloud/register",
                        "https://ytpcloudws.cctv.cn/cloudps/wssapi/device/v2/register",
                        body,
                        {},
                        false,
                        false,
                        true,
                        context,
                    );
                    cloud = guid(value);
                    code = resultCode(value);
                    if (cloud || code !== 695) break;
                }
                if (!cloud && [0, 694, 2].includes(code)) {
                    value = await get();
                    cloud = guid(value);
                    code = resultCode(value);
                }
            }
        } catch (e) {
            if (!savedGUID || !cloudGateway(e)) throw e;
            cloudWarning = {
                stage: e.stage,
                httpStatus: e.httpStatus,
                businessCode: null,
                recovery: "persisted-guid",
                at: Date.now() / 1000,
            };
            log("DEVICE cloud unavailable stage=" + e.stage + " HTTP=" + e.httpStatus + " recovery=persisted-guid");
        }
        let guidSource = "cloud";
        if (!cloud && savedGUID && ([0, 2, 601, 694, 695].includes(code) || cloudWarning)) {
            cloud = savedGUID;
            guidSource = "persisted";
            log(
                "DEVICE restore guidSource=persisted " +
                (cloudWarning ? "afterHTTP=" + cloudWarning.httpStatus : "afterBusiness=" + code),
            );
        }
        if (!cloud) {
            const e = fail("cloud/register", "Device registration returned no guid", resultCode(value));
            Object.assign(e, responses.get(value) || {}, { responseType: "json" });
            throw e;
        }
        session = { key, guid: cloud, created: Date.now(), identity: context, guidSource };
        await heartbeatCurrent();
        identity.x_uid = context.x_uid;
        identity.cloud_guid = cloud;
        identity.registered_at = identity.registered_at || Math.floor(Date.now() / 1000);
        persist();
        blockedUntil = 0;
        lastFailure = null;
        log("DEVICE session ready guidSource=" + guidSource);
        return session;
    }
    function rememberFailure(e) {
        lastFailure = {
            stage: e.stage || "device",
            code: e.code ?? null,
            httpStatus: e.httpStatus ?? null,
            businessCode: e.businessCode ?? null,
            responseType: e.responseType || null,
            at: Date.now() / 1000,
            retryAt: blockedUntil / 1000,
        };
    }
    async function ensure() {
        lastAccess = Date.now();
        if (initializing) return initializing;
        if (session && Date.now() - session.created < 7200000) return session;
        if (Date.now() < blockedUntil) {
            const reason = lastFailure
                ? " after " +
                lastFailure.stage +
                (lastFailure.businessCode !== null ? " (business " + lastFailure.businessCode + ")" : "")
                : "";
            const e = fail("device/cooldown", "Device initialization is cooling down" + reason);
            e.retryAt = blockedUntil / 1000;
            throw e;
        }
        initializing = bootstrap()
            .catch((e) => {
                session = null;
                blockedUntil = Date.now() + 30000;
                rememberFailure(e);
                throw e;
            })
            .finally(() => {
                initializing = null;
            });
        return initializing;
    }
    function form(value) {
        return Object.keys(value)
            .map(
                (k) =>
                    encodeURIComponent(k) +
                    "=" +
                    encodeURIComponent(value[k])
                        .replace(/%20/g, "+")
                        .replace(/[!'()*]/g, (c) => "%" + c.charCodeAt(0).toString(16).toUpperCase()),
            )
            .join("&");
    }
    function resolve(channel, rate = "36p") {
        return transaction(() => resolveCurrent(channel, rate));
    }
    async function resolveCurrent(channel, rate) {
        if (!LIVE_IDS[channel.id]) throw fail("device/channel", "Device route unavailable for this channel", null, 422);
        lastAccess = Date.now();
        for (const [key, time] of links)
            if (
                lastAccess - time > 15000 &&
                !Array.from(mediaLinks.values()).some((v) => v.channelID === key && lastAccess - v.at < 120000)
            )
                links.delete(key);
        if (!links.has(channel.id) && links.size >= 6) throw fail("device/quota", "Device link quota reached");
        const s = await ensure();
        try {
            const one = await post(
                "live/01",
                BASE + "api/live/v1/01",
                {
                    screenParam: s.identity.screen_param,
                    rate: "",
                    systemType: "ios",
                    model: s.identity.cast_model,
                    id: LIVE_IDS[channel.id],
                    userId: "BAEBFF2B-C516-4F34-ABC0-A824A6461CBD",
                    clientSign: "cctvVideo",
                    deviceId: { serial: "", imei: "", android_id: "" },
                },
                {},
                false,
                false,
                false,
                s.identity,
            );
            const videos = one.data && (one.data.videoList || one.data.videos);
            if (!Array.isArray(videos)) throw fail("live/01", "Missing videos", resultCode(one));
            const candidates = videos.filter((v) => v && typeof v.url === "string" && v.url);
            const video = candidates.find((v) => v.rate === rate) || candidates[0];
            if (!video) throw fail("live/01", "No usable video URL");
            const safeRate = (v) => (/^\d+p$/.test(v || "") ? v : "other");
            log(
                "DEVICE live channel=" +
                channel.id +
                " selectedRate=" +
                safeRate(video.rate) +
                " availableRates=" +
                candidates.map((v) => safeRate(v.rate)).join(","),
            );
            const raw = /^https?:\/\//.test(video.url) ? video.url : decrypt(video.url, s.key);
            const two = await post(
                "live/02",
                BASE + "api/live/v1/02",
                { guid: encrypt("", s.key) },
                {},
                false,
                false,
                false,
                s.identity,
            );
            const secretValue =
                typeof two.data === "string" ? two.data : two.data && (two.data.appSecret || two.data.app_secret);
            if (typeof secretValue !== "string") throw fail("live/02", "Missing appSecret", resultCode(two));
            const secret = decrypt(secretValue, s.key);
            const random = randomHex(4) + "-0000-" + randomHex(2) + "-0000-00000000" + randomHex(2);
            const sign = md5Hex(AK + secret + random);
            const vdn = await post(
                "VDN",
                "https://ytpvdn.cctv.cn/cctvmobileinf/rest/cctv/videoliveUrl/getstream",
                form({
                    appcommon: stable({ adid: "", av: "1.4.1", an: "央视频电视投屏助手", ap: "cctv_app_tv" }),
                    url: raw,
                }),
                { APPID: AK, APPSIGN: sign, APPRANDOMSTR: random },
                true,
                false,
                false,
                s.identity,
            );
            if (
                String(vdn.succeed).replace(/"/g, "") !== "1" ||
                typeof vdn.url !== "string" ||
                !/^https?:\/\//.test(vdn.url)
            )
                throw fail("VDN", "VDN returned no final URL", resultCode(vdn));
            links.set(channel.id, Date.now());
            return {
                url: vdn.url,
                headers: {
                    UID: s.identity.profile.android_id,
                    APPID: AK,
                    APPSIGN: sign,
                    APPRANDOMSTR: random,
                    Referer: "api.cctv.cn",
                    "User-Agent": "cctv_app_tv",
                },
                source: "device",
                rate: video.rate || "",
                quality: video.rateName || video.rate || "未验证",
                expiresAt: Date.now() / 1000 + 60,
                candidates: [vdn.url],
                resolutionVerified: false,
            };
        } catch (e) {
            if (e.stage === "decrypt" || [400, 401, 403].includes(e.code)) {
                session = null;
                blockedUntil = Date.now() + 5000;
            }
            rememberFailure(e);
            throw e;
        }
    }
    function mediaActivity(event) {
        if (event.kind === "closed") {
            mediaLinks.delete(event.sessionID);
            return;
        }
        if (event.kind !== "activity") return;
        const now = Date.now();
        for (const [id, value] of mediaLinks) if (now - value.at >= 120000) mediaLinks.delete(id);
        mediaLinks.set(event.sessionID, { channelID: event.channelID, at: now });
        lastAccess = now;
        links.set(event.channelID, now);
    }
    function persist() {
        const value = Object.assign({}, identity);
        delete value.x_fingerprint;
        storeSet("identity", value);
    }
    function start() {
        identity = storeGet("identity");
        if (identity) delete identity.x_fingerprint;
        if (
            !identity ||
            !identity.profile ||
            !/^[a-f0-9]{16}$/i.test(identity.profile.android_id || "") ||
            !identity.profile.mac
        ) {
            identity = createIdentity();
            storeSet("identity", identity);
        }
        if (!heartbeatTimer) {
            heartbeatTimer = setInterval(() => {
                heartbeat().catch((e) => {
                    debugLog("heartbeat failed: " + (e && e.message ? e.message : e));
                });
            }, 30000);
            if (typeof heartbeatTimer.unref === "function") heartbeatTimer.unref();
        }
    }
    return {
        start,
        resolve,
        mediaActivity,
        liveIDs: LIVE_IDS,
        heartbeat,
        status: () => ({
            sessionActive: !!session,
            linkedChannels: links.size,
            guidSource: session ? session.guidSource : null,
            cooldown: Math.max(0, blockedUntil - Date.now()),
            lastFailure,
            cloudWarning,
        }),
        stop: () => {
            if (heartbeatTimer) {
                clearInterval(heartbeatTimer);
                heartbeatTimer = null;
            }
            persist();
            session = null;
            links.clear();
            mediaLinks.clear();
        },
        testing: {
            stable,
            hashcode,
            uid,
            fingerprint,
            keyBytes,
            resultCode,
            createIdentity,
            common,
            publicKey: PUBLIC_KEY,
        },
    };
}

// ---------------------------------------------------------------------------
// ③ JCE 协议 —— JCE/QMF 二进制协议请求回看与直播窗口
//    移植自 ysp-service_2.0.13.txt 的 createJCEProtocol()。仅把 host.crypto
//    gzip/gunzip 换成 node:zlib，把 host.http.request 的 base64 体换成 fetch +
//    Buffer，把 host.storage / host.scheduler 换成本地存储与 setTimeout。
//    编解码（W/R、qua、wrap/unwrap）与请求参数未改动。
// ---------------------------------------------------------------------------

function createJCEProtocol() {
    let guid,
        flow = Promise.resolve(),
        lastRequestAt = -Infinity;
    function be(value, n) {
        const out = [];
        for (let i = n - 1; i >= 0; i--) out.push(Math.floor(value / Math.pow(256, i)) & 255);
        return out;
    }
    function W() {
        this.b = [];
    }
    W.prototype.head = function (type, tag) {
        this.b.push(tag < 15 ? (tag << 4) | type : 240 | type);
        if (tag >= 15) this.b.push(tag);
    };
    W.prototype.number = function (v, tag) {
        if (!Number.isSafeInteger(v)) throw new Error("JCE integer outside safe range");
        if (v === 0) {
            this.head(12, tag);
            return;
        }
        const n =
            v >= -128 && v <= 127 ? 1 : v >= -32768 && v <= 32767 ? 2 : v >= -2147483648 && v <= 2147483647 ? 4 : 8;
        this.head({ 1: 0, 2: 1, 4: 2, 8: 3 }[n], tag);
        this.b.push(...be(v, n));
    };
    function utf8(s) {
        const text = unescape(encodeURIComponent(s));
        return Array.from(text, (c) => c.charCodeAt(0));
    }
    function text(b) {
        return decodeURIComponent(escape(String.fromCharCode(...b)));
    }
    W.prototype.string = function (value, tag) {
        const b = utf8(value);
        this.head(b.length > 255 ? 7 : 6, tag);
        this.b.push(...be(b.length, b.length > 255 ? 4 : 1), ...b);
    };
    W.prototype.bytes = function (b, tag) {
        this.head(13, tag);
        this.head(0, 0);
        this.number(b.length, 0);
        this.b.push(...b);
    };
    W.prototype.struct = function (fn, tag) {
        this.head(10, tag);
        fn(this);
        this.head(11, 0);
    };
    function R(bytes) {
        this.b = bytes;
        this.p = 0;
    }
    R.prototype.get = function (n) {
        if (!Number.isInteger(n) || n < 0 || n > 2097152 || this.p + n > this.b.length)
            throw new Error("Truncated JCE");
        const out = this.b.slice(this.p, this.p + n);
        this.p += n;
        return out;
    };
    R.prototype.num = function (n, signed) {
        const a = this.get(n);
        let v = signed && a[0] & 128 ? -1 : 0;
        for (const c of a) v = v * 256 + c;
        if (!Number.isSafeInteger(v)) throw new Error("JCE integer outside safe range");
        return v;
    };
    R.prototype.head = function () {
        const b = this.num(1, false);
        return [b & 15, b >> 4 === 15 ? this.num(1, false) : b >> 4];
    };
    R.prototype.field = function (depth) {
        const [t] = this.head();
        return this.value(t, depth + 1);
    };
    R.prototype.value = function (t, depth) {
        if (depth > 32) throw new Error("JCE nesting limit");
        if (t <= 3) return this.num([1, 2, 4, 8][t], true);
        if (t === 4 || t === 5) {
            const b = this.get(t === 4 ? 4 : 8);
            const dv = new DataView(new Uint8Array(b).buffer);
            return t === 4 ? dv.getFloat32(0) : dv.getFloat64(0);
        }
        if (t === 6 || t === 7) {
            const b = this.get(this.num(t === 6 ? 1 : 4, false));
            if (b.length > 65536) throw new Error("JCE string limit");
            return text(b);
        }
        if (t === 8 || t === 9) {
            const n = this.field(depth);
            if (!Number.isInteger(n) || n < 0 || n > 4096) throw new Error("JCE collection limit");
            const out = t === 9 ? [] : {};
            for (let i = 0; i < n; i++) {
                if (t === 9) out.push(this.field(depth));
                else {
                    const k = this.field(depth);
                    out[k] = this.field(depth);
                }
            }
            return out;
        }
        if (t === 10) return this.struct(depth + 1);
        if (t === 12) return 0;
        if (t === 13) {
            const [sub] = this.head();
            if (sub !== 0) throw new Error("Invalid JCE byte array");
            return this.get(this.field(depth));
        }
        throw new Error("Unsupported JCE type " + t);
    };
    R.prototype.struct = function (depth = 0) {
        if (depth > 32) throw new Error("JCE nesting limit");
        const out = {};
        while (this.p < this.b.length) {
            const [t, tag] = this.head();
            if (t === 11) return out;
            out[tag] = this.value(t, depth + 1);
        }
        return out;
    };
    function qua(w, id) {
        w.string("3.2.7.26212", 0);
        w.string("302070", 1);
        [1080, 2400, 3].forEach((v, i) => w.number(v, i + 2));
        w.string("12", 5);
        w.number(1, 6);
        w.number(1, 7);
        w.number(420, 8);
        w.string("10070", 9);
        for (let i = 10; i < 15; i++) w.string("", i);
        w.struct((s) => {
            s.number(0, 0);
            s.number(0, 1);
            s.string("", 2);
        }, 15);
        for (let i = 16; i < 19; i++) w.string("", i);
        w.struct((s) => {
            s.number(0, 0);
            s.head(4, 1);
            s.b.push(0, 0, 0, 0);
            s.head(4, 2);
            s.b.push(0, 0, 0, 0);
            s.head(5, 3);
            s.b.push(0, 0, 0, 0, 0, 0, 0, 0);
        }, 19);
        w.string(id.slice(0, 16), 20);
        w.string("Pixel 6", 21);
        w.number(1, 22);
        for (let i = 23; i < 27; i++) w.number(0, i);
        w.string("", 27);
        w.string("", 28);
        w.string(id, 29);
    }
    function toBase64(bytes) {
        return Buffer.from(bytes).toString("base64");
    }
    function fromBase64(value) {
        return Array.from(Buffer.from(String(value), "base64"));
    }
    function wrap(body, id, reqid) {
        const w = new W();
        w.struct((s) => {
            s.number(reqid, 0);
            s.number(25312, 1);
            s.struct((v) => qua(v, id), 2);
            s.string("1200013", 3);
            s.string(id, 4);
            s.head(9, 5);
            s.number(0, 0);
            s.struct(() => { }, 6);
            s.head(9, 7);
            s.number(0, 0);
            [8, 9, 10].forEach((t) => s.number(0, t));
        }, 0);
        w.bytes(body, 1);
        const inner = [38, ...be(w.b.length + 17, 4), 1, ...Array(10).fill(0), ...w.b, 40];
        const compressed = Array.from(zlib.gzipSync(Buffer.from(inner)));
        // prettier-ignore
        const out = [
            19, 0, 0, 0, 0, ...be(2, 2), ...be(65281, 2), ...be(25312, 2), 0, 0, ...be(reqid, 8), ...be(531, 4),
            ...be(10012, 4), ...Array(8).fill(0), ...utf8(id), 1, ...be(302070, 4), ...Array(6).fill(0), 0, 0,
            0, 0, 0, ...be(inner.length, 4), ...compressed, 3,
        ];
        out.splice(1, 4, ...be(out.length, 4));
        return out;
    }
    function unwrap(bytes) {
        if (bytes.length < 90 || bytes[0] !== 19 || bytes[bytes.length - 1] !== 3)
            throw new Error("Invalid QMF response");
        const length = new R(bytes.slice(1, 5)).num(4, false);
        if (length !== bytes.length) throw new Error("QMF length mismatch");
        const flags = new R(bytes.slice(21, 25)).num(4, false);
        let payload = bytes.slice(89, -1);
        if (flags & 2) payload = Array.from(zlib.gunzipSync(Buffer.from(payload)));
        if (payload[0] !== 38 || payload[payload.length - 1] !== 40) throw new Error("Invalid QMF inner payload");
        const root = new R(payload.slice(16, -1)).struct();
        if (!Array.isArray(root[1])) throw new Error("Missing JCE body");
        return new R(root[1]).struct();
    }
    async function request(channel, start, end) {
        const w = new W();
        w.string(channel.livePID, 0);
        w.string(channel.channelID, 1);
        w.number(start, 2);
        w.number(end, 3);
        w.string(channel.definition || "fhd", 4);
        const packet = wrap(w.b, guid, Date.now() & 2147483647);
        const response = await httpBinary({
            url: "https://jacc.ysp.cctv.cn",
            method: "POST",
            headers: { "Content-Type": "application/octet-stream" },
            body: Buffer.from(toBase64(packet), "base64"),
            timeoutSeconds: 15,
        });
        if (response.status < 200 || response.status >= 300) throw new Error("JCE HTTP " + response.status);
        const value = unwrap(fromBase64(response.body));
        if (value[0] !== undefined && value[0] !== 0) throw new Error("JCE business code " + value[0]);
        const url = value[2];
        if (typeof url !== "string" || !/^https?:\/\//.test(url)) throw new Error("JCE returned no manifest");
        if (/^https?:\/\/liverecord\.video\.cloud\.cctv\.com(?:[/:]|$)/i.test(url))
            throw new Error("JCE returned an unavailable CDN host");
        return {
            url,
            candidates: [url],
            headers: { "User-Agent": "Mozilla/5.0" },
            source: "JCE",
            quality: channel.definition || "fhd",
            expiresAt: Date.now() / 1000 + 60,
            resolutionVerified: false,
        };
    }
    function resolve(channel, start, end) {
        const task = flow.then(async () => {
            const wait = 700 + Math.floor(Math.random() * 100) - (Date.now() - lastRequestAt);
            if (wait > 0) await sleep(wait);
            try {
                return await request(channel, start, end);
            } finally {
                lastRequestAt = Date.now();
            }
        });
        flow = task.then(
            () => undefined,
            () => undefined,
        );
        return task;
    }
    return {
        start: () => {
            guid = storeGet("jce-guid");
            if (typeof guid !== "string" || !/^[0-9a-f]{32}$/.test(guid)) {
                guid = randomHex(16);
                storeSet("jce-guid", guid);
            }
        },
        resolve,
        testing: { W, R, wrap, unwrap, toBase64, fromBase64 },
    };
}
    // ---- 频道表：64 个频道（央视 30 + 卫视 34），channelID / livePID 是 BK 与 JCE 请求用的上游编号 ----
    // 数据来源：ysp-service_2.0.13.txt 的 createChannelTable()，逐字提取，未改动任何编号。
    const CHANNELS = [
        {
            id: "cctv1",
            name: "CCTV-1 综合",
            group: "央视",
            channelID: "2024078201",
            livePID: "600001859",
            definition: "fhd",
            tvgID: "CCTV1",
            logo: "https://garysclub.sharewithyou.dpdns.org/logos/ysp-live-logos/cctv1.png",
            quality: "1080p候选",
            note: "",
        },
        {
            id: "cctv2",
            name: "CCTV-2 财经",
            group: "央视",
            channelID: "2024075401",
            livePID: "600001800",
            definition: "fhd",
            tvgID: "CCTV2",
            logo: "https://garysclub.sharewithyou.dpdns.org/logos/ysp-live-logos/cctv2.png",
            quality: "1080p候选",
            note: "",
        },
        {
            id: "cctv3",
            name: "CCTV-3 综艺",
            group: "央视",
            channelID: "2024068501",
            livePID: "600001801",
            definition: "fhd",
            tvgID: "CCTV3",
            logo: "https://garysclub.sharewithyou.dpdns.org/logos/ysp-live-logos/cctv3.png",
            quality: "1080p候选",
            note: "",
        },
        {
            id: "cctv4",
            name: "CCTV-4 中文国际",
            group: "央视",
            channelID: "2029797101",
            livePID: "600001814",
            definition: "fhd",
            tvgID: "CCTV4",
            logo: "https://garysclub.sharewithyou.dpdns.org/logos/ysp-live-logos/cctv4.png",
            quality: "1080p候选",
            note: "",
        },
        {
            id: "cctv5",
            name: "CCTV-5 体育",
            group: "央视",
            channelID: "2024078401",
            livePID: "600001818",
            definition: "fhd",
            tvgID: "CCTV5",
            logo: "https://garysclub.sharewithyou.dpdns.org/logos/ysp-live-logos/cctv5.png",
            quality: "1080p候选",
            note: "",
        },
        {
            id: "cctv5p",
            name: "CCTV-5+ 体育赛事",
            group: "央视",
            channelID: "2024078001",
            livePID: "600001817",
            definition: "fhd",
            tvgID: "CCTV5+",
            logo: "https://garysclub.sharewithyou.dpdns.org/logos/ysp-live-logos/cctv5p.png",
            quality: "1080p候选",
            note: "",
        },
        {
            id: "cctv6",
            name: "CCTV-6 电影",
            group: "央视",
            channelID: "2013693901",
            livePID: "600108442",
            definition: "fhd",
            tvgID: "CCTV6",
            logo: "https://garysclub.sharewithyou.dpdns.org/logos/ysp-live-logos/cctv6.png",
            quality: "1080p候选",
            note: "",
        },
        {
            id: "cctv7",
            name: "CCTV-7 国防军事",
            group: "央视",
            channelID: "2024072001",
            livePID: "600004092",
            definition: "fhd",
            tvgID: "CCTV7",
            logo: "https://garysclub.sharewithyou.dpdns.org/logos/ysp-live-logos/cctv7.png",
            quality: "1080p候选",
            note: "",
        },
        {
            id: "cctv8",
            name: "CCTV-8 电视剧",
            group: "央视",
            channelID: "2029793001",
            livePID: "600001803",
            definition: "fhd",
            tvgID: "CCTV8",
            logo: "https://garysclub.sharewithyou.dpdns.org/logos/ysp-live-logos/cctv8.png",
            quality: "1080p候选",
            note: "",
        },
        {
            id: "cctv9",
            name: "CCTV-9 纪录",
            group: "央视",
            channelID: "2024078601",
            livePID: "600004078",
            definition: "fhd",
            tvgID: "CCTV9",
            logo: "https://garysclub.sharewithyou.dpdns.org/logos/ysp-live-logos/cctv9.png",
            quality: "1080p候选",
            note: "",
        },
        {
            id: "cctv10",
            name: "CCTV-10 科教",
            group: "央视",
            channelID: "2024078701",
            livePID: "600001805",
            definition: "fhd",
            tvgID: "CCTV10",
            logo: "https://garysclub.sharewithyou.dpdns.org/logos/ysp-live-logos/cctv10.png",
            quality: "1080p候选",
            note: "",
        },
        {
            id: "cctv11",
            name: "CCTV-11 戏曲",
            group: "央视",
            channelID: "2027248701",
            livePID: "600001806",
            definition: "fhd",
            tvgID: "CCTV11",
            logo: "https://garysclub.sharewithyou.dpdns.org/logos/ysp-live-logos/cctv11.png",
            quality: "1080p候选",
            note: "",
        },
        {
            id: "cctv12",
            name: "CCTV-12 社会与法",
            group: "央视",
            channelID: "2027248801",
            livePID: "600001807",
            definition: "fhd",
            tvgID: "CCTV12",
            logo: "https://garysclub.sharewithyou.dpdns.org/logos/ysp-live-logos/cctv12.png",
            quality: "1080p候选",
            note: "",
        },
        {
            id: "cctv13",
            name: "CCTV-13 新闻",
            group: "央视",
            channelID: "2029797201",
            livePID: "600001811",
            definition: "fhd",
            tvgID: "CCTV13",
            logo: "https://garysclub.sharewithyou.dpdns.org/logos/ysp-live-logos/cctv13.png",
            quality: "1080p候选",
            note: "",
        },
        {
            id: "cctv14",
            name: "CCTV-14 少儿",
            group: "央视",
            channelID: "2027248901",
            livePID: "600001809",
            definition: "fhd",
            tvgID: "CCTV14",
            logo: "https://garysclub.sharewithyou.dpdns.org/logos/ysp-live-logos/cctv14.png",
            quality: "1080p候选",
            note: "",
        },
        {
            id: "cctv15",
            name: "CCTV-15 音乐",
            group: "央视",
            channelID: "2027249001",
            livePID: "600001815",
            definition: "fhd",
            tvgID: "CCTV15",
            logo: "https://garysclub.sharewithyou.dpdns.org/logos/ysp-live-logos/cctv15.png",
            quality: "1080p候选",
            note: "",
        },
        {
            id: "cctv16",
            name: "CCTV-16 奥林匹克",
            group: "央视",
            channelID: "2027249101",
            livePID: "600098637",
            definition: "fhd",
            tvgID: "CCTV16",
            logo: "https://garysclub.sharewithyou.dpdns.org/logos/ysp-live-logos/cctv16.png",
            quality: "1080p候选",
            note: "",
        },
        {
            id: "cctv164k",
            name: "CCTV-16 4K",
            group: "央视",
            channelID: "2027249301",
            livePID: "600099502",
            definition: "fhd",
            tvgID: "CCTV16",
            logo: "https://garysclub.sharewithyou.dpdns.org/logos/ysp-live-logos/cctv164k.png",
            quality: "1080p候选",
            note: "频道名称不代表本原型可提供4K/8K；仅尝试BK live回退链路。",
        },
        {
            id: "cctv17",
            name: "CCTV-17 农业农村",
            group: "央视",
            channelID: "2027249401",
            livePID: "600001810",
            definition: "fhd",
            tvgID: "CCTV17",
            logo: "https://garysclub.sharewithyou.dpdns.org/logos/ysp-live-logos/cctv17.png",
            quality: "1080p候选",
            note: "",
        },
        {
            id: "cctv4k",
            name: "CCTV-4K 超高清",
            group: "央视",
            channelID: "2029810301",
            livePID: "600002264",
            definition: "fhd",
            tvgID: "CCTV4K",
            logo: "https://garysclub.sharewithyou.dpdns.org/logos/ysp-live-logos/cctv4k.png",
            quality: "1080p候选",
            note: "频道名称不代表本原型可提供4K/8K；仅尝试BK live回退链路。",
        },
        {
            id: "cctv8k",
            name: "CCTV-8K 超高清",
            group: "央视",
            channelID: "2026774101",
            livePID: "600156816",
            definition: "fhd",
            tvgID: "CCTV-8K",
            logo: "https://garysclub.sharewithyou.dpdns.org/logos/ysp-live-logos/cctv8k.png",
            quality: "1080p候选",
            note: "频道名称不代表本原型可提供4K/8K；仅尝试BK live回退链路。",
        },
        {
            id: "cgtn",
            name: "CGTN",
            group: "央视",
            channelID: "2024181701",
            livePID: "600014550",
            definition: "fhd",
            tvgID: "CGTN英语",
            logo: "https://garysclub.sharewithyou.dpdns.org/logos/ysp-live-logos/cgtn.png",
            quality: "1080p候选",
            note: "",
        },
        {
            id: "cgtnfr",
            name: "CGTN 法语",
            group: "央视",
            channelID: "2024181801",
            livePID: "600084704",
            definition: "fhd",
            tvgID: "CGTN法语",
            logo: "https://garysclub.sharewithyou.dpdns.org/logos/ysp-live-logos/cgtnfr.png",
            quality: "1080p候选",
            note: "",
        },
        {
            id: "cgtnru",
            name: "CGTN 俄语",
            group: "央视",
            channelID: "2024181901",
            livePID: "600084758",
            definition: "fhd",
            tvgID: "CGTN俄语",
            logo: "https://garysclub.sharewithyou.dpdns.org/logos/ysp-live-logos/cgtnru.png",
            quality: "1080p候选",
            note: "",
        },
        {
            id: "cgtnar",
            name: "CGTN 阿拉伯语",
            group: "央视",
            channelID: "2024182001",
            livePID: "600084782",
            definition: "fhd",
            tvgID: "CGTN阿语",
            logo: "https://garysclub.sharewithyou.dpdns.org/logos/ysp-live-logos/cgtnar.png",
            quality: "1080p候选",
            note: "",
        },
        {
            id: "cgtnes",
            name: "CGTN 西班牙语",
            group: "央视",
            channelID: "2024182101",
            livePID: "600084744",
            definition: "fhd",
            tvgID: "CGTN西语",
            logo: "https://garysclub.sharewithyou.dpdns.org/logos/ysp-live-logos/cgtnes.png",
            quality: "1080p候选",
            note: "",
        },
        {
            id: "cgtndoc",
            name: "CGTN 纪录",
            group: "央视",
            channelID: "2024182301",
            livePID: "600084781",
            definition: "fhd",
            tvgID: "CGTN纪录",
            logo: "https://garysclub.sharewithyou.dpdns.org/logos/ysp-live-logos/cgtndoc.png",
            quality: "1080p候选",
            note: "",
        },
        {
            id: "cctvfyjc",
            name: "CCTV 风云剧场",
            group: "央视",
            channelID: "2025637102",
            livePID: "600099658",
            definition: "shd",
            tvgID: "CCTV风云剧场",
            logo: "https://garysclub.sharewithyou.dpdns.org/logos/ysp-live-logos/cctvfyjc.png",
            quality: "720p候选",
            note: "",
        },
        {
            id: "cctvdyjc",
            name: "CCTV 第一剧场",
            group: "央视",
            channelID: "2026874202",
            livePID: "600099655",
            definition: "shd",
            tvgID: "CCTV第一剧场",
            logo: "https://garysclub.sharewithyou.dpdns.org/logos/ysp-live-logos/cctvdyjc.png",
            quality: "720p候选",
            note: "",
        },
        {
            id: "cctvhjjc",
            name: "CCTV 怀旧剧场",
            group: "央视",
            channelID: "2026874302",
            livePID: "600099620",
            definition: "shd",
            tvgID: "CCTV怀旧剧场",
            logo: "https://garysclub.sharewithyou.dpdns.org/logos/ysp-live-logos/cctvhjjc.png",
            quality: "720p候选",
            note: "",
        },
        {
            id: "bjws",
            name: "北京卫视",
            group: "卫视",
            channelID: "2024052703",
            livePID: "600002309",
            definition: "fhd",
            tvgID: "北京卫视",
            logo: "https://garysclub.sharewithyou.dpdns.org/logos/ysp-live-logos/bjws.png",
            quality: "1080p候选",
            note: "",
        },
        {
            id: "jsws",
            name: "江苏卫视",
            group: "卫视",
            channelID: "2024171103",
            livePID: "600002521",
            definition: "fhd",
            tvgID: "江苏卫视",
            logo: "https://garysclub.sharewithyou.dpdns.org/logos/ysp-live-logos/jsws.png",
            quality: "1080p候选",
            note: "",
        },
        {
            id: "dfws",
            name: "东方卫视",
            group: "卫视",
            channelID: "2024054503",
            livePID: "600002483",
            definition: "fhd",
            tvgID: "东方卫视",
            logo: "https://garysclub.sharewithyou.dpdns.org/logos/ysp-live-logos/dfws.png",
            quality: "1080p候选",
            note: "",
        },
        {
            id: "zjws",
            name: "浙江卫视",
            group: "卫视",
            channelID: "2024054703",
            livePID: "600002520",
            definition: "fhd",
            tvgID: "浙江卫视",
            logo: "https://garysclub.sharewithyou.dpdns.org/logos/ysp-live-logos/zjws.png",
            quality: "1080p候选",
            note: "",
        },
        {
            id: "hnws",
            name: "湖南卫视",
            group: "卫视",
            channelID: "2024054803",
            livePID: "600002475",
            definition: "fhd",
            tvgID: "湖南卫视",
            logo: "https://garysclub.sharewithyou.dpdns.org/logos/ysp-live-logos/hnws.png",
            quality: "1080p候选",
            note: "",
        },
        {
            id: "hbws",
            name: "湖北卫视",
            group: "卫视",
            channelID: "2024171203",
            livePID: "600002508",
            definition: "fhd",
            tvgID: "湖北卫视",
            logo: "https://garysclub.sharewithyou.dpdns.org/logos/ysp-live-logos/hbws.png",
            quality: "1080p候选",
            note: "",
        },
        {
            id: "gdws",
            name: "广东卫视",
            group: "卫视",
            channelID: "2024060903",
            livePID: "600002485",
            definition: "fhd",
            tvgID: "广东卫视",
            logo: "https://garysclub.sharewithyou.dpdns.org/logos/ysp-live-logos/gdws.png",
            quality: "1080p候选",
            note: "",
        },
        {
            id: "gxws",
            name: "广西卫视",
            group: "卫视",
            channelID: "2024060703",
            livePID: "600002509",
            definition: "fhd",
            tvgID: "广西卫视",
            logo: "https://garysclub.sharewithyou.dpdns.org/logos/ysp-live-logos/gxws.png",
            quality: "1080p候选",
            note: "",
        },
        {
            id: "hljws",
            name: "黑龙江卫视",
            group: "卫视",
            channelID: "2029797003",
            livePID: "600002498",
            definition: "fhd",
            tvgID: "黑龙江卫视",
            logo: "https://garysclub.sharewithyou.dpdns.org/logos/ysp-live-logos/hljws.png",
            quality: "1080p候选",
            note: "",
        },
        {
            id: "hainanws",
            name: "海南卫视",
            group: "卫视",
            channelID: "2024055603",
            livePID: "600002506",
            definition: "fhd",
            tvgID: "海南卫视",
            logo: "https://garysclub.sharewithyou.dpdns.org/logos/ysp-live-logos/hainanws.png",
            quality: "1080p候选",
            note: "",
        },
        {
            id: "cqws",
            name: "重庆卫视",
            group: "卫视",
            channelID: "2024061103",
            livePID: "600002531",
            definition: "fhd",
            tvgID: "重庆卫视",
            logo: "https://garysclub.sharewithyou.dpdns.org/logos/ysp-live-logos/cqws.png",
            quality: "1080p候选",
            note: "",
        },
        {
            id: "szws",
            name: "深圳卫视",
            group: "卫视",
            channelID: "2024061303",
            livePID: "600002481",
            definition: "fhd",
            tvgID: "深圳卫视",
            logo: "https://garysclub.sharewithyou.dpdns.org/logos/ysp-live-logos/szws.png",
            quality: "1080p候选",
            note: "",
        },
        {
            id: "scws",
            name: "四川卫视",
            group: "卫视",
            channelID: "2024061403",
            livePID: "600002516",
            definition: "fhd",
            tvgID: "四川卫视",
            logo: "https://garysclub.sharewithyou.dpdns.org/logos/ysp-live-logos/scws.png",
            quality: "1080p候选",
            note: "",
        },
        {
            id: "henanws",
            name: "河南卫视",
            group: "卫视",
            channelID: "2029797303",
            livePID: "600002525",
            definition: "fhd",
            tvgID: "河南卫视",
            logo: "https://garysclub.sharewithyou.dpdns.org/logos/ysp-live-logos/henanws.png",
            quality: "1080p候选",
            note: "",
        },
        {
            id: "dnws",
            name: "东南卫视",
            group: "卫视",
            channelID: "2024061503",
            livePID: "600002484",
            definition: "fhd",
            tvgID: "东南卫视",
            logo: "https://garysclub.sharewithyou.dpdns.org/logos/ysp-live-logos/dnws.png",
            quality: "1080p候选",
            note: "",
        },
        {
            id: "gzws",
            name: "贵州卫视",
            group: "卫视",
            channelID: "2024061603",
            livePID: "600002490",
            definition: "fhd",
            tvgID: "贵州卫视",
            logo: "https://garysclub.sharewithyou.dpdns.org/logos/ysp-live-logos/gzws.png",
            quality: "1080p候选",
            note: "",
        },
        {
            id: "jxws",
            name: "江西卫视",
            group: "卫视",
            channelID: "2024061703",
            livePID: "600002503",
            definition: "fhd",
            tvgID: "江西卫视",
            logo: "https://garysclub.sharewithyou.dpdns.org/logos/ysp-live-logos/jxws.png",
            quality: "1080p候选",
            note: "",
        },
        {
            id: "lnws",
            name: "辽宁卫视",
            group: "卫视",
            channelID: "2024171303",
            livePID: "600002505",
            definition: "fhd",
            tvgID: "辽宁卫视",
            logo: "https://garysclub.sharewithyou.dpdns.org/logos/ysp-live-logos/lnws.png",
            quality: "1080p候选",
            note: "",
        },
        {
            id: "ahws",
            name: "安徽卫视",
            group: "卫视",
            channelID: "2024171403",
            livePID: "600002532",
            definition: "fhd",
            tvgID: "安徽卫视",
            logo: "https://garysclub.sharewithyou.dpdns.org/logos/ysp-live-logos/ahws.png",
            quality: "1080p候选",
            note: "",
        },
        {
            id: "hebws",
            name: "河北卫视",
            group: "卫视",
            channelID: "2024171503",
            livePID: "600002493",
            definition: "fhd",
            tvgID: "河北卫视",
            logo: "https://garysclub.sharewithyou.dpdns.org/logos/ysp-live-logos/hebws.png",
            quality: "1080p候选",
            note: "",
        },
        {
            id: "sdws",
            name: "山东卫视",
            group: "卫视",
            channelID: "2029787903",
            livePID: "600002513",
            definition: "fhd",
            tvgID: "山东卫视",
            logo: "https://garysclub.sharewithyou.dpdns.org/logos/ysp-live-logos/sdws.png",
            quality: "1080p候选",
            note: "",
        },
        {
            id: "tjws",
            name: "天津卫视",
            group: "卫视",
            channelID: "2019927003",
            livePID: "600152137",
            definition: "fhd",
            tvgID: "天津卫视",
            logo: "https://garysclub.sharewithyou.dpdns.org/logos/ysp-live-logos/tjws.png",
            quality: "1080p候选",
            note: "",
        },
        {
            id: "jlws",
            name: "吉林卫视",
            group: "卫视",
            channelID: "2025561503",
            livePID: "600190405",
            definition: "fhd",
            tvgID: "吉林卫视",
            logo: "https://garysclub.sharewithyou.dpdns.org/logos/ysp-live-logos/jlws.png",
            quality: "1080p候选",
            note: "",
        },
        {
            id: "saxws",
            name: "陕西卫视",
            group: "卫视",
            channelID: "2029795103",
            livePID: "600190400",
            definition: "fhd",
            tvgID: "陕西卫视",
            logo: "https://garysclub.sharewithyou.dpdns.org/logos/ysp-live-logos/saxws.png",
            quality: "1080p候选",
            note: "",
        },
        {
            id: "nxws",
            name: "宁夏卫视",
            group: "卫视",
            channelID: "2025608503",
            livePID: "600190737",
            definition: "fhd",
            tvgID: "宁夏卫视",
            logo: "https://garysclub.sharewithyou.dpdns.org/logos/ysp-live-logos/nxws.png",
            quality: "1080p候选",
            note: "",
        },
        {
            id: "nmgws",
            name: "内蒙古卫视",
            group: "卫视",
            channelID: "2025561203",
            livePID: "600190401",
            definition: "fhd",
            tvgID: "内蒙古卫视",
            logo: "https://garysclub.sharewithyou.dpdns.org/logos/ysp-live-logos/nmgws.png",
            quality: "1080p候选",
            note: "",
        },
        {
            id: "ynws",
            name: "云南卫视",
            group: "卫视",
            channelID: "2025561303",
            livePID: "600190402",
            definition: "fhd",
            tvgID: "云南卫视",
            logo: "https://garysclub.sharewithyou.dpdns.org/logos/ysp-live-logos/ynws.png",
            quality: "1080p候选",
            note: "",
        },
        {
            id: "shanxiws",
            name: "山西卫视",
            group: "卫视",
            channelID: "2025560803",
            livePID: "600190407",
            definition: "fhd",
            tvgID: "山西卫视",
            logo: "https://garysclub.sharewithyou.dpdns.org/logos/ysp-live-logos/shanxiws.png",
            quality: "1080p候选",
            note: "",
        },
        {
            id: "gsws",
            name: "甘肃卫视",
            group: "卫视",
            channelID: "2025561703",
            livePID: "600190408",
            definition: "fhd",
            tvgID: "甘肃卫视",
            logo: "https://garysclub.sharewithyou.dpdns.org/logos/ysp-live-logos/gsws.png",
            quality: "1080p候选",
            note: "",
        },
        {
            id: "qhws",
            name: "青海卫视",
            group: "卫视",
            channelID: "2025559103",
            livePID: "600190406",
            definition: "fhd",
            tvgID: "青海卫视",
            logo: "https://garysclub.sharewithyou.dpdns.org/logos/ysp-live-logos/qhws.png",
            quality: "1080p候选",
            note: "",
        },
        {
            id: "xizangws",
            name: "西藏卫视",
            group: "卫视",
            channelID: "2025558003",
            livePID: "600190403",
            definition: "fhd",
            tvgID: "西藏卫视",
            logo: "https://garysclub.sharewithyou.dpdns.org/logos/ysp-live-logos/xizangws.png",
            quality: "1080p候选",
            note: "",
        },
        {
            id: "xjws",
            name: "新疆卫视",
            group: "卫视",
            channelID: "2019927403",
            livePID: "600152138",
            definition: "fhd",
            tvgID: "新疆卫视",
            logo: "https://garysclub.sharewithyou.dpdns.org/logos/ysp-live-logos/xjws.png",
            quality: "1080p候选",
            note: "",
        },
        {
            id: "cetv1",
            name: "CETV-1",
            group: "卫视",
            channelID: "2022823801",
            livePID: "600171827",
            definition: "fhd",
            tvgID: "CETV1",
            logo: "https://garysclub.sharewithyou.dpdns.org/logos/ysp-live-logos/cetv1.png",
            quality: "1080p候选",
            note: "",
        },
        {
            id: "guoxue",
            name: "国学频道",
            group: "卫视",
            channelID: "2029360403",
            livePID: "600213139",
            definition: "fhd",
            tvgID: "国学",
            logo: "https://garysclub.sharewithyou.dpdns.org/logos/ysp-live-logos/guoxue.png",
            quality: "1080p候选",
            note: "",
        },
    ];

    const ALIASES = {
        "anhuiws": "ahws",
        "beijingws": "bjws",
        "cctv16hd": "cctv16",
        "cctv5plus": "cctv5p",
        "cctvdiyijuchang": "cctvdyjc",
        "cctvfengyunjuchang": "cctvfyjc",
        "cctvhuaijiujuchang": "cctvhjjc",
        "cgtnalaboyu": "cgtnar",
        "cgtneyu": "cgtnru",
        "cgtnfayu": "cgtnfr",
        "cgtnwaiyujilu": "cgtndoc",
        "cgtnxibanyayu": "cgtnes",
        "chongqingws": "cqws",
        "dongfangws": "dfws",
        "fujiandongnanws": "dnws",
        "guangdongws": "gdws",
        "guangxiws": "gxws",
        "guizhouws": "gzws",
        "hebeiws": "hebws",
        "heilongjiangws": "hljws",
        "hubeiws": "hbws",
        "hunanws": "hnws",
        "jiangsuws": "jsws",
        "jiangxiws": "jxws",
        "jilinws": "jlws",
        "liaoningws": "lnws",
        "neimengguws": "nmgws",
        "ningxiaws": "nxws",
        "qinghaiws": "qhws",
        "shandongws": "sdws",
        "shannxiws": "saxws",
        "shenzhenws": "szws",
        "sichuanws": "scws",
        "tianjinws": "tjws",
        "xinjiangws": "xjws",
        "yunnanws": "ynws",
        "zhejiangws": "zjws"
    };

    const CATCHUP_IDS = new Set(["ahws","bjws","cctv1","cctv10","cctv13","cctv2","cctv3","cctv4","cctv5","cctv5p","cctv6","cctv7","cctv8","cctv8k","cctv9","cetv1","cgtn","cgtnar","cgtndoc","cgtnes","cgtnfr","cgtnru","cqws","dfws","dnws","gdws","gsws","guoxue","gxws","gzws","hainanws","hbws","hebws","henanws","hljws","hnws","jlws","jsws","jxws","lnws","nmgws","nxws","qhws","saxws","scws","sdws","shanxiws","szws","tjws","xizangws","xjws","ynws","zjws"]);
    const FORCE_BK_IDS = new Set(["cctv11","cctv12","cctv14","cctv15","cctv16","cctv17","cctvfyjc","cctvdyjc","cctvhjjc"]);

// ---------------------------------------------------------------------------
// ④ Spider 接口 —— CatVod spider（Node 版）
//    方法集与 bundle 的 Ah0 路由注册对应：init / home / homeVod / category /
//    detail / play / search / proxy。live() 按文档实现，但本 bundle 没有 /live
//    路由，频道以分类条目 + play() 交付为准。
//    来源选择沿用 NanoTV 服务入口的 resolveSource() 规则：auto 时有 Device ID
//    且不在强制 BK 清单 → Device，失败回退 BK；否则有回看 → JCE 直播窗口，
//    失败回退 BK；其余直接 BK。
// ---------------------------------------------------------------------------

function createSpider(site) {
    const bk = createBKProtocol();
    const device = createDeviceProtocol();
    const jce = createJCEProtocol();
    const jceCooldown = new Map();
    const cache = new Map();
    const pending = new Map();
    const options = { defaultRate: "36p", proxyBase: "http://127.0.0.1:9988" };

    function fail(message, status = 400) {
        const e = new Error(message);
        e.status = status;
        return e;
    }

    function findChannel(id) {
        if (!id) return null;
        const key = String(id).trim().toLowerCase();
        const resolved = ALIASES[key] || key;
        return CHANNELS.find((ch) => ch.id === resolved) || null;
    }

    function channelCard(ch) {
        return {
            vod_id: "ysp://" + ch.id,
            vod_name: ch.name,
            vod_pic: ch.logo,
            vod_remarks: ch.quality,
            type_name: ch.group,
        };
    }

    function page(items, pg, limit) {
        const p = Math.max(1, parseInt(pg, 10) || 1);
        const total = items.length;
        const pagecount = Math.max(1, Math.ceil(total / limit));
        const start = (p - 1) * limit;
        return {
            list: items.slice(start, start + limit),
            page: p,
            pagecount,
            limit,
            total,
        };
    }

    function detailVod(ch) {
        const flags = [];
        const urls = [];
        const add = (name, source) => {
            flags.push(name);
            urls.push("直播$ysp://" + ch.id + "/" + source);
        };
        add("自动", "auto");
        if (device.liveIDs[ch.id]) add("Device", "device");
        add("BK", "bk");
        if (CATCHUP_IDS.has(ch.id)) add("JCE", "jce");
        const item = channelCard(ch);
        Object.assign(item, {
            vod_content:
                ch.group +
                " · " +
                ch.quality +
                (CATCHUP_IDS.has(ch.id) ? " · 支持回看（7 天）" : "") +
                (FORCE_BK_IDS.has(ch.id) ? " · 固定 BK 来源" : "") +
                (ch.note ? " · " + ch.note : ""),
            vod_play_from: flags.join("$$$"),
            vod_play_url: urls.join("$$$"),
        });
        return item;
    }

    function time(value) {
        if (value === undefined || value === null || value === "") return null;
        const s = String(value).trim();
        if (/^\d{10}$/.test(s)) return Number(s);
        if (/^\d{13}$/.test(s)) return Math.floor(Number(s) / 1000);
        const compact = /^(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})?(Z)?$/i.exec(s);
        let normalized = s;
        if (compact) {
            const [, y, m, d, h, n, sec, z] = compact;
            normalized = y + "-" + m + "-" + d + "T" + h + ":" + n + ":" + (sec || "00") + (z ? "Z" : "+08:00");
        } else if (/^\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}/.test(s)) {
            normalized = s.replace(" ", "T");
            if (!/(Z|[+-]\d{2}:?\d{2})$/i.test(s)) normalized += "+08:00";
        } else throw fail("Invalid catchup time");
        const dateParts = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2})(?::(\d{2}))?/.exec(normalized);
        if (
            !dateParts ||
            Number(dateParts[2]) < 1 ||
            Number(dateParts[2]) > 12 ||
            Number(dateParts[3]) < 1 ||
            Number(dateParts[3]) > new Date(Date.UTC(Number(dateParts[1]), Number(dateParts[2]), 0)).getUTCDate() ||
            Number(dateParts[4]) > 23 ||
            Number(dateParts[5]) > 59 ||
            Number(dateParts[6] || 0) > 59
        )
            throw fail("Invalid calendar date");
        const n = Date.parse(normalized);
        if (!Number.isFinite(n)) throw fail("Invalid catchup time");
        return Math.floor(n / 1000);
    }

    function windowQuery(q, now) {
        let a = q.start ?? q.utc ?? q.starttime,
            b = q.end ?? q.lutc ?? q.endtime;
        if (q.playseek) {
            const match = /^(\d{10,14}Z?)-(\d{10,14}Z?)$/i.exec(q.playseek);
            if (match) {
                a = match[1];
                b = match[2];
            } else a = q.playseek;
        }
        if (a === undefined && b === undefined) return null;
        const start = time(a);
        if (start === null) throw fail("Catchup requires a start time");
        const end = b === undefined ? Math.max(start + 60, now) : time(b);
        if (
            !Number.isSafeInteger(start) ||
            !Number.isSafeInteger(end) ||
            start < 0 ||
            end <= start ||
            start > now ||
            end > now + 60
        )
            throw fail("Catchup requires an ordered window");
        return { start, end };
    }

    async function resolveBK(channel) {
        const r = await bk.resolve(channel);
        if (!r.ok) throw fail(r.error, 502);
        return Object.assign({}, r, {
            source: "BK live",
            expiresAt: Date.now() / 1000 + 300,
            resolutionVerified: false,
        });
    }

    async function resolveJCELive(channel) {
        const now = Math.floor(Date.now() / 1000),
            end = now + 900;
        const result = await jce.resolve(channel, now - 120, end);
        return Object.assign({}, result, {
            expiresAt: end - 60,
            liveWindow: { playlistSegments: 6, holdbackSegments: 1, minPollSeconds: 5 },
        });
    }

    async function refreshJCELive(channel) {
        if ((jceCooldown.get(channel.id) || 0) > Date.now()) throw fail("JCE live window cooling down", 503);
        try {
            return await resolveJCELive(channel);
        } catch (e) {
            jceCooldown.set(channel.id, Date.now() + 300000);
            log("JCE fallback channel=" + channel.id + " stage=refresh");
            throw e;
        }
    }

    async function resolveSource(channel, q, force = false) {
        const source = q.source || "auto";
        if (!["auto", "device", "bk", "jce"].includes(source)) throw fail("Unknown source");
        const window = windowQuery(q, Math.floor(Date.now() / 1000));
        if (window && !CATCHUP_IDS.has(channel.id)) throw fail("Catchup is unavailable for this channel", 422);
        if (window && ["device", "bk"].includes(source)) throw fail("Catchup requires JCE source", 422);
        const key =
            channel.id +
            "|" +
            source +
            "|" +
            (q.rate || "36p") +
            "|" +
            (window ? window.start + ":" + window.end : "live");
        const saved = cache.get(key);
        if (
            !force &&
            saved &&
            saved.until > Date.now() / 1000 &&
            saved.result.expiresAt > Date.now() / 1000 + 5 &&
            !(source === "auto" && saved.result.liveWindow && (jceCooldown.get(channel.id) || 0) > Date.now())
        )
            return saved.result;
        if (pending.has(key)) return pending.get(key);
        if (pending.size >= 8) throw fail("Resolver concurrency limit reached", 503);
        const task = (async () => {
            let result;
            if (window || source === "jce") {
                if (!CATCHUP_IDS.has(channel.id)) throw fail("JCE is unavailable for this channel", 422);
                const now = Math.floor(Date.now() / 1000);
                result = await jce.resolve(channel, window ? window.start : now - 300, window ? window.end : now);
            } else if (source === "bk") result = await resolveBK(channel);
            else if (source === "device") result = await device.resolve(channel, q.rate || "36p");
            else if (device.liveIDs[channel.id] && !FORCE_BK_IDS.has(channel.id)) {
                try {
                    result = await device.resolve(channel, q.rate || "36p");
                } catch (e) {
                    log(
                        "DEVICE fallback channel=" +
                        channel.id +
                        " stage=" +
                        (e.stage || "device") +
                        " code=" +
                        (e.code ?? "none") +
                        " business=" +
                        (e.businessCode ?? "none"),
                    );
                    result = await resolveBK(channel);
                    result.fallback = {
                        from: "device",
                        stage: e.stage || "device",
                        code: e.code ?? null,
                        httpStatus: e.httpStatus ?? null,
                        businessCode: e.businessCode ?? null,
                        retryAt: Date.now() / 1000 + Math.max(5, device.status().cooldown / 1000),
                        cause: device.status().lastFailure,
                        reason: String(e.message).replace(/https?:\/\/[^\s]+/g, "[URL]").slice(0, 200),
                    };
                }
            } else if (CATCHUP_IDS.has(channel.id) && (jceCooldown.get(channel.id) || 0) <= Date.now()) {
                try {
                    result = await resolveJCELive(channel);
                } catch (e) {
                    jceCooldown.set(channel.id, Date.now() + 300000);
                    log("JCE fallback channel=" + channel.id + " stage=jce");
                    result = await resolveBK(channel);
                    result.fallback = {
                        from: "JCE",
                        stage: "jce",
                        retryAt: Date.now() / 1000 + 300,
                        reason: "JCE live window unavailable",
                    };
                }
            } else {
                result = await resolveBK(channel);
                if (CATCHUP_IDS.has(channel.id) && (jceCooldown.get(channel.id) || 0) > Date.now())
                    result.fallback = {
                        from: "JCE",
                        stage: "jce",
                        retryAt: jceCooldown.get(channel.id) / 1000,
                        reason: "JCE live window cooling down",
                    };
            }
            if (window) result.window = window;
            result.channel = { id: channel.id, name: channel.name };
            cache.set(key, {
                result,
                until: result.fallback ? Math.min(result.expiresAt, result.fallback.retryAt) : result.expiresAt,
            });
            if (cache.size > 128) cache.delete(cache.keys().next().value);
            return result;
        })().finally(() => pending.delete(key));
        pending.set(key, task);
        return task;
    }

    function parsePlayId(flag, id) {
        let raw = String(id || "").trim();
        raw = raw.replace(/^ysp:\/\//i, "");
        const parts = raw.split("/");
        const channel = findChannel(parts[0]);
        if (!channel) return { channel: null, source: "auto" };
        let source = (parts[1] || "").toLowerCase();
        if (!["auto", "device", "bk", "jce"].includes(source)) {
            const flagMap = { "自动": "auto", "device": "device", "bk": "bk", "jce": "jce" };
            source = flagMap[String(flag || "").trim()] || "auto";
        }
        return { channel, source };
    }

    const spider = {
        meta: {
            key: "ysp",
            name: "央视频",
            type: 3,
            searchable: 1,
            quickSearch: 1,
            filterable: 0,
        },

        init(ext) {
            let parsed = ext;
            if (typeof parsed === "string") {
                try {
                    parsed = JSON.parse(parsed);
                } catch (_) {
                    parsed = {};
                }
            }
            if (parsed && typeof parsed === "object") {
                if (parsed.debug) DEBUG = true;
                if (typeof parsed.defaultRate === "string" && /^\d+p$/.test(parsed.defaultRate))
                    options.defaultRate = parsed.defaultRate;
                if (typeof parsed.proxyBase === "string" && parsed.proxyBase)
                    options.proxyBase = parsed.proxyBase.replace(/\/+$/, "");
                storeInit(typeof parsed.storePath === "string" ? parsed.storePath : null);
            } else {
                storeInit(null);
            }
            device.start();
            jce.start();
            log("YSP spider ready: " + CHANNELS.length + " channels (BK/Device/JCE)");
            return {};
        },

        home(filter) {
            return {
                class: [
                    { type_id: "cctv", type_name: "央视" },
                    { type_id: "ws", type_name: "卫视" },
                    { type_id: "all", type_name: "全部" },
                ],
            };
        },

        homeVod() {
            return { list: CHANNELS.map(channelCard) };
        },

        category(tid, pg, filter, extend) {
            let items;
            if (tid === "cctv") items = CHANNELS.filter((ch) => ch.group === "央视");
            else if (tid === "ws") items = CHANNELS.filter((ch) => ch.group === "卫视");
            else if (tid === "all") items = CHANNELS.slice();
            else items = [];
            return page(items.map(channelCard), pg, 20);
        },

        detail(id) {
            const raw = String(id || "").replace(/^ysp:\/\//i, "").split("/")[0];
            const channel = findChannel(raw);
            if (!channel) return { list: [], msg: "找不到该频道" };
            return { list: [detailVod(channel)] };
        },

        search(key, quick, pg = "1") {
            const query = String(key || "").trim().toLowerCase();
            if (!query) return page([], pg, 20);
            const items = CHANNELS.filter((ch) => {
                const aliasHit = Object.keys(ALIASES).some((a) => ALIASES[a] === ch.id && a.includes(query));
                return (
                    aliasHit ||
                    ch.id.includes(query) ||
                    ch.name.toLowerCase().includes(query) ||
                    ch.tvgID.toLowerCase().includes(query)
                );
            }).map(channelCard);
            return page(items, pg, 20);
        },

        async play(flag, id, vipFlags) {
            const { channel, source } = parsePlayId(flag, id);
            if (!channel) return { parse: 0, msg: "无效的播放 ID" };
            try {
                const result = await resolveSource(channel, { source, rate: options.defaultRate });
                device.mediaActivity({ kind: "activity", sessionID: "play", channelID: channel.id });
                const response = {
                    parse: 0,
                    url: result.url,
                    header: result.headers || {},
                    list: [detailVod(channel)],
                };
                if (result.source === "JCE" && CATCHUP_IDS.has(channel.id)) {
                    const now = Math.floor(Date.now() / 1000);
                    const startSec = result.liveWindow
                        ? now - 120
                        : result.window
                            ? result.window.start
                            : now - 300;
                    response.timeshift = {
                        url:
                            options.proxyBase +
                            "/spider/ysp/3/proxy/timeshift?channel=" +
                            channel.id +
                            "&time={time}",
                        start: startSec * 1000,
                        window: 604800000,
                    };
                }
                return response;
            } catch (e) {
                const message = String((e && e.message) || e || "解析失败").slice(0, 200);
                log("play failed channel=" + channel.id + " source=" + source + " " + message);
                return { parse: 0, msg: message };
            }
        },

        live(url) {
            // 本 bundle 没有 /live 路由；此方法按 CatVod 文档实现，供兼容调用。
            // urls 里是 spider 的 play ID（ysp://<频道>/<来源>），不是直链。
            const group = (name) => ({
                name,
                channel: CHANNELS.filter((ch) => ch.group === name).map((ch) => ({
                    name: ch.name,
                    urls: ["ysp://" + ch.id + "/auto"],
                })),
            });
            return [group("央视"), group("卫视")];
        },

        async proxy(params) {
            let query = params;
            if (typeof query === "string") {
                query = {};
                for (const pair of String(params).split("&")) {
                    const [k, v] = pair.split("=");
                    if (k) query[decodeURIComponent(k)] = v ? decodeURIComponent(v) : "";
                }
            }
            query = query || {};
            const action = query.do || query.action || "";
            if (action !== "timeshift") {
                return [404, "text/plain", "unknown proxy action", { "Content-Type": "text/plain" }];
            }
            const channel = findChannel(query.channel);
            const timeMs = Number(query.time);
            if (!channel || !CATCHUP_IDS.has(channel.id) || !Number.isFinite(timeMs)) {
                return [400, "application/json", JSON.stringify({ error: "invalid timeshift request" }), { "Content-Type": "application/json" }];
            }
            try {
                const target = Math.floor(timeMs / 1000);
                const result = await jce.resolve(channel, target - 60, target + 900);
                return [
                    200,
                    "application/json",
                    JSON.stringify({ url: result.url, header: result.headers || {}, format: "m3u8" }),
                    { "Content-Type": "application/json" },
                ];
            } catch (e) {
                return [
                    500,
                    "application/json",
                    JSON.stringify({ error: String((e && e.message) || e).slice(0, 200) }),
                    { "Content-Type": "application/json" },
                ];
            }
        },

        destroy() {
            device.stop();
            cache.clear();
            pending.clear();
            jceCooldown.clear();
        },

        // 仅供本地验证。
        testing: {
            bk: bk.testing,
            device: device.testing,
            jce: jce.testing,
            channels: () => CHANNELS,
            aliases: () => ALIASES,
            resolveSource,
            findChannel,
        },
    };

    return spider;
}

const spider = createSpider();
module.exports = spider;
module.exports.createSpider = createSpider;
