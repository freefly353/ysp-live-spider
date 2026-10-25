# YSP Live Spider for JSTV

央视频直播 spider，CatVod spider（Node.js）格式，供 JSTV 使用。

- 64 个频道：央视 30 + 卫视 34
- 三路解析：BK（cKey/TEA 签名 + bkliveinfo）、Device（投屏设备协议，含 4K/8K）、JCE（JCE/QMF 二进制协议，回看 7 天）
- 频道以站点分类条目呈现，点播时 `play()` 实时解析出带签名的播放地址；回看经 `play()` 的 `timeshift` + `proxy()`

## 文件

- `ysp-live-spider.js` — spider 本体（Node.js CommonJS，导出 spider 对象 `{ meta, init, home, homeVod, category, detail, play, search, live, proxy, destroy }`）

## 安装

JSTV 下发的 CatVodSpider iOS 服务端 bundle 只认编译进去的内置 spider：新 spider 须随 bundle 一起重建打包，再托管新的 `index.js` + `.md5` 供 JSTV 拉取。站点配置示例：

```json
{ "key": "nodejs_ysp", "name": "央视频", "type": 3, "searchable": 1, "quickSearch": 1, "filterable": 0 }
```

`ext`（可选）：`{ "debug": false, "storePath": "<绝对路径>", "defaultRate": "36p" }`，用于持久化设备身份与 JCE guid。

## 验证状态

- 本地验证 15/15 通过：TEA/cKey、Device 签名、JCE 编解码与 NanoTV 原版逐字节一致；`play()` 三路模拟上游均通。
- **真实上游未验证**：构建环境的出口网络连不上央视频域名（bkliveinfo/jacc 连接超时），需在自己的网络或 JSTV 实机上验证。
- timeshift 的 URL 形状与 proxy() 参数格式按 bundle 的 `/proxy` 路由推断，未经实机验证。

## 来源

移植自 [ysp-live v9.5.0](https://garysclub.sharewithyou.dpdns.org/ysp-live/ysp-live-v9.5.py)（Gary's Club）及其 NanoTV JS 移植版；目标接口形状来自 JSTV 的 CatVodSpider iOS 服务端 bundle。
