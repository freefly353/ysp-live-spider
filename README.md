# YSP Live Spider for JSTV

央视频直播 spider，CatVod spider（Node.js）格式，供 JSTV 使用。

- 64 个频道：央视 30 + 卫视 34
- 三路解析：BK（cKey/TEA 签名 + bkliveinfo）、Device（投屏设备协议，含 4K/8K）、JCE（JCE/QMF 二进制协议，回看 7 天）
- 频道以站点分类条目呈现，点播时 `play()` 实时解析出带签名的播放地址；回看经 `play()` 的 `timeshift` + `proxy()`

## 文件

- `ysp-live-spider.js` — spider 本体（Node.js CommonJS，导出 spider 对象 `{ meta, init, home, homeVod, category, detail, play, search, live, proxy, destroy }`）

## 重建的 bundle（供 JSTV 直接使用）

- `cat/index.js` — 在官方 CatVodSpider iOS bundle（CatVodSpiderios 0.1.0）基础上重建：**只保留央视频 spider（`nodejs_ysp`）**，其余 53 个内置 spider 已从启动列表移除（原 bundle 内容除此之外未改动）。站点列表里将只剩央视频。
- `cat/index.js.md5` — `cat/index.js` 的 MD5 校验值。
- `cat/index.config.js` + `cat/index.config.js.md5` — JSTV 添加源时会从同一目录下载的 App 配置。**这两个文件缺了会导致添加源时报下载失败 404**，2026-10-25 补上后才完整。配置以原 bundle 发行版自带的为准，只改了一处：`sites.list` 限定为仅 `nodejs_ysp`（央视频），其余网盘登录等设置项原样保留。
- JSTV 里粘贴 `.md5` 链接：https://raw.githubusercontent.com/freefly353/ysp-live-spider/main/cat/index.js.md5
- 本地验证：重建服务在本地跑通过（/health、站点列表含 nodejs_ysp、init/home/category/detail/search/play 路由均通）；play() 的真实上游仍需在自己网络验证。

## 安装

JSTV 下发的 CatVodSpider iOS 服务端 bundle 只认编译进去的内置 spider：新 spider 须随 bundle 一起重建打包，再托管新的 `index.js` + `.md5` 供 JSTV 拉取（见上节，本仓库已提供重建版）。站点配置示例：

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
