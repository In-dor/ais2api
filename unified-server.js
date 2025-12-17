const session = require("express-session");
const cookieParser = require("cookie-parser");
const crypto = require("crypto");
const express = require("express");
const WebSocket = require("ws");
const http = require("http");
const { EventEmitter } = require("events");
const fs = require("fs");
const path = require("path");
const { firefox } = require("playwright");
const os = require("os");

// ===================================================================================
// AUTH SOURCE MANAGEMENT MODULE
// ===================================================================================
class AuthSource {
  constructor(logger) {
    this.logger = logger;
    this.authMode = "file";
    this.availableIndices = [];
    this.initialIndices = [];
    this.accountNameMap = new Map();

    if (process.env.AUTH_JSON_1) {
      this.authMode = "env";
      this.logger.info(
        "[Auth] 检测到 AUTH_JSON_1 环境变量，切换到环境变量认证模式。"
      );
    } else {
      this.logger.info(
        '[Auth] 未检测到环境变量认证，将使用 "auth/" 目录下的文件。'
      );
    }

    this._discoverAvailableIndices(); // 初步发现所有存在的源
    this._preValidateAndFilter(); // 预检验并过滤掉格式错误的源

    if (this.availableIndices.length === 0) {
      this.logger.error(
        `[Auth] 致命错误：在 '${this.authMode}' 模式下未找到任何有效的认证源。`
      );
      throw new Error("No valid authentication sources found.");
    }
  }

  _discoverAvailableIndices() {
    let indices = [];
    if (this.authMode === "env") {
      const regex = /^AUTH_JSON_(\d+)$/;
      // [关键修复] 完整的 for...in 循环，用于扫描所有环境变量
      for (const key in process.env) {
        const match = key.match(regex);
        if (match && match[1]) {
          indices.push(parseInt(match[1], 10));
        }
      }
    } else {
      // 'file' mode
      const authDir = path.join(__dirname, "auth");
      if (!fs.existsSync(authDir)) {
        this.logger.warn('[Auth] "auth/" 目录不存在。');
        this.availableIndices = [];
        return;
      }
      try {
        const files = fs.readdirSync(authDir);
        const authFiles = files.filter((file) => /^auth-\d+\.json$/.test(file));
        indices = authFiles.map((file) =>
          parseInt(file.match(/^auth-(\d+)\.json$/)[1], 10)
        );
      } catch (error) {
        this.logger.error(`[Auth] 扫描 "auth/" 目录失败: ${error.message}`);
        this.availableIndices = [];
        return;
      }
    }

    // 将扫描到的原始索引存起来
    this.initialIndices = [...new Set(indices)].sort((a, b) => a - b);
    this.availableIndices = [...this.initialIndices]; // 先假设都可用

    this.logger.info(
      `[Auth] 在 '${this.authMode}' 模式下，初步发现 ${
        this.initialIndices.length
      } 个认证源: [${this.initialIndices.join(", ")}]`
    );
  }

  _preValidateAndFilter() {
    if (this.availableIndices.length === 0) return;

    this.logger.info("[Auth] 开始预检验所有认证源的JSON格式...");
    const validIndices = [];
    const invalidSourceDescriptions = [];

    for (const index of this.availableIndices) {
      // 注意：这里我们调用一个内部的、简化的 getAuthContent
      const authContent = this._getAuthContent(index);
      if (authContent) {
        try {
          const authData = JSON.parse(authContent);
          validIndices.push(index);
          this.accountNameMap.set(
            index,
            authData.accountName || "N/A (未命名)"
          );
        } catch (e) {
          invalidSourceDescriptions.push(`auth-${index}`);
        }
      } else {
        invalidSourceDescriptions.push(`auth-${index} (无法读取)`);
      }
    }

    if (invalidSourceDescriptions.length > 0) {
      this.logger.warn(
        `⚠️ [Auth] 预检验发现 ${
          invalidSourceDescriptions.length
        } 个格式错误或无法读取的认证源: [${invalidSourceDescriptions.join(
          ", "
        )}]，将从可用列表中移除。`
      );
    }

    this.availableIndices = validIndices;
  }

  // 一个内部辅助函数，仅用于预检验，避免日志污染
  _getAuthContent(index) {
    if (this.authMode === "env") {
      return process.env[`AUTH_JSON_${index}`];
    } else {
      const authFilePath = path.join(__dirname, "auth", `auth-${index}.json`);
      if (!fs.existsSync(authFilePath)) return null;
      try {
        return fs.readFileSync(authFilePath, "utf-8");
      } catch (e) {
        return null;
      }
    }
  }

  getAuth(index) {
    if (!this.availableIndices.includes(index)) {
      this.logger.error(`[Auth] 请求了无效或不存在的认证索引: ${index}`);
      return null;
    }

    let jsonString = this._getAuthContent(index);
    if (!jsonString) {
      this.logger.error(`[Auth] 在读取时无法获取认证源 #${index} 的内容。`);
      return null;
    }

    try {
      return JSON.parse(jsonString);
    } catch (e) {
      this.logger.error(
        `[Auth] 解析来自认证源 #${index} 的JSON内容失败: ${e.message}`
      );
      return null;
    }
  }
}

// ===================================================================================
// STATISTICS MANAGEMENT MODULE
// ===================================================================================

class StatsManager {
  constructor(logger) {
    this.logger = logger;
    // 修改保存路径为 data/daily_stats.json
    this.dataDir = path.join(__dirname, "data");
    this.statsFilePath = path.join(this.dataDir, "daily_stats.json");
    this.accountStatsFilePath = path.join(this.dataDir, "account_stats.json");
    this.stats = {};
    this.accountStats = {};
    this._ensureDataDir(); // 确保目录存在
    this._loadStats();
    this._loadAccountStats();
  }

  _ensureDataDir() {
    if (!fs.existsSync(this.dataDir)) {
      try {
        fs.mkdirSync(this.dataDir, { recursive: true });
      } catch (error) {
        this.logger.error(`[Stats] 创建 data 目录失败: ${error.message}`);
      }
    }
  }

  _loadStats() {
    try {
      if (fs.existsSync(this.statsFilePath)) {
        const data = fs.readFileSync(this.statsFilePath, "utf-8");
        this.stats = JSON.parse(data);
      }
    } catch (error) {
      this.logger.error(`[Stats] 加载统计文件失败: ${error.message}`);
      this.stats = {};
    }
  }

  _loadAccountStats() {
    try {
      if (fs.existsSync(this.accountStatsFilePath)) {
        const data = fs.readFileSync(this.accountStatsFilePath, "utf-8");
        this.accountStats = JSON.parse(data);
      }
    } catch (error) {
      this.logger.error(`[Stats] 加载账号统计文件失败: ${error.message}`);
      this.accountStats = {};
    }
  }

  _saveStats() {
    try {
      fs.writeFileSync(this.statsFilePath, JSON.stringify(this.stats, null, 2));
    } catch (error) {
      this.logger.error(`[Stats] 保存统计文件失败: ${error.message}`);
    }
  }

  _saveAccountStats() {
    try {
      fs.writeFileSync(
        this.accountStatsFilePath,
        JSON.stringify(this.accountStats, null, 2)
      );
    } catch (error) {
      this.logger.error(`[Stats] 保存账号统计文件失败: ${error.message}`);
    }
  }

  // [New] 计算逻辑上的有效统计日期 (北京时间 16:00 重置，即 UTC 08:00)
  // 将 UTC 时间偏移 -8 小时，使得 UTC 08:00 变为当天的 00:00
  _getEffectiveDate(baseDate = new Date()) {
    return new Date(baseDate.getTime() - 8 * 60 * 60 * 1000);
  }

  // [New] 格式化为 UTC 日期字符串，确保不受服务器时区影响
  _formatDate(date) {
    const year = date.getUTCFullYear();
    const month = String(date.getUTCMonth() + 1).padStart(2, "0");
    const day = String(date.getUTCDate()).padStart(2, "0");
    return `${year}-${month}-${day}`;
  }

  _getTodayDateString() {
    const effectiveDate = this._getEffectiveDate();
    return this._formatDate(effectiveDate);
  }

  incrementDailyUsage() {
    const today = this._getTodayDateString();
    if (!this.stats[today]) {
      this.stats[today] = 0;
    }
    this.stats[today]++;
    this._saveStats();
    return this.stats[today];
  }

  incrementAccountUsage(authIndex) {
    const today = this._getTodayDateString();
    if (!this.accountStats[today]) {
      this.accountStats[today] = {};
    }
    if (!this.accountStats[today][authIndex]) {
      this.accountStats[today][authIndex] = 0;
    }
    this.accountStats[today][authIndex]++;
    this._saveAccountStats();
    return this.accountStats[today][authIndex];
  }

  getTodayAccountStats() {
    const today = this._getTodayDateString();
    return this.accountStats[today] || {};
  }

  getStats(days = 7) {
    const result = [];
    // 基准时间使用逻辑上的有效日期
    const effectiveNow = this._getEffectiveDate();

    for (let i = days - 1; i >= 0; i--) {
      const d = new Date(effectiveNow);
      // 使用 UTC 日期操作，避免时区干扰
      d.setUTCDate(effectiveNow.getUTCDate() - i);
      
      const dateString = this._formatDate(d);

      result.push({
        date: dateString,
        count: this.stats[dateString] || 0
      });
    }
    
    // 获取今日的字符串 (基于同样的逻辑)
    const todayStr = this._getTodayDateString();
    
    return {
      daily: result,
      today: this.stats[todayStr] || 0
    };
  }
}
// ===================================================================================
// BROWSER MANAGEMENT MODULE
// ===================================================================================

class BrowserManager {
  constructor(logger, config, authSource) {
    this.logger = logger;
    this.config = config;
    this.authSource = authSource;
    this.browser = null;
    this.context = null;
    this.page = null;
    this.currentAuthIndex = 0;
    this.scriptFileName = "black-browser.js";
    this.noButtonCount = 0;
    this.launchArgs = [
      "--disable-dev-shm-usage", // 关键！防止 /dev/shm 空间不足导致浏览器崩溃
      "--disable-gpu",
      "--no-sandbox", // 在受限的容器环境中通常需要
      "--disable-setuid-sandbox",
      "--disable-infobars",
      "--disable-background-networking",
      "--disable-default-apps",
      "--disable-extensions",
      "--disable-sync",
      "--disable-translate",
      "--metrics-recording-only",
      "--mute-audio",
      "--safebrowsing-disable-auto-update",
    ];

    if (this.config.browserExecutablePath) {
      this.browserExecutablePath = this.config.browserExecutablePath;
    } else {
      const platform = os.platform();
      if (platform === "linux") {
        this.browserExecutablePath = path.join(
          __dirname,
          "camoufox-linux",
          "camoufox"
        );
      } else {
        throw new Error(`Unsupported operating system: ${platform}`);
      }
    }
  }

  notifyUserActivity() {
    if (this.noButtonCount > 0) {
      this.logger.info(
        "[Browser] ⚡ 收到用户请求信号，强制唤醒后台检测 (重置计数器)"
      );
      this.noButtonCount = 0;
    }
  }

  async launchOrSwitchContext(authIndex) {
    if (!this.browser) {
      this.logger.info("🚀 [Browser] 浏览器实例未运行，正在进行首次启动...");
      if (!fs.existsSync(this.browserExecutablePath)) {
        throw new Error(
          `Browser executable not found at path: ${this.browserExecutablePath}`
        );
      }
      this.browser = await firefox.launch({
        headless: true,
        executablePath: this.browserExecutablePath,
        args: this.launchArgs,
      });
      this.browser.on("disconnected", () => {
        this.logger.error("❌ [Browser] 浏览器意外断开连接！");
        this.browser = null;
        this.context = null;
        this.page = null;
      });
      this.logger.info("✅ [Browser] 浏览器实例已成功启动。");
    }
    if (this.context) {
      this.logger.info("[Browser] 正在关闭旧的浏览器上下文...");
      await this.context.close();
      this.context = null;
      this.page = null;
      this.logger.info("[Browser] 旧上下文已关闭。");
    }

    const sourceDescription =
      this.authSource.authMode === "env"
        ? `环境变量 AUTH_JSON_${authIndex}`
        : `文件 auth-${authIndex}.json`;
    this.logger.info("==================================================");
    this.logger.info(
      `🔄 [Browser] 正在为账号 #${authIndex} 创建新的浏览器上下文`
    );
    this.logger.info(`   • 认证源: ${sourceDescription}`);
    this.logger.info("==================================================");

    const storageStateObject = this.authSource.getAuth(authIndex);
    if (!storageStateObject) {
      throw new Error(
        `Failed to get or parse auth source for index ${authIndex}.`
      );
    }
    const buildScriptContent = fs.readFileSync(
      path.join(__dirname, this.scriptFileName),
      "utf-8"
    );

    try {
      this.context = await this.browser.newContext({
        storageState: storageStateObject,
        viewport: { width: 1920, height: 1080 },
      });
      this.page = await this.context.newPage();
      this.page.on("console", (msg) => {
        const msgText = msg.text();
        if (msgText.includes("[ProxyClient]")) {
          this.logger.info(
            `[Browser] ${msgText.replace("[ProxyClient] ", "")}`
          );
        } else if (msg.type() === "error") {
          this.logger.error(`[Browser Page Error] ${msgText}`);
        }
      });

      this.logger.info(`[Browser] 正在导航至目标网页...`);
      const targetUrl =
        "https://aistudio.google.com/u/0/apps/bundled/blank?showPreview=true&showCode=true&showAssistant=true";
      await this.page.goto(targetUrl, {
        timeout: 180000,
        waitUntil: "domcontentloaded",
      });
      this.logger.info("[Browser] 页面加载完成。");

      await this.page.waitForTimeout(3000);

      const currentUrl = this.page.url();
      let pageTitle = "";
      try {
        pageTitle = await this.page.title();
      } catch (e) {
        this.logger.warn(`[Browser] 无法获取页面标题: ${e.message}`);
      }

      this.logger.info(`[Browser] [诊断] URL: ${currentUrl}`);
      this.logger.info(`[Browser] [诊断] Title: "${pageTitle}"`);

      // 1. 检查 Cookie 是否失效 (跳转回登录页)
      if (
        currentUrl.includes("accounts.google.com") ||
        currentUrl.includes("ServiceLogin") ||
        pageTitle.includes("Sign in") ||
        pageTitle.includes("登录")
      ) {
        throw new Error(
          "🚨 Cookie 已失效/过期！浏览器被重定向到了 Google 登录页面。请重新提取 storageState。"
        );
      }

      // 2. 检查 IP 地区限制 (Region Unsupported)
      // 通常标题是 "Google AI Studio is not available in your location"
      if (
        pageTitle.includes("Available regions") ||
        pageTitle.includes("not available")
      ) {
        throw new Error(
          "🚨 当前 IP 不支持访问 Google AI Studio。请更换节点后重启！"
        );
      }

      // 3. 检查 IP 风控 (403 Forbidden)
      if (pageTitle.includes("403") || pageTitle.includes("Forbidden")) {
        throw new Error(
          "🚨 403 Forbidden：当前 IP 信誉过低，被 Google 风控拒绝访问。"
        );
      }

      // 4. 检查白屏 (网络极差或加载失败)
      if (currentUrl === "about:blank") {
        throw new Error(
          "🚨 页面加载失败 (about:blank)，可能是网络连接超时或浏览器崩溃。"
        );
      }

      this.logger.info(
        `[Browser] 进入 20秒 检查流程 (目标: Cookie + Got it + 新手引导)...`
      );

      const startTime = Date.now();
      const timeLimit = 20000;

      // 状态记录表
      const popupStatus = {
        cookie: false,
        gotIt: false,
        guide: false,
      };

      while (Date.now() - startTime < timeLimit) {
        // 如果3个都处理过了，立刻退出 ---
        if (popupStatus.cookie && popupStatus.gotIt && popupStatus.guide) {
          this.logger.info(
            `[Browser] ⚡ 完美！3个弹窗全部处理完毕，提前进入下一步。`
          );
          break;
        }

        let clickedInThisLoop = false;

        // 1. 检查 Cookie "Agree" (如果还没点过)
        if (!popupStatus.cookie) {
          try {
            const agreeBtn = this.page.locator('button:text("Agree")').first();
            if (await agreeBtn.isVisible({ timeout: 100 })) {
              await agreeBtn.click({ force: true });
              this.logger.info(`[Browser] ✅ (1/3) 点击了 "Cookie Agree"`);
              popupStatus.cookie = true;
              clickedInThisLoop = true;
            }
          } catch (e) {}
        }

        // 2. 检查 "Got it" (如果还没点过)
        if (!popupStatus.gotIt) {
          try {
            const gotItBtn = this.page
              .locator('div.dialog button:text("Got it")')
              .first();
            if (await gotItBtn.isVisible({ timeout: 100 })) {
              await gotItBtn.click({ force: true });
              this.logger.info(`[Browser] ✅ (2/3) 点击了 "Got it" 弹窗`);
              popupStatus.gotIt = true;
              clickedInThisLoop = true;
            }
          } catch (e) {}
        }

        // 3. 检查 新手引导 "Close" (如果还没点过)
        if (!popupStatus.guide) {
          try {
            const closeBtn = this.page
              .locator('button[aria-label="Close"]')
              .first();
            if (await closeBtn.isVisible({ timeout: 100 })) {
              await closeBtn.click({ force: true });
              this.logger.info(`[Browser] ✅ (3/3) 点击了 "新手引导关闭" 按钮`);
              popupStatus.guide = true;
              clickedInThisLoop = true;
            }
          } catch (e) {}
        }

        // 如果本轮点击了按钮，稍微等一下动画；如果没点，等待1秒避免死循环空转
        await this.page.waitForTimeout(clickedInThisLoop ? 500 : 1000);
      }

      this.logger.info(
        `[Browser] 弹窗检查结束 (耗时: ${Math.round(
          (Date.now() - startTime) / 1000
        )}s)，结果: ` +
          `Cookie[${popupStatus.cookie ? "Ok" : "No"}], ` +
          `GotIt[${popupStatus.gotIt ? "Ok" : "No"}], ` +
          `Guide[${popupStatus.guide ? "Ok" : "No"}]`
      );

      this.logger.info(
        `[Browser] 弹窗清理阶段结束，准备进入 Code 按钮点击流程。`
      );

      await this.page.evaluate(() => {
        const overlays = document.querySelectorAll("div.cdk-overlay-backdrop");
        if (overlays.length > 0) {
          overlays.forEach((el) => el.remove());
        }
      });

      this.logger.info('[Browser] 正在初始化编辑器...');
      for (let i = 1; i <= 5; i++) {
        try {
          // this.logger.debug(`  [Attempt ${i}/5] Clear overlays & Click Code btn...`);
          await this.page.evaluate(() => {
            document
              .querySelectorAll("div.cdk-overlay-backdrop")
              .forEach((el) => el.remove());
          });
          await this.page.waitForTimeout(500);

          await this.page
            .locator('button:text("Code")')
            .click({ timeout: 10000 });
          // Click success
          break;
        } catch (error) {
          if (i === 5) {
            // [新增截图] 在最终失败时保存截图
            try {
              const screenshotPath = path.join(
                __dirname,
                "debug_screenshot_final.png"
              );
              await this.page.screenshot({
                path: screenshotPath,
                fullPage: true,
              });
              this.logger.info(
                `[调试] 最终失败截图已保存到: ${screenshotPath}`
              );
            } catch (screenshotError) {
              this.logger.error(
                `[调试] 保存截图失败: ${screenshotError.message}`
              );
            }
            throw new Error(`多次尝试后仍无法点击 "Code" 按钮，初始化失败。`);
          }
        }
      }

      const editorContainerLocator = this.page.locator("div.monaco-editor").first();
      await editorContainerLocator.waitFor({ state: "visible", timeout: 60000 });

      // 二次清理遮罩层
      await this.page.evaluate(() => {
        document.querySelectorAll("div.cdk-overlay-backdrop").forEach((el) => el.remove());
      });
      await this.page.waitForTimeout(250);

      await editorContainerLocator.click({ timeout: 30000 });
      await this.page.evaluate((text) => navigator.clipboard.writeText(text), buildScriptContent);
      
      const isMac = os.platform() === "darwin";
      await this.page.keyboard.press(isMac ? "Meta+V" : "Control+V");
      
      await this.page.locator('button:text("Preview")').click();
      this.logger.info("[Browser] ✅ UI交互完成，脚本已开始运行。");

      this.currentAuthIndex = authIndex;

      // === 步骤 A: 启动后台保活监控 ===
      // 注意：不要 await 这个方法，因为它是一个死循环
      this._startBackgroundWakeup();
      this.logger.info("[Browser] (后台任务) 🛡️ 监控进程初始化指令已发出...");
      // 后台任务内部有 1500ms 的启动延迟，所以至少要等 2000ms
      await this.page.waitForTimeout(2500);

      // === 步骤 B: 发送主动唤醒请求 ===
      this.logger.info(
        "[Browser] ⚡ 正在发送主动唤醒请求以触发 Launch 流程..."
      );
      try {
        await this.page.evaluate(async () => {
          try {
            await fetch(
              "https://generativelanguage.googleapis.com/v1beta/models?key=ActiveTrigger",
              {
                method: "GET",
                headers: { "Content-Type": "application/json" },
              }
            );
          } catch (e) {
            console.log(
              "[ProxyClient] 主动唤醒请求已发送 (预期内可能会失败，这很正常)"
            );
          }
        });
        this.logger.info("[Browser] ⚡ 主动唤醒请求已发送。");
      } catch (e) {
        this.logger.warn(
          `[Browser] 主动唤醒请求发送异常 (不影响主流程): ${e.message}`
        );
      }
      this.logger.info("==================================================");
      this.logger.info(`✅ [Browser] 账号 ${authIndex} 的上下文初始化成功！`);
      this.logger.info("✅ [Browser] 浏览器客户端已准备就绪。");
      this.logger.info("==================================================");
    } catch (error) {
      this.logger.error(
        `❌ [Browser] 账户 ${authIndex} 的上下文初始化失败: ${error.message}`
      );
      if (this.browser) {
        await this.browser.close();
        this.browser = null;
      }
      throw error;
    }
  }

  async closeBrowser() {
    if (this.browser) {
      this.logger.info("[Browser] 正在关闭整个浏览器实例...");
      await this.browser.close();
      this.browser = null;
      this.context = null;
      this.page = null;
      this.logger.info("[Browser] 浏览器实例已关闭。");
    }
  }

  async switchAccount(newAuthIndex) {
    this.logger.info(
      `🔄 [Browser] 开始账号切换: 从 ${this.currentAuthIndex} 到 ${newAuthIndex}`
    );
    await this.launchOrSwitchContext(newAuthIndex);
    this.logger.info(
      `✅ [Browser] 账号切换完成，当前账号: ${this.currentAuthIndex}`
    );
  }

  async _startBackgroundWakeup() {
    const currentPage = this.page;
    await new Promise((r) => setTimeout(r, 1500));
    if (!currentPage || currentPage.isClosed() || this.page !== currentPage)
      return;
    this.logger.info("[Browser] (后台任务) 🛡️ 网页保活监控已启动");
    while (
      currentPage &&
      !currentPage.isClosed() &&
      this.page === currentPage
    ) {
      try {
        // --- [增强步骤 1] 强制唤醒页面 (解决不发请求不刷新的问题) ---
        await currentPage.bringToFront().catch(() => {});

        // 关键：在无头模式下，仅仅 bringToFront 可能不够，需要伪造鼠标移动来触发渲染帧
        // 随机在一个无害区域轻微晃动鼠标
        await currentPage.mouse.move(10, 10);
        await currentPage.mouse.move(20, 20);

        // --- [增强步骤 2] 智能查找 (查找文本并向上锁定可交互父级) ---
        const targetInfo = await currentPage.evaluate(() => {
          // 1. 直接CSS定位
          try {
            const preciseCandidates = Array.from(
              document.querySelectorAll(
                ".interaction-modal p, .interaction-modal button"
              )
            );
            for (const el of preciseCandidates) {
              const text = (el.innerText || "").trim();
              if (/Launch|rocket_launch/i.test(text)) {
                const rect = el.getBoundingClientRect();
                if (rect.width > 0 && rect.height > 0) {
                  return {
                    found: true,
                    x: rect.left + rect.width / 2,
                    y: rect.top + rect.height / 2,
                    tagName: el.tagName,
                    text: text.substring(0, 15),
                    strategy: "precise_css", // 标记：这是通过精准CSS找到的
                  };
                }
              }
            }
          } catch (e) {}
          // 2. 扫描Y轴400-800范围刻意元素
          const MIN_Y = 400;
          const MAX_Y = 800;

          // 辅助函数：判断元素是否可见且在区域内
          const isValid = (rect) => {
            return (
              rect.width > 0 &&
              rect.height > 0 &&
              rect.top > MIN_Y &&
              rect.top < MAX_Y
            );
          };

          // 扫描所有包含关键词的元素
          const candidates = Array.from(
            document.querySelectorAll("button, span, div, a, i")
          );

          for (const el of candidates) {
            const text = (el.innerText || "").trim();
            // 匹配 Launch 或 rocket_launch 图标名
            if (!/Launch|rocket_launch/i.test(text)) continue;

            let targetEl = el;
            let rect = targetEl.getBoundingClientRect();

            // [关键优化] 如果当前元素很小或是纯文本容器，尝试向上找 3 层父级
            let parentDepth = 0;
            while (parentDepth < 3 && targetEl.parentElement) {
              if (
                targetEl.tagName === "BUTTON" ||
                targetEl.getAttribute("role") === "button"
              ) {
                break;
              }
              const parent = targetEl.parentElement;
              const pRect = parent.getBoundingClientRect();
              if (isValid(pRect)) {
                targetEl = parent;
                rect = pRect;
              }
              parentDepth++;
            }

            // 最终检查
            if (isValid(rect)) {
              return {
                found: true,
                x: rect.left + rect.width / 2,
                y: rect.top + rect.height / 2,
                tagName: targetEl.tagName,
                text: text.substring(0, 15),
                strategy: "fuzzy_scan", // 标记：这是通过模糊扫描找到的
              };
            }
          }
          return { found: false };
        });

        // --- [增强步骤 3] 执行操作 ---
        if (targetInfo.found) {
          this.noButtonCount = 0;
          this.logger.info(
            `[Browser] 🎯 锁定目标 [${targetInfo.tagName}] (策略: ${
              targetInfo.strategy === "precise_css" ? "精准定位" : "模糊扫描"
            })...`
          );

          // === 策略 A: 物理点击 (模拟真实鼠标) ===
          // 1. 移动过去
          await currentPage.mouse.move(targetInfo.x, targetInfo.y, {
            steps: 5,
          });
          // 2. 悬停 (给 hover 样式一点反应时间)
          await new Promise((r) => setTimeout(r, 300));
          // 3. 按下
          await currentPage.mouse.down();
          // 4. 长按 (某些按钮防误触，需要按住一小会儿)
          await new Promise((r) => setTimeout(r, 400));
          // 5. 抬起
          await currentPage.mouse.up();

          this.logger.info(`[Browser] 🖱️ 物理点击已执行，验证结果...`);
          // 等待 1.5 秒看效果
          await new Promise((r) => setTimeout(r, 1500));

          // === 策略 B: JS 补刀 (如果物理点击失败) ===
          // 再次检查按钮是否还在原地
          const isStillThere = await currentPage.evaluate(() => {
            // 逻辑同上，简单检查
            const allText = document.body.innerText;
            // 简单粗暴检查页面可视区是否还有那个特定位置的文字
            // 这里为了性能做简化：再次扫描元素
            const els = Array.from(
              document.querySelectorAll('button, span, div[role="button"]')
            );
            return els.some((el) => {
              const r = el.getBoundingClientRect();
              return (
                /Launch|rocket_launch/i.test(el.innerText) &&
                r.top > 400 &&
                r.top < 800 &&
                r.height > 0
              );
            });
          });

          if (isStillThere) {
            this.logger.warn(
              `[Browser] ⚠️ 物理点击似乎无效（按钮仍在），尝试 JS 强力点击...`
            );

            // 直接在浏览器内部触发 click 事件
            await currentPage.evaluate(() => {
              const MIN_Y = 400;
              const MAX_Y = 800;
              const candidates = Array.from(
                document.querySelectorAll('button, span, div[role="button"]')
              );
              for (const el of candidates) {
                const r = el.getBoundingClientRect();
                if (
                  /Launch|rocket_launch/i.test(el.innerText) &&
                  r.top > MIN_Y &&
                  r.top < MAX_Y
                ) {
                  // 尝试找到最近的 button 父级点击
                  let target = el;
                  if (target.closest("button"))
                    target = target.closest("button");
                  target.click(); // 原生 JS 点击
                  console.log(
                    "[ProxyClient] JS Click triggered on " + target.tagName
                  );
                  return true;
                }
              }
            });
            await new Promise((r) => setTimeout(r, 2000));
          } else {
            this.logger.info(`[Browser] ✅ 物理点击成功，按钮已消失。`);
            await new Promise((r) => setTimeout(r, 60000));
            this.noButtonCount = 21;
          }
        } else {
          this.noButtonCount++;
          // 5. [关键] 智能休眠逻辑 (支持被唤醒)
          if (this.noButtonCount > 20) {
            for (let i = 0; i < 30; i++) {
              if (this.noButtonCount === 0) {
                break;
              }
              await new Promise((r) => setTimeout(r, 1000));
            }
          } else {
            await new Promise((r) => setTimeout(r, 1500));
          }
        }
      } catch (e) {
        await new Promise((r) => setTimeout(r, 1000));
      }
    }
  }
}

// ===================================================================================
// PROXY SERVER MODULE
// ===================================================================================

class LoggingService {
  constructor(serviceName = "ProxyServer") {
    this.serviceName = serviceName;
    this.logBuffer = []; // 用于在内存中保存日志
    this.maxBufferSize = 200; // 最多保存200条
    // 定义ANSI颜色代码
    this.colors = {
      reset: "\x1b[0m",
      info: "\x1b[36m", // 青色
      error: "\x1b[31m", // 红色
      warn: "\x1b[33m", // 黄色
      debug: "\x1b[90m", // 灰色
    };
  }

  _getTimestamp() {
    const now = new Date();
    const pad = (n) => n.toString().padStart(2, "0");
    return (
      `${now.getFullYear()}-${pad(now.getMonth() + 1)}-${pad(now.getDate())} ` +
      `${pad(now.getHours())}:${pad(now.getMinutes())}:${pad(
        now.getSeconds()
      )}`
    );
  }

  _emit(level, message, color) {
    const timestamp = this._getTimestamp();
    const prefix = `[${level}] ${timestamp} [${this.serviceName}] - `;

    // 1. 存入缓冲区 (纯文本)
    this.logBuffer.push(prefix + message);
    if (this.logBuffer.length > this.maxBufferSize) {
      this.logBuffer.shift();
    }

    // 2. 控制台输出 (仅前缀有颜色，内容保持原色)
    const output = `${color}${prefix}${this.colors.reset}${message}`;
    if (level === "ERROR") console.error(output);
    else if (level === "WARN") console.warn(output);
    else if (level === "DEBUG") console.debug(output);
    else console.log(output);
  }

  info(message) {
    this._emit("INFO", message, this.colors.info);
  }
  error(message) {
    this._emit("ERROR", message, this.colors.error);
  }
  warn(message) {
    this._emit("WARN", message, this.colors.warn);
  }
  debug(message) {
    this._emit("DEBUG", message, this.colors.debug);
  }
}

class MessageQueue extends EventEmitter {
  constructor(timeoutMs = 600000) {
    super();
    this.messages = [];
    this.waitingResolvers = [];
    this.defaultTimeout = timeoutMs;
    this.closed = false;
  }
  enqueue(message) {
    if (this.closed) return;
    if (this.waitingResolvers.length > 0) {
      const resolver = this.waitingResolvers.shift();
      resolver.resolve(message);
    } else {
      this.messages.push(message);
    }
  }
  async dequeue(timeoutMs = this.defaultTimeout) {
    if (this.closed) {
      throw new Error("Queue is closed");
    }
    return new Promise((resolve, reject) => {
      if (this.messages.length > 0) {
        resolve(this.messages.shift());
        return;
      }
      const resolver = { resolve, reject };
      this.waitingResolvers.push(resolver);
      const timeoutId = setTimeout(() => {
        const index = this.waitingResolvers.indexOf(resolver);
        if (index !== -1) {
          this.waitingResolvers.splice(index, 1);
          reject(new Error("Queue timeout"));
        }
      }, timeoutMs);
      resolver.timeoutId = timeoutId;
    });
  }
  close() {
    this.closed = true;
    this.waitingResolvers.forEach((resolver) => {
      clearTimeout(resolver.timeoutId);
      resolver.reject(new Error("Queue closed"));
    });
    this.waitingResolvers = [];
    this.messages = [];
  }
}

class ConnectionRegistry extends EventEmitter {
  constructor(logger) {
    super();
    this.logger = logger;
    this.connections = new Set();
    this.messageQueues = new Map();
    this.reconnectGraceTimer = null; // 新增：用于缓冲期计时的定时器
  }
  addConnection(websocket, clientInfo) {
    // --- 核心修改：当新连接建立时，清除可能存在的“断开”警报 ---
    if (this.reconnectGraceTimer) {
      clearTimeout(this.reconnectGraceTimer);
      this.reconnectGraceTimer = null;
      this.logger.info("[Server] 在缓冲期内检测到新连接，已取消断开处理。");
    }
    // --- 修改结束 ---

    this.connections.add(websocket);
    this.logger.info(
      `[Server] 内部WebSocket客户端已连接 (来自: ${clientInfo.address})`
    );
    websocket.on("message", (data) =>
      this._handleIncomingMessage(data.toString())
    );
    websocket.on("close", () => this._removeConnection(websocket));
    websocket.on("error", (error) =>
      this.logger.error(`[Server] 内部WebSocket连接错误: ${error.message}`)
    );
    this.emit("connectionAdded", websocket);
  }

  _removeConnection(websocket) {
    this.connections.delete(websocket);
    this.logger.warn("[Server] 内部WebSocket客户端连接断开。");

    // --- 核心修改：不立即清理队列，而是启动一个缓冲期 ---
    this.logger.info("[Server] 启动5秒重连缓冲期...");
    this.reconnectGraceTimer = setTimeout(() => {
      // 5秒后，如果没有新连接进来（即reconnectGraceTimer未被清除），则确认是真实断开
      this.logger.error(
        "[Server] 缓冲期结束，未检测到重连。确认连接丢失，正在清理所有待处理请求..."
      );
      this.messageQueues.forEach((queue) => queue.close());
      this.messageQueues.clear();
      this.emit("connectionLost"); // 使用一个新的事件名，表示确认丢失
    }, 5000); // 5秒的缓冲时间
    // --- 修改结束 ---

    this.emit("connectionRemoved", websocket);
  }

  _handleIncomingMessage(messageData) {
    try {
      const parsedMessage = JSON.parse(messageData);
      const requestId = parsedMessage.request_id;
      if (!requestId) {
        this.logger.warn("[Server] 收到无效消息：缺少request_id");
        return;
      }
      const queue = this.messageQueues.get(requestId);
      if (queue) {
        this._routeMessage(parsedMessage, queue);
      } else {
        // 在缓冲期内，旧的请求队列可能仍然存在，但连接已经改变，这可能会导致找不到队列。
        // 暂时只记录警告，避免因竞速条件而报错。
        this.logger.warn(`[Server] 收到未知或已过时请求ID的消息: ${requestId}`);
      }
    } catch (error) {
      this.logger.error("[Server] 解析内部WebSocket消息失败");
    }
  }

  // 其他方法 (_routeMessage, hasActiveConnections, getFirstConnection,等) 保持不变...
  _routeMessage(message, queue) {
    const { event_type } = message;
    switch (event_type) {
      case "response_headers":
      case "chunk":
      case "error":
        queue.enqueue(message);
        break;
      case "stream_close":
        queue.enqueue({ type: "STREAM_END" });
        break;
      default:
        this.logger.warn(`[Server] 未知的内部事件类型: ${event_type}`);
    }
  }
  hasActiveConnections() {
    return this.connections.size > 0;
  }
  getFirstConnection() {
    return this.connections.values().next().value;
  }
  createMessageQueue(requestId) {
    const queue = new MessageQueue();
    this.messageQueues.set(requestId, queue);
    return queue;
  }
  removeMessageQueue(requestId) {
    const queue = this.messageQueues.get(requestId);
    if (queue) {
      queue.close();
      this.messageQueues.delete(requestId);
    }
  }
}

class RequestHandler {
  constructor(
    serverSystem,
    connectionRegistry,
    logger,
    browserManager,
    config,
    authSource,
    statsManager
  ) {
    this.serverSystem = serverSystem;
    this.connectionRegistry = connectionRegistry;
    this.logger = logger;
    this.browserManager = browserManager;
    this.config = config;
    this.authSource = authSource;
    this.statsManager = statsManager;
    this.maxRetries = this.config.maxRetries;
    this.retryDelay = this.config.retryDelay;
    this.failureCount = 0;
    this.usageCount = 0;
    this.isAuthSwitching = false;
    this.needsSwitchingAfterRequest = false;
    this.isSystemBusy = false;
  }

  get currentAuthIndex() {
    return this.browserManager.currentAuthIndex;
  }

  _getMaxAuthIndex() {
    return this.authSource.getMaxIndex();
  }

  _getNextAuthIndex() {
    const available = this.authSource.availableIndices; // 使用新的 availableIndices
    if (available.length === 0) return null;

    const currentIndexInArray = available.indexOf(this.currentAuthIndex);

    if (currentIndexInArray === -1) {
      this.logger.warn(
        `[Auth] 当前索引 ${this.currentAuthIndex} 不在可用列表中，将切换到第一个可用索引。`
      );
      return available[0];
    }

    const nextIndexInArray = (currentIndexInArray + 1) % available.length;
    return available[nextIndexInArray];
  }

  async _switchToNextAuth() {
    const available = this.authSource.availableIndices;

    if (available.length === 0) {
      throw new Error("没有可用的认证源，无法切换。");
    }

    if (this.isAuthSwitching) {
      this.logger.info("🔄 [Auth] 正在切换/重启账号，跳过重复操作");
      return { success: false, reason: "Switch already in progress." };
    }

    // --- 加锁！ ---
    this.isSystemBusy = true;
    this.isAuthSwitching = true;

    try {
      // 单账号模式 - 执行原地重启 (Refresh)
      if (available.length === 1) {
        const singleIndex = available[0];
        this.logger.info("==================================================");
        this.logger.info(
          `🔄 [Auth] 单账号模式：达到轮换阈值，正在执行原地重启...`
        );
        this.logger.info(`   • 目标账号: #${singleIndex}`);
        this.logger.info("==================================================");

        try {
          // 强制重新加载当前账号的 Context
          await this.browserManager.launchOrSwitchContext(singleIndex);

          // 关键：重置计数器
          this.failureCount = 0;
          this.usageCount = 0;

          this.logger.info(
            `✅ [Auth] 单账号 #${singleIndex} 重启/刷新成功，使用计数已清零。`
          );
          return { success: true, newIndex: singleIndex };
        } catch (error) {
          this.logger.error(`❌ [Auth] 单账号重启失败: ${error.message}`);
          throw error;
        }
      }

      // 多账号模式 - 执行轮换 (Rotate)

      const previousAuthIndex = this.currentAuthIndex;
      const nextAuthIndex = this._getNextAuthIndex();

      this.logger.info("==================================================");
      this.logger.info(`🔄 [Auth] 多账号模式：开始账号切换流程`);
      this.logger.info(`   • 当前账号: #${previousAuthIndex}`);
      this.logger.info(`   • 目标账号: #${nextAuthIndex}`);
      this.logger.info("==================================================");

      try {
        await this.browserManager.switchAccount(nextAuthIndex);
        this.failureCount = 0;
        this.usageCount = 0;
        this.logger.info(
          `✅ [Auth] 成功切换到账号 #${this.currentAuthIndex}，计数已重置。`
        );
        return { success: true, newIndex: this.currentAuthIndex };
      } catch (error) {
        this.logger.error(
          `❌ [Auth] 切换到账号 #${nextAuthIndex} 失败: ${error.message}`
        );
        this.logger.warn(
          `🚨 [Auth] 切换失败，正在尝试回退到上一个可用账号 #${previousAuthIndex}...`
        );
        try {
          await this.browserManager.launchOrSwitchContext(previousAuthIndex);
          this.logger.info(`✅ [Auth] 成功回退到账号 #${previousAuthIndex}！`);
          this.failureCount = 0;
          this.usageCount = 0;
          this.logger.info("[Auth] 失败和使用计数已在回退成功后重置为0。");
          return {
            success: false,
            fallback: true,
            newIndex: this.currentAuthIndex,
          };
        } catch (fallbackError) {
          this.logger.error(
            `FATAL: ❌❌❌ [Auth] 紧急回退到账号 #${previousAuthIndex} 也失败了！服务可能中断。`
          );
          throw fallbackError;
        }
      }
    } finally {
      this.isAuthSwitching = false;
      this.isSystemBusy = false;
    }
  }

  async _switchToSpecificAuth(targetIndex) {
    if (this.isAuthSwitching) {
      this.logger.info("🔄 [Auth] 正在切换账号，跳过重复操作");
      return { success: false, reason: "Switch already in progress." };
    }
    if (!this.authSource.availableIndices.includes(targetIndex)) {
      return {
        success: false,
        reason: `切换失败：账号 #${targetIndex} 无效或不存在。`,
      };
    }

    this.isSystemBusy = true;
    this.isAuthSwitching = true;
    try {
      this.logger.info(`🔄 [Auth] 开始切换到指定账号 #${targetIndex}...`);
      await this.browserManager.switchAccount(targetIndex);
      this.failureCount = 0;
      this.usageCount = 0;
      this.logger.info(
        `✅ [Auth] 成功切换到账号 #${this.currentAuthIndex}，计数已重置。`
      );
      return { success: true, newIndex: this.currentAuthIndex };
    } catch (error) {
      this.logger.error(
        `❌ [Auth] 切换到指定账号 #${targetIndex} 失败: ${error.message}`
      );
      // 对于指定切换，失败了就直接报错，不进行回退，让用户知道这个账号有问题
      throw error;
    } finally {
      this.isAuthSwitching = false;
      this.isSystemBusy = false;
    }
  }

  async _handleRequestFailureAndSwitch(errorDetails, res) {
    // 失败计数逻辑
    if (this.config.failureThreshold > 0) {
      this.failureCount++;
      this.logger.warn(
        `⚠️ [Auth] 请求失败 - 失败计数: ${this.failureCount}/${this.config.failureThreshold} (当前账号索引: ${this.currentAuthIndex})`
      );
    }

    const isImmediateSwitch = this.config.immediateSwitchStatusCodes.includes(
      errorDetails.status
    );
    const isThresholdReached =
      this.config.failureThreshold > 0 &&
      this.failureCount >= this.config.failureThreshold;

    // 只要满足任一切换条件
    if (isImmediateSwitch || isThresholdReached) {
      if (isImmediateSwitch) {
        this.logger.warn(
          `🔴 [Auth] 收到状态码 ${errorDetails.status}，触发立即切换账号...`
        );
      } else {
        this.logger.warn(
          `🔴 [Auth] 达到失败阈值 (${this.failureCount}/${this.config.failureThreshold})！准备切换账号...`
        );
      }

      // [核心修改] 等待切换操作完成，并根据其结果发送不同消息
      try {
        await this._switchToNextAuth();
        // 如果上面这行代码没有抛出错误，说明切换/回退成功了
        const successMessage = `🔄 目标账户无效，已自动回退至账号 #${this.currentAuthIndex}。`;
        this.logger.info(`[Auth] ${successMessage}`);
        if (res) this._sendErrorChunkToClient(res, successMessage);
      } catch (error) {
        let userMessage = `❌ 致命错误：发生未知切换错误: ${error.message}`;

        if (error.message.includes("Only one account is available")) {
          // 场景：单账号无法切换
          userMessage = "❌ 切换失败：只有一个可用账号。";
          this.logger.info("[Auth] 只有一个可用账号，失败计数已重置。");
          this.failureCount = 0;
        } else if (error.message.includes("回退失败原因")) {
          // 场景：切换到坏账号后，连回退都失败了
          userMessage = `❌ 致命错误：自动切换和紧急回退均失败，服务可能已中断，请检查日志！`;
        } else if (error.message.includes("切换到账号")) {
          // 场景：切换到坏账号后，成功回退（这是一个伪“成功”，本质是上一个操作失败了）
          userMessage = `⚠️ 自动切换失败：已自动回退到账号 #${this.currentAuthIndex}，请检查目标账号是否存在问题。`;
        }

        this.logger.error(`[Auth] 后台账号切换任务最终失败: ${error.message}`);
        if (res) this._sendErrorChunkToClient(res, userMessage);
      }

      return;
    }
  }

  async processRequest(req, res) {
    if (this.browserManager) {
      this.browserManager.notifyUserActivity();
    }
    const requestId = this._generateRequestId();
    res.on("close", () => {
      if (!res.writableEnded) {
        this.logger.warn(
          `[Request] 客户端已提前关闭请求 #${requestId} 的连接。`
        );
        this._cancelBrowserRequest(requestId);
      }
    });

    if (!this.connectionRegistry.hasActiveConnections()) {
      if (this.isSystemBusy) {
        this.logger.warn(
          "[System] 检测到连接断开，但系统正在进行切换/恢复，拒绝新请求。"
        );
        return this._sendErrorResponse(
          res,
          503,
          "服务器正在进行内部维护（账号切换/恢复），请稍后重试。"
        );
      }

      this.logger.error(
        "❌ [System] 检测到浏览器WebSocket连接已断开！可能是进程崩溃。正在尝试恢复..."
      );
      // --- 开始恢复前，加锁！ ---
      this.isSystemBusy = true;
      try {
        await this.browserManager.launchOrSwitchContext(this.currentAuthIndex);
        this.logger.info(`✅ [System] 浏览器已成功恢复！`);
      } catch (error) {
        this.logger.error(`❌ [System] 浏览器自动恢复失败: ${error.message}`);
        return this._sendErrorResponse(
          res,
          503,
          "服务暂时不可用：后端浏览器实例崩溃且无法自动恢复，请联系管理员。"
        );
      } finally {
        // --- 恢复结束后，解锁！ ---
        this.isSystemBusy = false;
      }
    }

    if (this.isSystemBusy) {
      this.logger.warn(
        "[System] 收到新请求，但系统正在进行切换/恢复，拒绝新请求。"
      );
      return this._sendErrorResponse(
        res,
        503,
        "服务器正在进行内部维护（账号切换/恢复），请稍后重试。"
      );
    }

    const isGenerativeRequest =
      req.method === "POST" &&
      (req.path.includes("generateContent") ||
        req.path.includes("streamGenerateContent"));
    
    if (this.config.switchOnUses > 0 && isGenerativeRequest) {
      this.usageCount++;
      // 仅在每10次或接近阈值时打印日志，减少刷屏
      if (
        this.usageCount % 10 === 0 ||
        this.usageCount >= this.config.switchOnUses - 3
      ) {
        this.logger.info(
          `[Request] 账号轮换计数: ${this.usageCount}/${this.config.switchOnUses} (当前账号: ${this.currentAuthIndex})`
        );
      }
      if (this.usageCount >= this.config.switchOnUses) {
        this.needsSwitchingAfterRequest = true;
      }
    }

    const proxyRequest = this._buildProxyRequest(req, requestId);
    proxyRequest.is_generative = isGenerativeRequest;
    // 根据判断结果，为浏览器脚本准备标志位
    const messageQueue = this.connectionRegistry.createMessageQueue(requestId);
    const wantsStreamByHeader =
      req.headers.accept && req.headers.accept.includes("text/event-stream");
    const wantsStreamByPath = req.path.includes(":streamGenerateContent");
    const wantsStream = wantsStreamByHeader || wantsStreamByPath;

    try {
      if (wantsStream) {
        // --- 客户端想要流式响应 ---
        this.logger.info(
          `[Request] 客户端启用流式传输 (${this.serverSystem.streamingMode})，进入流式处理模式...`
        );
        if (this.serverSystem.streamingMode === "fake") {
          await this._handlePseudoStreamResponse(
            proxyRequest,
            messageQueue,
            req,
            res
          );
        } else {
          await this._handleRealStreamResponse(proxyRequest, messageQueue, res);
        }
      } else {
        // --- 客户端想要非流式响应 ---
        // 明确告知浏览器脚本本次应按“一次性JSON”（即fake模式）来处理
        proxyRequest.streaming_mode = "fake";
        await this._handleNonStreamResponse(proxyRequest, messageQueue, res);
      }
    } catch (error) {
      this._handleRequestError(error, res);
    } finally {
      this.connectionRegistry.removeMessageQueue(requestId);
      if (this.needsSwitchingAfterRequest) {
        this.logger.info(
          `[Auth] 轮换计数已达到切换阈值 (${this.usageCount}/${this.config.switchOnUses})，将在后台自动切换账号...`
        );
        this._switchToNextAuth().catch((err) => {
          this.logger.error(`[Auth] 后台账号切换任务失败: ${err.message}`);
        });
        this.needsSwitchingAfterRequest = false;
      }
    }
  }

  async processOpenAIRequest(req, res) {
    if (this.browserManager) {
      this.browserManager.notifyUserActivity();
    }
    const requestId = this._generateRequestId();
    const isOpenAIStream = req.body.stream === true;
    const model = req.body.model || "gemini-1.5-pro-latest";
    const systemStreamMode = this.serverSystem.streamingMode;
    const useRealStream = isOpenAIStream && systemStreamMode === "real";

    if (this.config.switchOnUses > 0) {
      this.usageCount++;
      // 仅在每10次或接近阈值时打印日志
      if (
        this.usageCount % 10 === 0 ||
        this.usageCount >= this.config.switchOnUses - 3
      ) {
        this.logger.info(
          `[Request] 账号轮换计数: ${this.usageCount}/${this.config.switchOnUses} (当前账号: ${this.currentAuthIndex})`
        );
      }
      if (this.usageCount >= this.config.switchOnUses) {
        this.needsSwitchingAfterRequest = true;
      }
    }

    let googleBody;
    try {
      googleBody = this._translateOpenAIToGoogle(req.body, model);
    } catch (error) {
      this.logger.error(`[Adapter] OpenAI请求翻译失败: ${error.message}`);
      return this._sendErrorResponse(
        res,
        400,
        "Invalid OpenAI request format."
      );
    }

    const googleEndpoint = useRealStream
      ? "streamGenerateContent"
      : "generateContent";
    const proxyRequest = {
      path: `/v1beta/models/${model}:${googleEndpoint}`,
      method: "POST",
      headers: { "Content-Type": "application/json" },
      query_params: useRealStream ? { alt: "sse" } : {},
      body: JSON.stringify(googleBody),
      request_id: requestId,
      is_generative: true,
      streaming_mode: useRealStream ? "real" : "fake",
      fix_thinking_config: this.serverSystem.fixThinkingConfig,
    };

    const messageQueue = this.connectionRegistry.createMessageQueue(requestId);

    try {
      this._forwardRequest(proxyRequest);
      const initialMessage = await messageQueue.dequeue();

      if (initialMessage.event_type === "error") {
        this.logger.error(
          `[Adapter] 收到来自浏览器的错误，将触发切换逻辑。状态码: ${initialMessage.status}, 消息: ${initialMessage.message}`
        );
        await this._handleRequestFailureAndSwitch(initialMessage, res);
        if (isOpenAIStream) {
          if (!res.writableEnded) {
            res.write("data: [DONE]\n\n");
            res.end();
          }
        } else {
          this._sendErrorResponse(
            res,
            initialMessage.status || 500,
            initialMessage.message
          );
        }
        return;
      }

      // [统计] 请求成功，记录统计数据
      this.statsManager.incrementDailyUsage();
      this.statsManager.incrementAccountUsage(this.currentAuthIndex);

      if (this.failureCount > 0) {
        this.logger.info(
          `✅ [Auth] OpenAI接口请求成功 - 失败计数已从 ${this.failureCount} 重置为 0`
        );
        this.failureCount = 0;
      }

      if (isOpenAIStream) {
        res.status(200).set({
          "Content-Type": "text/event-stream",
          "Cache-Control": "no-cache",
          Connection: "keep-alive",
        });

        if (useRealStream) {
          this.logger.info(`[Adapter] OpenAI 流式响应 (Real Mode) 已启动...`);
          let lastGoogleChunk = "";
          const streamState = { inThought: false };

          while (true) {
            const message = await messageQueue.dequeue(300000); // 5分钟超时
            if (message.type === "STREAM_END") {
              if (streamState.inThought) {
                const closeThoughtPayload = {
                  id: `chatcmpl-${requestId}`,
                  object: "chat.completion.chunk",
                  created: Math.floor(Date.now() / 1000),
                  model: model,
                  choices: [
                    {
                      index: 0,
                      delta: { content: "\n</think>\n" },
                      finish_reason: null,
                    },
                  ],
                };
                res.write(`data: ${JSON.stringify(closeThoughtPayload)}\n\n`);
              }
              res.write("data: [DONE]\n\n");
              break;
            }
            if (message.data) {
              // [修改] 将 streamState 传递给翻译函数
              const translatedChunk = this._translateGoogleToOpenAIStream(
                message.data,
                model,
                streamState
              );
              if (translatedChunk) {
                res.write(translatedChunk);
              }
              lastGoogleChunk = message.data;
            }
          }
        } else {
          this.logger.info(`[Adapter] OpenAI 流式响应 (Fake Mode) 已启动...`);

          let fullBody = "";
          while (true) {
            const message = await messageQueue.dequeue(300000);
            if (message.type === "STREAM_END") break;
            if (message.data) fullBody += message.data;
          }

          const translatedChunk = this._translateGoogleToOpenAIStream(
            fullBody,
            model
          );
          if (translatedChunk) {
            res.write(translatedChunk);
          }
          res.write("data: [DONE]\n\n");
          this.logger.info(
            `[Adapter] Fake模式：已一次性发送完整内容并结束流。`
          );
        }
      } else {
        let fullBody = "";
        while (true) {
          const message = await messageQueue.dequeue(300000);
          if (message.type === "STREAM_END") {
            break;
          }
          if (message.event_type === "chunk" && message.data) {
            fullBody += message.data;
          }
        }

        const googleResponse = JSON.parse(fullBody);
        const candidate = googleResponse.candidates?.[0];

        let responseContent = "";
        if (
          candidate &&
          candidate.content &&
          Array.isArray(candidate.content.parts)
        ) {
          const imagePart = candidate.content.parts.find((p) => p.inlineData);
          if (imagePart) {
            const image = imagePart.inlineData;
            responseContent = `![Generated Image](data:${image.mimeType};base64,${image.data})`;
            this.logger.info(
              "[Adapter] 从 parts.inlineData 中成功解析到图片。"
            );
          } else {
            let mainContent = "";
            let reasoningContent = "";

            candidate.content.parts.forEach((p) => {
              if (p.thought) {
                reasoningContent += p.text;
              } else {
                mainContent += p.text;
              }
            });

            responseContent = mainContent;
            var messageObj = {
              role: "assistant",
              content: responseContent,
            };
            if (reasoningContent) {
              messageObj.reasoning_content = reasoningContent;
            }
          }
        }

        const openaiResponse = {
          id: `chatcmpl-${requestId}`,
          object: "chat.completion",
          created: Math.floor(Date.now() / 1000),
          model: model,
          choices: [
            {
              index: 0,
              // 使用上面构建的 messageObj
              message: messageObj || { role: "assistant", content: "" },
              finish_reason: candidate?.finishReason,
            },
          ],
        };

        const finishReason = candidate?.finishReason || "UNKNOWN";
        this.logger.info(
          `✅ [Request] OpenAI非流式响应结束，原因: ${finishReason}，请求ID: ${requestId}`
        );

        res.status(200).json(openaiResponse);
      }
    } catch (error) {
      this._handleRequestError(error, res);
    } finally {
      this.connectionRegistry.removeMessageQueue(requestId);
      if (this.needsSwitchingAfterRequest) {
        this.logger.info(
          `[Auth] OpenAI轮换计数已达到切换阈值 (${this.usageCount}/${this.config.switchOnUses})，将在后台自动切换账号...`
        );
        this._switchToNextAuth().catch((err) => {
          this.logger.error(`[Auth] 后台账号切换任务失败: ${err.message}`);
        });
        this.needsSwitchingAfterRequest = false;
      }
      if (!res.writableEnded) {
        res.end();
      }
    }
  }

  // --- 新增一个辅助方法，用于发送取消指令 ---
  _cancelBrowserRequest(requestId) {
    const connection = this.connectionRegistry.getFirstConnection();
    if (connection) {
      this.logger.info(
        `[Request] 正在向浏览器发送取消请求 #${requestId} 的指令...`
      );
      connection.send(
        JSON.stringify({
          event_type: "cancel_request",
          request_id: requestId,
        })
      );
    } else {
      this.logger.warn(
        `[Request] 无法发送取消指令：没有可用的浏览器WebSocket连接。`
      );
    }
  }

  _generateRequestId() {
    return `${Date.now()}_${Math.random().toString(36).substring(2, 11)}`;
  }
  _buildProxyRequest(req, requestId) {
    let bodyObj = req.body;
    // [修改] 排除 gemini-2.5-flash-image 不受强制思维链影响
    const isExcludedModel = req.path && req.path.includes("gemini-2.5-flash-image");

    if (
      this.serverSystem.forceThinking &&
      !isExcludedModel &&
      req.method === "POST" &&
      bodyObj &&
      bodyObj.contents
    ) {
      if (!bodyObj.generationConfig) {
        bodyObj.generationConfig = {};
      }

      if (!bodyObj.generationConfig.thinkingConfig) {
        this.logger.info(
          `[Proxy] ⚠️ (Google原生格式) 强制推理已启用，且客户端未提供配置，正在注入 thinkingConfig...`
        );
        bodyObj.generationConfig.thinkingConfig = { includeThoughts: true };
      } else {
        // [修正] 即使有配置，也要检查 includeThoughts 是否为 true
        if (bodyObj.generationConfig.thinkingConfig.includeThoughts !== true) {
          this.logger.info(
            `[Proxy] ⚠️ (Google原生格式) 强制推理已启用，但客户端配置未开启 includeThoughts，正在修正...`
          );
          bodyObj.generationConfig.thinkingConfig.includeThoughts = true;
        } else {
          this.logger.info(
            `[Proxy] ✅ (Google原生格式) 检测到客户端自带推理配置且已开启 includeThoughts，无需干预。`
          );
        }
      }
    }

    let requestBody = "";
    if (bodyObj) {
      requestBody = JSON.stringify(bodyObj);
    }

    return {
      path: req.path,
      method: req.method,
      headers: req.headers,
      query_params: req.query,
      body: requestBody,
      request_id: requestId,
      streaming_mode: this.serverSystem.streamingMode,
      fix_thinking_config: this.serverSystem.fixThinkingConfig,
    };
  }
  _forwardRequest(proxyRequest) {
    const connection = this.connectionRegistry.getFirstConnection();
    if (connection) {
      connection.send(JSON.stringify(proxyRequest));
    } else {
      throw new Error("无法转发请求：没有可用的WebSocket连接。");
    }
  }
  _sendErrorChunkToClient(res, errorMessage) {
    const errorPayload = {
      error: {
        message: `[代理系统提示] ${errorMessage}`,
        type: "proxy_error",
        code: "proxy_error",
      },
    };
    const chunk = `data: ${JSON.stringify(errorPayload)}\n\n`;
    if (res && !res.writableEnded) {
      res.write(chunk);
      this.logger.info(`[Request] 已向客户端发送标准错误信号: ${errorMessage}`);
    }
  }

  async _handlePseudoStreamResponse(proxyRequest, messageQueue, req, res) {
    this.logger.info(
      "[Request] 客户端启用流式传输 (fake)，进入伪流式处理模式..."
    );
    res.status(200).set({
      "Content-Type": "text/event-stream",
      "Cache-Control": "no-cache",
      Connection: "keep-alive",
    });
    const connectionMaintainer = setInterval(() => {
      if (!res.writableEnded) res.write(": keep-alive\n\n");
    }, 3000);

    try {
      let lastMessage,
        requestFailed = false;

      // 我们的重试循环（即使只跑一次）
      for (let attempt = 1; attempt <= this.maxRetries; attempt++) {
        if (attempt > 1) {
          this.logger.info(
            `[Request] 请求尝试 #${attempt}/${this.maxRetries}...`
          );
        }
        this._forwardRequest(proxyRequest);
        try {
          const timeoutPromise = new Promise((_, reject) =>
            setTimeout(
              () =>
                reject(
                  new Error("Response from browser timed out after 300 seconds")
                ),
              300000
            )
          );
          lastMessage = await Promise.race([
            messageQueue.dequeue(),
            timeoutPromise,
          ]);
        } catch (timeoutError) {
          this.logger.error(`[Request] 致命错误: ${timeoutError.message}`);
          lastMessage = {
            event_type: "error",
            status: 504,
            message: timeoutError.message,
          };
        }

        if (lastMessage.event_type === "error") {
          // --- 核心修改：在这里就区分，避免打印不必要的“失败”日志 ---
          if (
            !(
              lastMessage.message &&
              lastMessage.message.includes("The user aborted a request")
            )
          ) {
            // 只有在不是“用户取消”的情况下，才打印“尝试失败”的警告
            this.logger.warn(
              `[Request] 尝试 #${attempt} 失败: 收到 ${
                lastMessage.status || "未知"
              } 错误。 - ${lastMessage.message}`
            );
          }

          if (attempt < this.maxRetries) {
            await new Promise((resolve) =>
              setTimeout(resolve, this.retryDelay)
            );
            continue;
          }
          requestFailed = true;
        }
        break;
      }

      // 处理最终结果
      if (requestFailed) {
        if (
          lastMessage.message &&
          lastMessage.message.includes("The user aborted a request")
        ) {
          this.logger.info(
            `[Request] 请求 #${proxyRequest.request_id} 已由用户妥善取消，不计入失败统计。`
          );
        } else {
          this.logger.error(
            `[Request] 所有 ${this.maxRetries} 次重试均失败，将计入失败统计。`
          );
          await this._handleRequestFailureAndSwitch(lastMessage, res);
          this._sendErrorChunkToClient(
            res,
            `请求最终失败: ${lastMessage.message}`
          );
        }
        return;
      }

      // 成功的逻辑
      if (proxyRequest.is_generative) {
        // [统计] 请求成功，记录统计数据
        this.statsManager.incrementDailyUsage();
        this.statsManager.incrementAccountUsage(this.currentAuthIndex);

        if (this.failureCount > 0) {
          this.logger.info(
            `✅ [Auth] 生成请求成功 - 失败计数已从 ${this.failureCount} 重置为 0`
          );
          this.failureCount = 0;
        }
      }
      const dataMessage = await messageQueue.dequeue();
      const endMessage = await messageQueue.dequeue();
      if (dataMessage.data) {
        res.write(`data: ${dataMessage.data}\n\n`);
      }
      if (endMessage.type !== "STREAM_END") {
        this.logger.warn("[Request] 未收到预期的流结束信号。");
      }
      try {
        const fullResponse = JSON.parse(dataMessage.data);
        const finishReason =
          fullResponse.candidates?.[0]?.finishReason || "UNKNOWN";
        this.logger.info(
          `✅ [Request] 响应结束，原因: ${finishReason}，请求ID: ${proxyRequest.request_id}`
        );
      } catch (e) {}
      res.write("data: [DONE]\n\n");
    } catch (error) {
      this._handleRequestError(error, res);
    } finally {
      clearInterval(connectionMaintainer);
      if (!res.writableEnded) {
        res.end();
      }
      this.logger.info(
        `[Request] 响应处理结束，请求ID: ${proxyRequest.request_id}`
      );
    }
  }

  async _handleRealStreamResponse(proxyRequest, messageQueue, res) {
    this.logger.info(`[Request] 请求已派发给浏览器端处理...`);
    this._forwardRequest(proxyRequest);
    const headerMessage = await messageQueue.dequeue();

    if (headerMessage.event_type === "error") {
      if (
        headerMessage.message &&
        headerMessage.message.includes("The user aborted a request")
      ) {
        this.logger.info(
          `[Request] 请求 #${proxyRequest.request_id} 已被用户妥善取消，不计入失败统计。`
        );
      } else {
        this.logger.error(`[Request] 请求失败，将计入失败统计。`);
        await this._handleRequestFailureAndSwitch(headerMessage, null);
        return this._sendErrorResponse(
          res,
          headerMessage.status,
          headerMessage.message
        );
      }
      if (!res.writableEnded) res.end();
      return;
    }

    // --- 核心修改：只有在生成请求成功时，才重置失败计数 ---
    if (proxyRequest.is_generative) {
      // [统计] 请求成功，记录统计数据
      this.statsManager.incrementDailyUsage();
      this.statsManager.incrementAccountUsage(this.currentAuthIndex);

      if (this.failureCount > 0) {
        this.logger.info(
          `✅ [Auth] 生成请求成功 - 失败计数已从 ${this.failureCount} 重置为 0`
        );
        this.failureCount = 0;
      }
    }
    // --- 修改结束 ---

    this._setResponseHeaders(res, headerMessage);

    let contentType = res.get("Content-Type") || "";

    // [Fix] 如果 Content-Type 缺失，且状态码正常，默认为 text/event-stream
    if (!contentType && (headerMessage.status === 200 || !headerMessage.status)) {
      res.set("Content-Type", "text/event-stream");
      contentType = "text/event-stream";
    }

    // [Fix] RikkaHub 兼容性修复：
    // 1. 修正 text/plain 或 application/octet-stream
    // 2. 修正流式请求中出现的 application/json (导致 RikkaHub 报错 Invalid content-type: application/json)
    const isErrorStatus = headerMessage.status && headerMessage.status >= 400;
    
    if (
      !isErrorStatus &&
      (contentType.includes("text/plain") ||
        contentType.includes("application/octet-stream") ||
        contentType.includes("application/json"))
    ) {
      // 既然进入了 _handleRealStreamResponse，说明客户端期望流式响应
      res.set("Content-Type", "text/event-stream");
      this.logger.info(
        `[Request] 已将 Content-Type 从 "${contentType}" 强制修正为 "text/event-stream" 以兼容 RikkaHub (流式模式)。`
      );
    }

    this.logger.info("[Request] 开始流式传输...");
    try {
      let lastChunk = "";
      while (true) {
        const dataMessage = await messageQueue.dequeue(30000);
        if (dataMessage.type === "STREAM_END") {
          this.logger.info("[Request] 收到流结束信号。");
          break;
        }
        if (dataMessage.data) {
          res.write(dataMessage.data);
          lastChunk = dataMessage.data;
        }
      }
      try {
        if (lastChunk.startsWith("data: ")) {
          const jsonString = lastChunk.substring(6).trim();
          if (jsonString) {
            const lastResponse = JSON.parse(jsonString);
            const finishReason =
              lastResponse.candidates?.[0]?.finishReason || "UNKNOWN";
            this.logger.info(
              `✅ [Request] 响应结束，原因: ${finishReason}，请求ID: ${proxyRequest.request_id}`
            );
          }
        }
      } catch (e) {}
    } catch (error) {
      if (error.message !== "Queue timeout") throw error;
      this.logger.warn("[Request] 真流式响应超时，可能流已正常结束。");
    } finally {
      if (!res.writableEnded) res.end();
      this.logger.info(
        `[Request] 真流式响应连接已关闭，请求ID: ${proxyRequest.request_id}`
      );
    }
  }

  async _handleNonStreamResponse(proxyRequest, messageQueue, res) {
    this.logger.info(`[Request] 进入非流式处理模式...`);

    // 转发请求到浏览器端
    this._forwardRequest(proxyRequest);

    try {
      // 1. 等待响应头信息
      const headerMessage = await messageQueue.dequeue();
      if (headerMessage.event_type === "error") {
        // ... (错误处理逻辑保持不变)
        if (headerMessage.message?.includes("The user aborted a request")) {
          this.logger.info(
            `[Request] 请求 #${proxyRequest.request_id} 已被用户妥善取消。`
          );
        } else {
          this.logger.error(
            `[Request] 浏览器端返回错误: ${headerMessage.message}`
          );
          await this._handleRequestFailureAndSwitch(headerMessage, null);
        }
        return this._sendErrorResponse(
          res,
          headerMessage.status || 500,
          headerMessage.message
        );
      }

      // 2. 准备一个缓冲区，并确保循环等待直到收到结束信号
      let fullBody = "";
      while (true) {
        const message = await messageQueue.dequeue(300000);
        if (message.type === "STREAM_END") {
          this.logger.info("[Request] 收到结束信号，数据接收完毕。");
          break;
        }
        if (message.event_type === "chunk" && message.data) {
          fullBody += message.data;
        }
      }

      // 3. 重置失败计数器（如果需要）和记录统计
      if (proxyRequest.is_generative) {
        // [统计] 请求成功，记录统计数据
        this.statsManager.incrementDailyUsage();
        this.statsManager.incrementAccountUsage(this.currentAuthIndex);

        if (this.failureCount > 0) {
          this.logger.info(
            `✅ [Auth] 非流式生成请求成功 - 失败计数已从 ${this.failureCount} 重置为 0`
          );
          this.failureCount = 0;
        }
      }

      // [核心修正] 对Google原生格式的响应进行智能图片处理
      try {
        let parsedBody = JSON.parse(fullBody);
        let needsReserialization = false;

        const candidate = parsedBody.candidates?.[0];
        if (candidate?.content?.parts) {
          const imagePartIndex = candidate.content.parts.findIndex(
            (p) => p.inlineData
          );

          if (imagePartIndex > -1) {
            this.logger.info(
              "[Proxy] 检测到Google格式响应中的图片数据，正在转换为Markdown..."
            );
            const imagePart = candidate.content.parts[imagePartIndex];
            const image = imagePart.inlineData;

            // 创建一个新的 text part 来替换原来的 inlineData part
            const markdownTextPart = {
              text: `![Generated Image](data:${image.mimeType};base64,${image.data})`,
            };

            // 替换掉原来的部分
            candidate.content.parts[imagePartIndex] = markdownTextPart;
            needsReserialization = true;
          }
        }

        if (needsReserialization) {
          fullBody = JSON.stringify(parsedBody); // 如果处理了图片，重新序列化
        }
      } catch (e) {
        this.logger.warn(
          `[Proxy] 响应体不是有效的JSON，或在处理图片时出错: ${e.message}`
        );
        // 如果出错，则什么都不做，直接发送原始的 fullBody
      }

      try {
        const fullResponse = JSON.parse(fullBody);
        const finishReason =
          fullResponse.candidates?.[0]?.finishReason || "UNKNOWN";
        this.logger.info(
          `✅ [Request] 响应结束，原因: ${finishReason}，请求ID: ${proxyRequest.request_id}`
        );
      } catch (e) {}

      // 4. 设置正确的JSON响应头，并一次性发送处理过的全部数据
      // 如果上游没有返回 Content-Type，或者我们之前没有设置，这里显式设置为 json
      if (!res.get("Content-Type")) {
        res.type("application/json");
      } else {
        res.status(headerMessage.status || 200);
      }
      
      res.send(fullBody || "{}");

      this.logger.info(`[Request] 已向客户端发送完整的非流式响应。`);
    } catch (error) {
      this._handleRequestError(error, res);
    }
  }

  _getKeepAliveChunk(req) {
    if (req.path.includes("chat/completions")) {
      const payload = {
        id: `chatcmpl-${this._generateRequestId()}`,
        object: "chat.completion.chunk",
        created: Math.floor(Date.now() / 1000),
        model: "gpt-4",
        choices: [{ index: 0, delta: {}, finish_reason: null }],
      };
      return `data: ${JSON.stringify(payload)}\n\n`;
    }
    if (
      req.path.includes("generateContent") ||
      req.path.includes("streamGenerateContent")
    ) {
      const payload = {
        candidates: [
          {
            content: { parts: [{ text: "" }], role: "model" },
            finishReason: null,
            index: 0,
            safetyRatings: [],
          },
        ],
      };
      return `data: ${JSON.stringify(payload)}\n\n`;
    }
    return "data: {}\n\n";
  }

  _setResponseHeaders(res, headerMessage) {
    res.status(headerMessage.status || 200);
    const headers = headerMessage.headers || {};
    const ignoredHeaders = [
      "content-length",
      "content-encoding",
      "transfer-encoding",
      "connection",
      "keep-alive",
    ];

    Object.entries(headers).forEach(([name, value]) => {
      const lowerName = name.toLowerCase();
      if (!ignoredHeaders.includes(lowerName)) {
        res.set(name, value);
      }
    });
  }
  _handleRequestError(error, res) {
    if (res.headersSent) {
      this.logger.error(`[Request] 请求处理错误 (头已发送): ${error.message}`);
      if (this.serverSystem.streamingMode === "fake")
        this._sendErrorChunkToClient(res, `处理失败: ${error.message}`);
      if (!res.writableEnded) res.end();
    } else {
      this.logger.error(`[Request] 请求处理错误: ${error.message}`);
      const status = error.message.includes("超时") ? 504 : 500;
      this._sendErrorResponse(res, status, `代理错误: ${error.message}`);
    }
  }

  _sendErrorResponse(res, status, message) {
    if (!res.headersSent) {
      // 1. 创建一个符合API规范的JSON错误对象
      const errorPayload = {
        error: {
          code: status || 500,
          message: message,
          status: "SERVICE_UNAVAILABLE", // 这是一个示例状态名
        },
      };
      // 2. 设置响应类型为 application/json 并发送
      res
        .status(status || 500)
        .type("application/json")
        .send(JSON.stringify(errorPayload));
    }
  }

  _translateOpenAIToGoogle(openaiBody, modelName = "") {
    // this.logger.debug("[Adapter] 开始将OpenAI请求格式翻译为Google格式...");

    let systemInstruction = null;
    const googleContents = [];

    // 1. 分离出 system 指令
    const systemMessages = openaiBody.messages.filter(
      (msg) => msg.role === "system"
    );
    if (systemMessages.length > 0) {
      // 将所有 system message 的内容合并
      const systemContent = systemMessages.map((msg) => msg.content).join("\n");
      systemInstruction = {
        // Google Gemini 1.5 Pro 开始正式支持 system instruction
        role: "system",
        parts: [{ text: systemContent }],
      };
    }

    // 2. 转换 user 和 assistant 消息
    const conversationMessages = openaiBody.messages.filter(
      (msg) => msg.role !== "system"
    );
    for (const message of conversationMessages) {
      const googleParts = [];

      // [核心改进] 判断 content 是字符串还是数组
      if (typeof message.content === "string") {
        // a. 如果是纯文本
        googleParts.push({ text: message.content });
      } else if (Array.isArray(message.content)) {
        // b. 如果是图文混合内容
        for (const part of message.content) {
          if (part.type === "text") {
            googleParts.push({ text: part.text });
          } else if (part.type === "image_url" && part.image_url) {
            // 从 data URL 中提取 mimetype 和 base64 数据
            const dataUrl = part.image_url.url;
            const match = dataUrl.match(/^data:(image\/.*?);base64,(.*)$/);
            if (match) {
              googleParts.push({
                inlineData: {
                  mimeType: match[1],
                  data: match[2],
                },
              });
            }
          }
        }
      }

      googleContents.push({
        role: message.role === "assistant" ? "model" : "user",
        parts: googleParts,
      });
    }

    // 3. 构建最终的Google请求体
    const googleRequest = {
      contents: googleContents,
      ...(systemInstruction && {
        systemInstruction: { parts: systemInstruction.parts },
      }),
    };

    // 4. 转换生成参数
    const generationConfig = {
      temperature: openaiBody.temperature,
      topP: openaiBody.top_p,
      topK: openaiBody.top_k,
      maxOutputTokens: openaiBody.max_tokens,
      stopSequences: openaiBody.stop,
    };

    const extraBody = openaiBody.extra_body || {};
    let rawThinkingConfig =
      extraBody.google?.thinking_config ||
      extraBody.google?.thinkingConfig ||
      extraBody.thinkingConfig ||
      extraBody.thinking_config ||
      openaiBody.thinkingConfig ||
      openaiBody.thinking_config;

    let thinkingConfig = null;

    if (rawThinkingConfig) {
      // 2. 格式清洗：将 snake_case (下划线) 转换为 camelCase (驼峰)
      thinkingConfig = {};

      // 处理开关
      if (rawThinkingConfig.include_thoughts !== undefined) {
        thinkingConfig.includeThoughts = rawThinkingConfig.include_thoughts;
      } else if (rawThinkingConfig.includeThoughts !== undefined) {
        thinkingConfig.includeThoughts = rawThinkingConfig.includeThoughts;
      }

      // 处理 Budget (预算)
      // if (rawThinkingConfig.thinking_budget !== undefined) {
      // thinkingConfig.thinkingBudgetTokenLimit =
      // rawThinkingConfig.thinking_budget;
      //} else if (rawThinkingConfig.thinkingBudget !== undefined) {
      //thinkingConfig.thinkingBudgetTokenLimit =
      //rawThinkingConfig.thinkingBudget;
      //}

      this.logger.info(
        `[Adapter] 成功提取并转换推理配置: ${JSON.stringify(thinkingConfig)}`
      );
    }

    // 3. 如果没找到配置，尝试识别 OpenAI 标准参数 'reasoning_effort'
    if (!thinkingConfig) {
      const effort = openaiBody.reasoning_effort || extraBody.reasoning_effort;
      if (effort) {
        this.logger.info(
          `[Adapter] 检测到 OpenAI 标准推理参数 (reasoning_effort: ${effort})，自动转换为 Google 格式。`
        );
        thinkingConfig = { includeThoughts: true };
      }
    }

    // 4. 强制开启逻辑 (WebUI开关)
    const isExcludedModel = modelName && modelName.includes("gemini-2.5-flash-image");
    if (this.serverSystem.forceThinking && !isExcludedModel) {
      if (!thinkingConfig) {
        this.logger.info(
          "[Adapter] ⚠️ 强制推理已启用，且客户端未提供配置，正在注入 thinkingConfig..."
        );
        thinkingConfig = { includeThoughts: true };
      } else if (thinkingConfig.includeThoughts !== true) {
        this.logger.info(
          "[Adapter] ⚠️ 强制推理已启用，但客户端配置未开启 includeThoughts，正在修正..."
        );
        thinkingConfig.includeThoughts = true;
      }
    }

    // 5. 写入最终配置
    if (thinkingConfig) {
      generationConfig.thinkingConfig = thinkingConfig;
    }

    googleRequest.generationConfig = generationConfig;

    // 5. 安全设置
    googleRequest.safetySettings = [
      { category: "HARM_CATEGORY_HARASSMENT", threshold: "BLOCK_NONE" },
      { category: "HARM_CATEGORY_HATE_SPEECH", threshold: "BLOCK_NONE" },
      { category: "HARM_CATEGORY_SEXUALLY_EXPLICIT", threshold: "BLOCK_NONE" },
      { category: "HARM_CATEGORY_DANGEROUS_CONTENT", threshold: "BLOCK_NONE" },
    ];

    return googleRequest;
  }

  _translateGoogleToOpenAIStream(googleChunk, modelName = "gemini-pro") {
    if (!googleChunk || googleChunk.trim() === "") {
      return null;
    }

    let jsonString = googleChunk;
    if (jsonString.startsWith("data: ")) {
      jsonString = jsonString.substring(6).trim();
    }

    if (!jsonString || jsonString === "[DONE]") return null;

    let googleResponse;
    try {
      googleResponse = JSON.parse(jsonString);
    } catch (e) {
      this.logger.warn(`[Adapter] 无法解析Google返回的JSON块: ${jsonString}`);
      return null;
    }

    const candidate = googleResponse.candidates?.[0];
    if (!candidate) {
      if (googleResponse.promptFeedback) {
        this.logger.warn(
          `[Adapter] Google返回了promptFeedback，可能已被拦截: ${JSON.stringify(
            googleResponse.promptFeedback
          )}`
        );
        const errorText = `[ProxySystem Error] Request blocked due to safety settings. Finish Reason: ${googleResponse.promptFeedback.blockReason}`;
        return `data: ${JSON.stringify({
          id: `chatcmpl-${this._generateRequestId()}`,
          object: "chat.completion.chunk",
          created: Math.floor(Date.now() / 1000),
          model: modelName,
          choices: [
            { index: 0, delta: { content: errorText }, finish_reason: "stop" },
          ],
        })}\n\n`;
      }
      return null;
    }

    const delta = {};

    if (candidate.content && Array.isArray(candidate.content.parts)) {
      const imagePart = candidate.content.parts.find((p) => p.inlineData);

      if (imagePart) {
        const image = imagePart.inlineData;
        delta.content = `![Generated Image](data:${image.mimeType};base64,${image.data})`;
        this.logger.info("[Adapter] 从流式响应块中成功解析到图片。");
      } else {
        // 遍历所有部分，分离思考内容和正文内容
        let contentAccumulator = "";
        let reasoningAccumulator = "";

        for (const part of candidate.content.parts) {
          // Google API 的 thought 标记
          if (part.thought === true) {
            reasoningAccumulator += part.text || "";
          } else {
            contentAccumulator += part.text || "";
          }
        }

        // 只有当有内容时才添加到 delta 中
        if (reasoningAccumulator) {
          delta.reasoning_content = reasoningAccumulator;
        }
        if (contentAccumulator) {
          delta.content = contentAccumulator;
        }
      }
    }

    // 如果没有任何内容变更，则不返回数据（避免空行）
    if (!delta.content && !delta.reasoning_content && !candidate.finishReason) {
      return null;
    }

    const openaiResponse = {
      id: `chatcmpl-${this._generateRequestId()}`,
      object: "chat.completion.chunk",
      created: Math.floor(Date.now() / 1000),
      model: modelName,
      choices: [
        {
          index: 0,
          delta: delta, // 使用包含 reasoning_content 的 delta
          finish_reason: candidate.finishReason || null,
        },
      ],
    };

    return `data: ${JSON.stringify(openaiResponse)}\n\n`;
  }
}

class ProxyServerSystem extends EventEmitter {
  constructor() {
    super();
    this.logger = new LoggingService("ProxySystem");
    this._loadConfiguration(); // 这个函数会执行下面的_loadConfiguration
    this.streamingMode = this.config.streamingMode;

    this.forceThinking = false;
    this.fixThinkingConfig = true;

    this.authSource = new AuthSource(this.logger);
    this.statsManager = new StatsManager(this.logger); // 初始化 StatsManager
    this.browserManager = new BrowserManager(
      this.logger,
      this.config,
      this.authSource
    );
    this.connectionRegistry = new ConnectionRegistry(this.logger);
    this.requestHandler = new RequestHandler(
      this,
      this.connectionRegistry,
      this.logger,
      this.browserManager,
      this.config,
      this.authSource,
      this.statsManager // 传入 StatsManager
    );

    this.httpServer = null;
    this.wsServer = null;
  }

  // ===== 所有函数都已正确放置在类内部 =====

  _loadConfiguration() {
    let config = {
      httpPort: 7860,
      host: "0.0.0.0",
      wsPort: 9998,
      streamingMode: "real",
      failureThreshold: 3,
      switchOnUses: 40,
      maxRetries: 1,
      retryDelay: 2000,
      browserExecutablePath: null,
      apiKeys: [],
      immediateSwitchStatusCodes: [429, 503],
      // [新增] 用于追踪API密钥来源
      apiKeySource: "未设置",
    };

    const configPath = path.join(__dirname, "config.json");
    try {
      if (fs.existsSync(configPath)) {
        const fileConfig = JSON.parse(fs.readFileSync(configPath, "utf-8"));
        config = { ...config, ...fileConfig };
        this.logger.info("[System] 已从 config.json 加载配置。");
      }
    } catch (error) {
      this.logger.warn(`[System] 无法读取或解析 config.json: ${error.message}`);
    }

    if (process.env.PORT)
      config.httpPort = parseInt(process.env.PORT, 10) || config.httpPort;
    if (process.env.HOST) config.host = process.env.HOST;
    if (process.env.STREAMING_MODE)
      config.streamingMode = process.env.STREAMING_MODE;
    if (process.env.FAILURE_THRESHOLD)
      config.failureThreshold =
        parseInt(process.env.FAILURE_THRESHOLD, 10) || config.failureThreshold;
    if (process.env.SWITCH_ON_USES)
      config.switchOnUses =
        parseInt(process.env.SWITCH_ON_USES, 10) || config.switchOnUses;
    if (process.env.MAX_RETRIES)
      config.maxRetries =
        parseInt(process.env.MAX_RETRIES, 10) || config.maxRetries;
    if (process.env.RETRY_DELAY)
      config.retryDelay =
        parseInt(process.env.RETRY_DELAY, 10) || config.retryDelay;
    if (process.env.CAMOUFOX_EXECUTABLE_PATH)
      config.browserExecutablePath = process.env.CAMOUFOX_EXECUTABLE_PATH;
    if (process.env.API_KEYS) {
      config.apiKeys = process.env.API_KEYS.split(",");
    }

    let rawCodes = process.env.IMMEDIATE_SWITCH_STATUS_CODES;
    let codesSource = "环境变量";

    if (
      !rawCodes &&
      config.immediateSwitchStatusCodes &&
      Array.isArray(config.immediateSwitchStatusCodes)
    ) {
      rawCodes = config.immediateSwitchStatusCodes.join(",");
      codesSource = "config.json 文件或默认值";
    }

    if (rawCodes && typeof rawCodes === "string") {
      config.immediateSwitchStatusCodes = rawCodes
        .split(",")
        .map((code) => parseInt(String(code).trim(), 10))
        .filter((code) => !isNaN(code) && code >= 400 && code <= 599);
      if (config.immediateSwitchStatusCodes.length > 0) {
        this.logger.info(`[System] 已从 ${codesSource} 加载“立即切换报错码”。`);
      }
    } else {
      config.immediateSwitchStatusCodes = [];
    }

    if (Array.isArray(config.apiKeys)) {
      config.apiKeys = config.apiKeys
        .map((k) => String(k).trim())
        .filter((k) => k);
    } else {
      config.apiKeys = [];
    }

    // [修改] 更新API密钥来源的判断逻辑
    if (config.apiKeys.length > 0) {
      config.apiKeySource = "自定义";
    } else {
      config.apiKeys = ["123456"];
      config.apiKeySource = "默认";
      this.logger.info("[System] 未设置任何API Key，已启用默认密码: 123456");
    }

    const modelsPath = path.join(__dirname, "models.json");
    try {
      if (fs.existsSync(modelsPath)) {
        const modelsFileContent = fs.readFileSync(modelsPath, "utf-8");
        config.modelList = JSON.parse(modelsFileContent); // 将读取到的模型列表存入config对象
        this.logger.info(
          `[System] 已从 models.json 成功加载 ${config.modelList.length} 个模型。`
        );
      } else {
        this.logger.warn(
          `[System] 未找到 models.json 文件，将使用默认模型列表。`
        );
        config.modelList = ["gemini-1.5-pro-latest"]; // 提供一个备用模型，防止服务启动失败
      }
    } catch (error) {
      this.logger.error(
        `[System] 读取或解析 models.json 失败: ${error.message}，将使用默认模型列表。`
      );
      config.modelList = ["gemini-1.5-pro-latest"]; // 出错时也使用备用模型
    }

    this.config = config;
    this.logger.info("================ [ 生效配置 ] ================");
    this.logger.info(`  HTTP 服务端口: ${this.config.httpPort}`);
    this.logger.info(`  监听地址: ${this.config.host}`);
    this.logger.info(`  流式模式: ${this.config.streamingMode}`);
    this.logger.info(
      `  轮换计数切换阈值: ${
        this.config.switchOnUses > 0
          ? `每 ${this.config.switchOnUses} 次请求后切换`
          : "已禁用"
      }`
    );
    this.logger.info(
      `  失败计数切换: ${
        this.config.failureThreshold > 0
          ? `失败${this.config.failureThreshold} 次后切换`
          : "已禁用"
      }`
    );
    this.logger.info(
      `  立即切换报错码: ${
        this.config.immediateSwitchStatusCodes.length > 0
          ? this.config.immediateSwitchStatusCodes.join(", ")
          : "已禁用"
      }`
    );
    this.logger.info(`  单次请求最大重试: ${this.config.maxRetries}次`);
    this.logger.info(`  重试间隔: ${this.config.retryDelay}ms`);
    this.logger.info(`  API 密钥来源: ${this.config.apiKeySource}`); // 在启动日志中也显示出来
    this.logger.info(
      "============================================================="
    );
  }

  async start(initialAuthIndex = null) {
    // <<<--- 1. 重新接收参数
    this.logger.info("[System] 开始弹性启动流程...");
    const allAvailableIndices = this.authSource.availableIndices;

    if (allAvailableIndices.length === 0) {
      throw new Error("没有任何可用的认证源，无法启动。");
    }

    // 2. <<<--- 创建一个优先尝试的启动顺序列表 --->>>
    let startupOrder = [...allAvailableIndices];
    if (initialAuthIndex && allAvailableIndices.includes(initialAuthIndex)) {
      this.logger.info(
        `[System] 检测到指定启动索引 #${initialAuthIndex}，将优先尝试。`
      );
      // 将指定索引放到数组第一位，其他索引保持原状
      startupOrder = [
        initialAuthIndex,
        ...allAvailableIndices.filter((i) => i !== initialAuthIndex),
      ];
    } else {
      if (initialAuthIndex) {
        this.logger.warn(
          `[System] 指定的启动索引 #${initialAuthIndex} 无效或不可用，将按默认顺序启动。`
        );
      }
      this.logger.info(
        `[System] 未指定有效启动索引，将按默认顺序 [${startupOrder.join(
          ", "
        )}] 尝试。`
      );
    }

    let isStarted = false;
    // 3. <<<--- 遍历这个新的、可能被重排过的顺序列表 --->>>
    for (const index of startupOrder) {
      try {
        this.logger.info(`[System] 尝试使用账号 #${index} 启动服务...`);
        await this.browserManager.launchOrSwitchContext(index);

        isStarted = true;
        this.logger.info(`[System] ✅ 使用账号 #${index} 成功启动！`);
        break; // 成功启动，跳出循环
      } catch (error) {
        this.logger.error(
          `[System] ❌ 使用账号 #${index} 启动失败。原因: ${error.message}`
        );
        // 失败了，循环将继续，尝试下一个账号
      }
    }

    if (!isStarted) {
      // 如果所有账号都尝试失败了
      throw new Error("所有认证源均尝试失败，服务器无法启动。");
    }

    // 只有在浏览器成功启动后，才启动网络服务
    await this._startHttpServer();
    await this._startWebSocketServer();
    this.logger.info(`[System] 代理服务器系统启动完成。`);
    this.emit("started");
  }

  _createAuthMiddleware() {
    const basicAuth = require("basic-auth"); // 确保此行存在，为admin认证提供支持

    return (req, res, next) => {
      const serverApiKeys = this.config.apiKeys;
      if (!serverApiKeys || serverApiKeys.length === 0) {
        return next();
      }

      let clientKey = null;
      if (req.headers["x-goog-api-key"]) {
        clientKey = req.headers["x-goog-api-key"];
      } else if (
        req.headers.authorization &&
        req.headers.authorization.startsWith("Bearer ")
      ) {
        clientKey = req.headers.authorization.substring(7);
      } else if (req.headers["x-api-key"]) {
        clientKey = req.headers["x-api-key"];
      } else if (req.query.key) {
        clientKey = req.query.key;
      }

      if (clientKey && serverApiKeys.includes(clientKey)) {
        this.logger.info(
          `[Auth] API Key验证通过 (来自: ${
            req.headers["x-forwarded-for"] || req.ip
          })`
        );
        if (req.query.key) {
          delete req.query.key;
        }
        return next();
      }

      // 对于没有有效API Key的请求，返回401错误
      // 注意：健康检查等逻辑已在_createExpressApp中提前处理
      if (req.path !== "/favicon.ico") {
        const clientIp = req.headers["x-forwarded-for"] || req.ip;
        this.logger.warn(
          `[Auth] 访问密码错误或缺失，已拒绝请求。IP: ${clientIp}, Path: ${req.path}`
        );
      }

      return res.status(401).json({
        error: {
          message:
            "Access denied. A valid API key was not found or is incorrect.",
        },
      });
    };
  }

  async _startHttpServer() {
    const app = this._createExpressApp();
    this.httpServer = http.createServer(app);

    this.httpServer.keepAliveTimeout = 120000;
    this.httpServer.headersTimeout = 125000;
    this.httpServer.requestTimeout = 120000;

    return new Promise((resolve) => {
      this.httpServer.listen(this.config.httpPort, this.config.host, () => {
        this.logger.info(
          `[System] HTTP服务器已在 http://${this.config.host}:${this.config.httpPort} 上监听`
        );
        this.logger.info(
          `[System] Keep-Alive 超时已设置为 ${
            this.httpServer.keepAliveTimeout / 1000
          } 秒。`
        );
        resolve();
      });
    });
  }

  _createExpressApp() {
    const app = express();

    app.use((req, res, next) => {
      res.header("Access-Control-Allow-Origin", "*");
      res.header(
        "Access-Control-Allow-Methods",
        "GET, POST, PUT, DELETE, PATCH, OPTIONS"
      );
      res.header(
        "Access-Control-Allow-Headers",
        "Content-Type, Authorization, x-requested-with, x-api-key, x-goog-api-key, origin, accept"
      );
      if (req.method === "OPTIONS") {
        return res.sendStatus(204);
      }
      next();
    });

    app.use((req, res, next) => {
      if (
        req.path !== "/api/status" &&
        req.path !== "/" &&
        req.path !== "/favicon.ico" &&
        req.path !== "/login"
      ) {
        this.logger.info(
          `[Entrypoint] 收到一个请求: ${req.method} ${req.path}`
        );
      }
      next();
    });
    app.use(express.json({ limit: "100mb" }));
    app.use(express.urlencoded({ extended: true }));

    const sessionSecret =
      // Section 1 & 2 (核心中间件和登录路由) 保持不变...
      (this.config.apiKeys && this.config.apiKeys[0]) ||
      crypto.randomBytes(20).toString("hex");
    app.use(cookieParser());
    app.use(
      session({
        secret: sessionSecret,
        resave: false,
        saveUninitialized: true,
        cookie: { secure: false, maxAge: 86400000 },
      })
    );
    const isAuthenticated = (req, res, next) => {
      if (req.session.isAuthenticated) {
        return next();
      }
      res.redirect("/login");
    };
    app.get("/login", (req, res) => {
      if (req.session.isAuthenticated) {
        return res.redirect("/");
      }
      const loginHtml = `
      <!DOCTYPE html>
      <html lang="zh-CN">
      <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>AIS2API - Login</title>
        <style>
          :root { --primary: #2563eb; --primary-hover: #1d4ed8; --bg-gradient: linear-gradient(135deg, #667eea 0%, #764ba2 100%); }
          body { margin: 0; display: flex; justify-content: center; align-items: center; height: 100vh; font-family: 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; background: var(--bg-gradient); color: #333; }
          .card { background: white; padding: 2.5rem; border-radius: 16px; box-shadow: 0 10px 25px rgba(0,0,0,0.2); width: 100%; max-width: 400px; text-align: center; transition: transform 0.3s ease; }
          .card:hover { transform: translateY(-5px); }
          h2 { margin-bottom: 1.5rem; color: #1a202c; font-weight: 600; font-size: 1.5rem; }
          .input-group { margin-bottom: 1.5rem; text-align: left; }
          label { display: block; margin-bottom: 0.5rem; font-size: 0.875rem; font-weight: 500; color: #4a5568; }
          input { width: 100%; padding: 0.75rem 1rem; border: 2px solid #e2e8f0; border-radius: 8px; font-size: 1rem; transition: border-color 0.2s; box-sizing: border-box; outline: none; }
          input:focus { border-color: var(--primary); }
          button { width: 100%; padding: 0.875rem; background-color: var(--primary); color: white; border: none; border-radius: 8px; font-size: 1rem; font-weight: 600; cursor: pointer; transition: background-color 0.2s; }
          button:hover { background-color: var(--primary-hover); }
          .error { background-color: #fff5f5; color: #c53030; padding: 0.75rem; border-radius: 8px; margin-top: 1rem; border: 1px solid #fed7d7; font-size: 0.875rem; }
          .footer { margin-top: 1.5rem; font-size: 0.75rem; color: #a0aec0; }
        </style>
      </head>
      <body>
        <div class="card">
          <form action="/login" method="post">
            <h2>🔐 身份验证</h2>
            <div class="input-group">
              <label for="apiKey">API Key</label>
              <input type="password" id="apiKey" name="apiKey" placeholder="请输入您的访问密钥" required autofocus>
            </div>
            <button type="submit">登 录</button>
            ${
              req.query.error ? '<div class="error">⚠️ API Key 验证失败，请重试。</div>' : ""
            }
            <div class="footer">AIS2API Proxy Service</div>
          </form>
        </div>
      </body>
      </html>`;
      res.send(loginHtml);
    });
    app.post("/login", (req, res) => {
      const { apiKey } = req.body;
      if (apiKey && this.config.apiKeys.includes(apiKey)) {
        req.session.isAuthenticated = true;
        res.redirect("/");
      } else {
        res.redirect("/login?error=1");
      }
    });

    // ==========================================================
    // Section 3: 状态页面 和 API (最终版)
    // ==========================================================
    app.get("/", isAuthenticated, (req, res) => {
      const { config, requestHandler, authSource, browserManager } = this;
      const initialIndices = authSource.initialIndices || [];
      const availableIndices = authSource.availableIndices || [];
      const invalidIndices = initialIndices.filter(
        (i) => !availableIndices.includes(i)
      );
      const logs = this.logger.logBuffer || [];

      const accountNameMap = authSource.accountNameMap;
      const accountDetailsHtml = initialIndices
        .map((index) => {
          const isInvalid = invalidIndices.includes(index);
          const name = isInvalid
            ? "N/A (JSON格式错误)"
            : accountNameMap.get(index) || "N/A (未命名)";
          return `<span class="label" style="padding-left: 20px;">账号${index}</span>: ${name}`;
        })
        .join("\n");

      const accountOptionsHtml = availableIndices
        .map((index) => `<option value="${index}">账号 #${index}</option>`)
        .join("");

      const statusHtml = `
    <!DOCTYPE html>
    <html lang="zh-CN">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>AIS2API 控制台</title>
        <link href="https://cdn.jsdelivr.net/npm/remixicon@3.5.0/fonts/remixicon.css" rel="stylesheet">
        <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
        <style>
        :root { --primary: #2563eb; --success: #10b981; --danger: #ef4444; --warning: #f59e0b; --bg: #f8fafc; --card-bg: #ffffff; --text: #1e293b; --text-light: #64748b; --border: #e2e8f0; }
        body { font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif; background-color: var(--bg); color: var(--text); margin: 0; padding: 0; line-height: 1.5; }
        .navbar { background: var(--card-bg); border-bottom: 1px solid var(--border); padding: 1rem 2rem; display: flex; justify-content: space-between; align-items: center; position: sticky; top: 0; z-index: 100; box-shadow: 0 1px 2px 0 rgba(0, 0, 0, 0.05); }
        .brand { font-weight: 700; font-size: 1.25rem; display: flex; align-items: center; gap: 0.5rem; color: var(--primary); }
        .status-badge { padding: 0.25rem 0.75rem; border-radius: 9999px; font-size: 0.875rem; font-weight: 500; display: flex; align-items: center; gap: 0.375rem; }
        .status-ok { background-color: #d1fae5; color: #065f46; }
        .status-error { background-color: #fee2e2; color: #991b1b; }
        .dot { width: 8px; height: 8px; border-radius: 50%; background-color: currentColor; }
        .blink { animation: blink 1.5s infinite; }
        @keyframes blink { 0%, 100% { opacity: 1; } 50% { opacity: 0.4; } }
        
        .container { max-width: 1200px; margin: 2rem auto; padding: 0 1rem; display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 1.5rem; }
        .card { background: var(--card-bg); border-radius: 12px; border: 1px solid var(--border); overflow: hidden; box-shadow: 0 1px 3px rgba(0,0,0,0.1); transition: transform 0.2s; }
        .card:hover { transform: translateY(-2px); box-shadow: 0 4px 6px rgba(0,0,0,0.1); }
        .card-header { padding: 1rem 1.5rem; border-bottom: 1px solid var(--border); font-weight: 600; display: flex; align-items: center; gap: 0.5rem; background-color: #f8fafc; }
        .card-body { padding: 1.5rem; }
        
        .info-row { display: flex; justify-content: space-between; margin-bottom: 0.75rem; font-size: 0.925rem; }
        .info-label { color: var(--text-light); }
        .info-value { font-weight: 500; font-family: monospace; }
        
        .full-width { grid-column: 1 / -1; }
        
        .log-container { background: #1e1e1e; color: #e0e0e0; padding: 1rem; border-radius: 8px; height: 400px; overflow-y: auto; font-family: 'JetBrains Mono', 'Fira Code', monospace; font-size: 0.85rem; line-height: 1.6; white-space: pre-wrap; scroll-behavior: smooth; }
        .log-entry { border-bottom: 1px solid #333; padding: 2px 0; }
        
        .controls { display: flex; gap: 1rem; flex-wrap: wrap; align-items: center; background: #f1f5f9; padding: 1rem; border-radius: 8px; }
        select, button { padding: 0.6rem 1rem; border-radius: 6px; border: 1px solid var(--border); font-size: 0.925rem; outline: none; transition: all 0.2s; }
        select { background: white; min-width: 200px; }
        button { background: white; cursor: pointer; font-weight: 500; color: var(--text); display: flex; align-items: center; gap: 0.5rem; }
        button:hover { background: #f8fafc; border-color: var(--primary); color: var(--primary); }
        button.primary { background: var(--primary); color: white; border: none; }
        button.primary:hover { background: #1d4ed8; }
        
        .account-list { max-height: 300px; overflow-y: auto; display: grid; grid-template-columns: repeat(auto-fill, minmax(280px, 1fr)); gap: 0.75rem; padding-right: 0.5rem; }
        .account-item { display: flex; align-items: center; padding: 0.75rem; border: 1px solid var(--border); border-radius: 8px; font-size: 0.9rem; background-color: #f8fafc; transition: all 0.2s; }
        .account-item:hover { border-color: var(--primary); background: #f0f9ff; }
        .account-idx { background: #e2e8f0; padding: 2px 8px; border-radius: 4px; margin-right: 10px; font-size: 0.8rem; font-family: monospace; }
        
        /* Scrollbar styling */
        ::-webkit-scrollbar { width: 8px; height: 8px; }
        ::-webkit-scrollbar-track { background: transparent; }
        ::-webkit-scrollbar-thumb { background: #cbd5e1; border-radius: 4px; }
        ::-webkit-scrollbar-thumb:hover { background: #94a3b8; }

        /* Custom Tooltip */
        [data-tooltip] { position: relative; }
        [data-tooltip]::after {
            content: attr(data-tooltip);
            position: absolute;
            bottom: 125%;
            left: 50%;
            transform: translateX(-50%) translateY(10px);
            background: rgba(30, 41, 59, 0.95);
            color: #f8fafc;
            padding: 0.5rem 0.75rem;
            border-radius: 6px;
            font-size: 0.75rem;
            font-weight: normal;
            white-space: normal;
            max-width: 240px;
            width: max-content;
            opacity: 0;
            visibility: hidden;
            transition: all 0.2s cubic-bezier(0.68, -0.55, 0.265, 1.55);
            z-index: 1000;
            pointer-events: none;
            box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1), 0 2px 4px -1px rgba(0, 0, 0, 0.06);
            text-align: center;
            line-height: 1.4;
        }
        [data-tooltip]::before {
            content: '';
            position: absolute;
            bottom: 115%;
            left: 50%;
            transform: translateX(-50%) translateY(10px);
            border: 6px solid transparent;
            border-top-color: rgba(30, 41, 59, 0.95);
            opacity: 0;
            visibility: hidden;
            transition: all 0.2s cubic-bezier(0.68, -0.55, 0.265, 1.55);
            z-index: 1000;
            pointer-events: none;
        }
        [data-tooltip]:hover::after, [data-tooltip]:hover::before {
            opacity: 1;
            visibility: visible;
            transform: translateX(-50%) translateY(0);
        }
        </style>
    </head>
    <body>
        <nav class="navbar">
            <div class="brand">
                <i class="ri-robot-2-line"></i> AIS2API Console
            </div>
            <div class="status-badge status-ok">
                <span class="dot blink"></span> 系统运行中
            </div>
        </nav>

        <div class="container">
            <!-- Service Status -->
            <div class="card">
                <div class="card-header"><i class="ri-server-line"></i> 服务状态</div>
                <div class="card-body" id="service-status-body">
                    Loading...
                </div>
            </div>

            <!-- Configuration -->
            <div class="card">
                <div class="card-header"><i class="ri-settings-3-line"></i> 系统配置</div>
                <div class="card-body" id="config-body">
                    Loading...
                </div>
            </div>
            
            <!-- Account Stats -->
             <div class="card">
                <div class="card-header"><i class="ri-user-star-line"></i> 账号监控</div>
                <div class="card-body" id="account-stats-body">
                    Loading...
                </div>
            </div>
    
            <!-- Usage Chart -->
            <div class="card full-width">
                <div class="card-header"><i class="ri-bar-chart-line"></i> 调用统计 (近7天)</div>
                <div class="card-body" style="position: relative; height: 200px;">
                    <canvas id="usageChart"></canvas>
                </div>
            </div>

            <!-- Accounts List -->
            <div class="card full-width">
                 <div class="card-header"><i class="ri-group-line"></i> 账号列表</div>
                 <div class="card-body">
                     <div class="account-list" id="account-list-body">
                         Loading...
                     </div>
                 </div>
            </div>

            <!-- Actions -->
            <div class="card full-width">
                <div class="card-header"><i class="ri-command-line"></i> 控制面板</div>
                <div class="card-body">
                    <div class="controls">
                        <div style="display:flex; flex-direction:column; gap:0.25rem;">
                            <label style="font-size:0.8rem; color:var(--text-light);">切换目标账号</label>
                            <select id="accountIndexSelect">${accountOptionsHtml}</select>
                        </div>
                        <button onclick="switchSpecificAccount()" class="primary"><i class="ri-switch-line"></i> 执行切换</button>
                        <div style="width: 1px; height: 24px; background: #cbd5e1; margin: 0 10px;"></div>
                        <button onclick="toggleStreamingMode()"><i class="ri-wireless-charging-line"></i> 切换流模式</button>
                        <button onclick="toggleForceThinking()" data-tooltip="强制模型始终返回思维链 (思考过程)。若客户端未请求或参数不正确，系统将自动注入或修正配置 (includeThoughts: true)。"><i class="ri-brain-line"></i> 切换强制返回思维链</button>
                        <button onclick="toggleFixThinking()" data-tooltip="Gemini 3.0 Pro (Build版) 不支持 thinkingLevel 参数，会导致 400 错误。开启此开关将自动移除该参数并使用默认值 (High)。"><i class="ri-magic-line"></i> 切换思考配置修正</button>
                    </div>
                </div>
            </div>

            <!-- Logs -->
            <div class="card full-width">
                <div class="card-header">
                    <div style="display:flex; justify-content:space-between; width:100%; align-items:center;">
                        <span><i class="ri-terminal-box-line"></i> 系统日志</span>
                        <span style="font-size:0.8rem; font-weight:normal; color:var(--text-light);" id="log-count"></span>
                    </div>
                </div>
                <div class="card-body" style="padding:0; background:#1e1e1e;">
                    <div id="log-container" class="log-container"></div>
                </div>
            </div>
        </div>

        <script>
        let chartInstance = null;

        function renderChart(stats) {
            const ctx = document.getElementById('usageChart');
            if (!ctx) return;

            const safeStats = Array.isArray(stats) ? stats : [];
            const labels = safeStats.map(item => item.date);
            const data = safeStats.map(item => item.count);

            if (chartInstance) {
                chartInstance.data.labels = labels;
                chartInstance.data.datasets[0].data = data;
                chartInstance.update();
            } else {
                chartInstance = new Chart(ctx, {
                    type: 'bar',
                    data: {
                        labels: labels,
                        datasets: [{
                            label: '日调用次数',
                            data: data,
                            backgroundColor: 'rgba(37, 99, 235, 0.5)',
                            borderColor: 'rgba(37, 99, 235, 1)',
                            borderWidth: 1
                        }]
                    },
                    options: {
                        responsive: true,
                        maintainAspectRatio: false,
                        scales: {
                            y: {
                                beginAtZero: true,
                                ticks: {
                                    precision: 0,
                                    suggestedMax: 5
                                }
                            }
                        },
                        plugins: {
                          legend: { display: false }
                        }
                    }
                });
            }
        }

        function renderInfoRow(label, value, isCode = false) {
            return \`<div class="info-row"><span class="info-label">\${label}</span><span class="info-value" \${isCode ? 'style="font-family:monospace"' : ''}>\${value}</span></div>\`;
        }
        
        function updateContent() {
            fetch('/api/status').then(response => response.json()).then(data => {
                // Update Service Status
                const browserStatus = data.status.browserConnected
                    ? '<span style="color:var(--success);"><i class="ri-checkbox-circle-fill"></i> 已连接</span>'
                    : '<span style="color:var(--danger);"><i class="ri-close-circle-fill"></i> 断开</span>';
                
                document.getElementById('service-status-body').innerHTML =
                    renderInfoRow('HTTP服务', '<span style="color:var(--success);">Online</span>') +
                    renderInfoRow('浏览器后端', browserStatus) +
                    renderInfoRow('当前账号', '#' + data.status.currentAuthIndex);

                // Update Config
                document.getElementById('config-body').innerHTML =
                    renderInfoRow('流式模式', data.status.streamingMode.split(' ')[0]) +
                    renderInfoRow('强制返回思维链', data.status.forceThinking) +
                    renderInfoRow('修正思考配置', data.status.fixThinkingConfig) +
                    renderInfoRow('API认证', data.status.apiKeySource);

                // Update Stats
                document.getElementById('account-stats-body').innerHTML =
                    renderInfoRow('今日调用', \`<span style="color:var(--primary);font-weight:bold">\${data.status.todayUsage || 0}</span> 次\`) +
                    renderInfoRow('使用计数', data.status.usageCount) +
                    renderInfoRow('连续失败', data.status.failureCount) +
                    renderInfoRow('扫描总数', data.status.initialIndices.match(/总数: (\\d+)/)[1] + ' 个');
                
                // Update Chart
                if (data.status.dailyStats) {
                    renderChart(data.status.dailyStats);
                }
                    
                // Update Account List
                const accounts = data.status.accountDetails.map(acc => {
                    const count = (data.status.accountStats && data.status.accountStats[acc.index]) || 0;
                    return \`<div class="account-item" style="justify-content:space-between"><div style="display:flex;align-items:center"><span class="account-idx">#\${acc.index}</span> \${acc.name}</div><span style="font-size:0.8rem;color:var(--text-light);background:#e2e8f0;padding:2px 6px;border-radius:4px;">\${count}次</span></div>\`;
                }).join('');
                const invalid = data.status.invalidIndices !== '[]' ? \`<div style="grid-column: 1 / -1; padding:0.75rem; color:#991b1b; background:#fee2e2; border-radius:8px; font-size:0.9rem; display:flex; align-items:center; gap:0.5rem;"><i class="ri-error-warning-line"></i> 无效索引: \${data.status.invalidIndices}</div>\` : '';
                
                document.getElementById('account-list-body').innerHTML = accounts + invalid;

                // Update Logs
                const logContainer = document.getElementById('log-container');
                const logTitle = document.querySelector('#log-section h2');
                const isScrolledToBottom = logContainer.scrollHeight - logContainer.clientHeight <= logContainer.scrollTop + 50;
                
                document.getElementById('log-count').innerText = \`最近 \${data.logCount} 条记录\`;
                // Simple highlighting for logs
                const coloredLogs = data.logs.split('\\n').map(line => {
                    let color = '#e0e0e0';
                    if(line.includes('[ERROR]')) color = '#ef4444';
                    else if(line.includes('[WARN]')) color = '#f59e0b';
                    else if(line.includes('[INFO]')) color = '#60a5fa';
                    return \`<div class="log-entry" style="color:\${color}">\${line}</div>\`;
                }).join('');
                
                logContainer.innerHTML = coloredLogs;
                if (isScrolledToBottom) { logContainer.scrollTop = logContainer.scrollHeight; }
            }).catch(error => console.error('Error fetching new content:', error));
        }

        function switchSpecificAccount() {
            const selectElement = document.getElementById('accountIndexSelect');
            const targetIndex = selectElement.value;
            if (!confirm(\`确定要切换到账号 #\${targetIndex} 吗？这会重置浏览器会话。\\n(操作可能需要几秒钟)\`)) {
                return;
            }
            // Disable button
            const btn = document.querySelector('button[onclick="switchSpecificAccount()"]');
            const originalText = btn.innerHTML;
            btn.disabled = true;
            btn.innerHTML = '<i class="ri-loader-4-line blink"></i> 切换中...';

            fetch('/api/switch-account', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ targetIndex: parseInt(targetIndex, 10) })
            })
            .then(res => res.text()).then(data => {
                alert(data);
                updateContent();
            })
            .catch(err => {
                alert('操作反馈: ' + err);
                updateContent();
            })
            .finally(() => {
                btn.disabled = false;
                btn.innerHTML = originalText;
            });
        }
            
        function toggleStreamingMode() {
            fetch('/api/toggle-streaming-mode', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' }
            })
            .then(res => res.text()).then(data => { alert(data); updateContent(); })
            .catch(err => alert('设置失败: ' + err));
        }

        function toggleForceThinking() {
            fetch('/api/toggle-force-thinking', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' }
            })
            .then(res => res.text()).then(data => { alert(data); updateContent(); })
            .catch(err => alert('设置失败: ' + err));
        }

        function toggleFixThinking() {
            fetch('/api/toggle-fix-thinking', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' }
            })
            .then(res => res.text()).then(data => { alert(data); updateContent(); })
            .catch(err => alert('设置失败: ' + err));
        }

        document.addEventListener('DOMContentLoaded', () => {
            updateContent();
            setInterval(updateContent, 500);
        });
        </script>
    </body>
    </html>
    `;
      res.status(200).send(statusHtml);
    });

    app.get("/api/status", isAuthenticated, (req, res) => {
        const { config, requestHandler, authSource, browserManager, statsManager } = this;
        const initialIndices = authSource.initialIndices || [];
        const invalidIndices = initialIndices.filter(
          (i) => !authSource.availableIndices.includes(i)
        );
        const logs = this.logger.logBuffer || [];
        const accountNameMap = authSource.accountNameMap;
        const accountDetails = initialIndices.map((index) => {
          const isInvalid = invalidIndices.includes(index);
          const name = isInvalid
            ? "N/A (JSON格式错误)"
            : accountNameMap.get(index) || "N/A (未命名)";
          return { index, name };
        });
  
        const statsData = statsManager.getStats();
        const accountStats = statsManager.getTodayAccountStats();
  
        const data = {
          status: {
            streamingMode: `${this.streamingMode} (仅启用流式传输时生效)`,
            forceThinking: this.forceThinking ? "✅ 已启用" : "❌ 已关闭",
            fixThinkingConfig: this.fixThinkingConfig ? "✅ 已启用" : "❌ 已关闭",
            browserConnected: !!browserManager.browser,
            immediateSwitchStatusCodes:
              config.immediateSwitchStatusCodes.length > 0
                ? `[${config.immediateSwitchStatusCodes.join(", ")}]`
                : "已禁用",
            apiKeySource: config.apiKeySource,
            currentAuthIndex: requestHandler.currentAuthIndex,
            usageCount: `${requestHandler.usageCount} / ${
              config.switchOnUses > 0 ? config.switchOnUses : "N/A"
            }`,
            failureCount: `${requestHandler.failureCount} / ${
              config.failureThreshold > 0 ? config.failureThreshold : "N/A"
            }`,
            initialIndices: `[${initialIndices.join(", ")}] (总数: ${
              initialIndices.length
            })`,
            accountDetails: accountDetails,
            invalidIndices: `[${invalidIndices.join(", ")}] (总数: ${
              invalidIndices.length
            })`,
            // Stats Data
            todayUsage: statsData.today,
            dailyStats: statsData.daily,
            accountStats: accountStats
          },
          logs: logs.join("\n"),
          logCount: logs.length,
        };
        res.json(data);
      });
    app.post("/api/switch-account", isAuthenticated, async (req, res) => {
      try {
        const { targetIndex } = req.body;
        if (targetIndex !== undefined && targetIndex !== null) {
          this.logger.info(
            `[WebUI] 收到切换到指定账号 #${targetIndex} 的请求...`
          );
          const result = await this.requestHandler._switchToSpecificAuth(
            targetIndex
          );
          if (result.success) {
            res.status(200).send(`切换成功！已激活账号 #${result.newIndex}。`);
          } else {
            res.status(400).send(result.reason);
          }
        } else {
          this.logger.info("[WebUI] 收到手动切换下一个账号的请求...");
          if (this.authSource.availableIndices.length <= 1) {
            return res
              .status(400)
              .send("切换操作已取消：只有一个可用账号，无法切换。");
          }
          const result = await this.requestHandler._switchToNextAuth();
          if (result.success) {
            res
              .status(200)
              .send(`切换成功！已切换到账号 #${result.newIndex}。`);
          } else if (result.fallback) {
            res
              .status(200)
              .send(`切换失败，但已成功回退到账号 #${result.newIndex}。`);
          } else {
            res.status(409).send(`操作未执行: ${result.reason}`);
          }
        }
      } catch (error) {
        res
          .status(500)
          .send(`致命错误：操作失败！请检查日志。错误: ${error.message}`);
      }
    });
    app.post("/api/set-mode", isAuthenticated, (req, res) => {
      const newMode = req.body.mode;
      if (newMode === "fake" || newMode === "real") {
        this.streamingMode = newMode;
        this.logger.info(
          `[WebUI] 流式模式已由认证用户切换为: ${this.streamingMode}`
        );
        res.status(200).send(`流式模式已切换为: ${this.streamingMode}`);
      } else {
        res.status(400).send('无效模式. 请用 "fake" 或 "real".');
      }
    });

    app.post("/api/toggle-streaming-mode", isAuthenticated, (req, res) => {
      this.streamingMode = this.streamingMode === "real" ? "fake" : "real";
      this.logger.info(
        `[WebUI] 流式模式已切换为: ${this.streamingMode}`
      );
      res.status(200).send(`流式模式已切换为: ${this.streamingMode}`);
    });

    app.post("/api/toggle-force-thinking", isAuthenticated, (req, res) => {
      this.forceThinking = !this.forceThinking;
      const statusText = this.forceThinking ? "已启用" : "已关闭";
      this.logger.info(`[WebUI] 强制返回思维链开关已切换为: ${statusText}`);
      res.status(200).send(`强制返回思维链模式: ${statusText}`);
    });

    app.post("/api/toggle-fix-thinking", isAuthenticated, (req, res) => {
      this.fixThinkingConfig = !this.fixThinkingConfig;
      const statusText = this.fixThinkingConfig ? "已启用" : "已关闭";
      this.logger.info(`[WebUI] 思考配置修正开关已切换为: ${statusText}`);
      res.status(200).send(`思考配置修正模式: ${statusText}`);
    });

    app.use(this._createAuthMiddleware());

    app.get("/v1/models", (req, res) => {
      const modelIds = this.config.modelList || ["gemini-2.5-pro"];

      const models = modelIds.map((id) => ({
        id: id,
        object: "model",
        created: Math.floor(Date.now() / 1000),
        owned_by: "google",
      }));

      res.status(200).json({
        object: "list",
        data: models,
      });
    });

    app.post("/v1/chat/completions", (req, res) => {
      this.requestHandler.processOpenAIRequest(req, res);
    });
    app.all(/(.*)/, (req, res) => {
      this.requestHandler.processRequest(req, res);
    });

    return app;
  }

  async _startWebSocketServer() {
    this.wsServer = new WebSocket.Server({
      port: this.config.wsPort,
      host: this.config.host,
    });
    this.wsServer.on("connection", (ws, req) => {
      this.connectionRegistry.addConnection(ws, {
        address: req.socket.remoteAddress,
      });
    });
  }
}

// ===================================================================================
// MAIN INITIALIZATION
// ===================================================================================

async function initializeServer() {
  const initialAuthIndex = parseInt(process.env.INITIAL_AUTH_INDEX, 10) || 1;
  try {
    const serverSystem = new ProxyServerSystem();
    await serverSystem.start(initialAuthIndex);
  } catch (error) {
    console.error("❌ 服务器启动失败:", error.message);
    process.exit(1);
  }
}

if (require.main === module) {
  initializeServer();
}

module.exports = { ProxyServerSystem, BrowserManager, initializeServer };
