const express = require('express');
const cors = require('cors');
const mysql = require('mysql2/promise');
const winston = require('winston');
const crypto = require('crypto');
const cron = require('node-cron');
const fetch = require('node-fetch');  // 如果是 Node.js 17+ 可以不用安装
const https = require('https');
const session = require('express-session');
const rateLimit = require('express-rate-limit');
const nodemailer = require('nodemailer');
const path = require('path');
const fs = require('fs').promises;  // 添加fs模块

// HTML模板缓存
const htmlTemplates = {};

// 读取HTML模板函数
async function loadHtmlTemplate(templateName) {
  if (htmlTemplates[templateName]) {
    return htmlTemplates[templateName];
  }

  try {
    const template = await fs.readFile(path.join(__dirname, 'html', `${templateName}.html`), 'utf8');
    htmlTemplates[templateName] = template;
    return template;
  } catch (err) {
    logger.error(`加载HTML模板 ${templateName} 失败:`, err);
    throw err;
  }
}

// 添加配置对象
const config = {
  baseUrl: process.env.BASE_URL || 'http://101.200.57.128:3000',  // 设置默认域名
  apiKey: process.env.API_KEY || 'cursor-98999899'  // 添加 API 密钥
};

// 创建应用实例
const app = express();
const port = process.env.PORT || 3000;

// 配置日志
const logger = winston.createLogger({
  level: 'info',
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.json()
  ),
  transports: [
    new winston.transports.File({ filename: 'logs/error.log', level: 'error' }),
    new winston.transports.File({ filename: 'logs/combined.log' })
  ]
});

// 配置邮件发送
const transporter = nodemailer.createTransport({
  host: 'smtp.qq.com',
  port: 465,
  secure: true,
  auth: {
    user: '2686264538@qq.com',
    pass: 'maawpvjjcruydcje'
  },
  debug: true,
  logger: true
});

// 验证邮件发送器配置
transporter.verify(function (error, success) {
  if (error) {
    logger.error('邮件发送器配置错误:', {
      error: error.message,
      stack: error.stack,
      host: 'smtp.qq.com',
      port: 465,
      user: '2686264538@qq.com',
      // 不记录密码
      authMethod: error.authMethod
    });
  } else {
    logger.info('邮件发送器配置成功');
  }
});

// 修改邮件模板函数，使用外部HTML文件
const getActivationEmailTemplate = async (activationCode, daysInt) => {
  try {
    let template = await loadHtmlTemplate('activation-email');
    return template
      .replace('${activationCode}', activationCode)
      .replace('${daysInt}', daysInt);
  } catch (err) {
    logger.error('加载激活邮件模板失败:', err);
    throw err;
  }
};

// 数据库连接配置
const dbConfig = {
  host: process.env.DB_HOST,
  port: process.env.DB_PORT,
  user: process.env.DB_USER,
  password: process.env.DB_PASS,
  database: process.env.DB_NAME,
  ssl: false,
  insecureAuth: true,
  connectTimeout: 10000  // 统一配置连接超时时间
};

// 创建访问日志表
async function createAccessLogTable() {
  try {
    const conn = await mysql.createConnection(dbConfig);

    // 先创建表
    await conn.execute(`
      CREATE TABLE IF NOT EXISTS access_logs (
        id BIGINT NOT NULL AUTO_INCREMENT,
        ip VARCHAR(50) NOT NULL,
        api VARCHAR(100) NOT NULL,
        params TEXT,
        user_agent VARCHAR(500),
        accept_language VARCHAR(100),
        referer VARCHAR(500),
        response TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        PRIMARY KEY (id),
        INDEX idx_ip (ip),
        INDEX idx_api (api),
        INDEX idx_created_at (created_at),
        INDEX idx_user_agent (user_agent(50))
      ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
    `);

    // 检查并添加新字段
    const [columns] = await conn.execute(`
      SELECT COLUMN_NAME 
      FROM INFORMATION_SCHEMA.COLUMNS 
      WHERE TABLE_NAME = 'access_logs'
      AND TABLE_SCHEMA = (SELECT DATABASE())
    `);

    const existingColumns = columns.map(col => col.COLUMN_NAME.toLowerCase());

    // 逐个添加不存在的字段
    const columnsToAdd = [];
    if (!existingColumns.includes('response')) {
      columnsToAdd.push('ADD COLUMN response TEXT');
    }
    if (!existingColumns.includes('user_agent')) {
      columnsToAdd.push('ADD COLUMN user_agent VARCHAR(500)');
    }
    if (!existingColumns.includes('accept_language')) {
      columnsToAdd.push('ADD COLUMN accept_language VARCHAR(100)');
    }
    if (!existingColumns.includes('referer')) {
      columnsToAdd.push('ADD COLUMN referer VARCHAR(500)');
    }

    // 检查索引是否存在
    const [indexes] = await conn.execute(`SHOW INDEX FROM access_logs`);
    const existingIndexes = indexes.map(idx => idx.Key_name.toLowerCase());

    if (!existingIndexes.includes('idx_user_agent')) {
      columnsToAdd.push('ADD INDEX idx_user_agent (user_agent(50))');
    }

    // 如果有需要添加的字段或索引，执行 ALTER TABLE
    if (columnsToAdd.length > 0) {
      const alterSql = `ALTER TABLE access_logs ${columnsToAdd.join(', ')}`;
      await conn.execute(alterSql);
      logger.info('access_logs 表字段和索引更新成功:', {
        added_items: columnsToAdd
      });
    } else {
      logger.info('access_logs 表所有字段和索引已存在');
    }

    await conn.end();
    logger.info('access_logs 表创建/更新完成');
  } catch (err) {
    logger.error('创建/更新访问日志表失败:', {
      error: err.message,
      code: err.code,
      sql_state: err.sqlState,
      sql_message: err.sqlMessage,
      stack: err.stack
    });
  }
}

// 记录访问日志中间件
async function logAccess(req, res, next) {
  const clientIP = req.ip.replace(/^::ffff:/, '');
  const userAgent = req.headers['user-agent'] || '';

  // 添加内网IP检查函数
  function isInternalIP(ip) {
    return ip === '127.0.0.1' ||
      ip === 'localhost' ||
      ip === '::1' ||
      ip.startsWith('192.168.') ||
      ip.startsWith('10.') ||
      (ip.startsWith('172.') &&
        parseInt(ip.split('.')[1]) >= 16 &&
        parseInt(ip.split('.')[1]) <= 31);
  }

  // 检查是否是特权User-Agent
  async function isPrivilegedUserAgent(userAgent) {
    let conn;
    try {
      conn = await mysql.createConnection(dbConfig);
      const [rows] = await conn.execute(
        'SELECT * FROM privileged_user_agents WHERE user_agent = ?',
        [userAgent]
      );
      return rows.length > 0;
    } catch (err) {
      logger.error('检查特权User-Agent失败:', err);
      return false;
    } finally {
      if (conn) await conn.end();
    }
  }

  // 保存原始的 res.json 方法
  const originalJson = res.json;
  let responseBody;

  // 重写 res.json 方法来捕获响应内容
  res.json = function (data) {
    responseBody = JSON.stringify(data);

    process.nextTick(async () => {
      let conn;
      try {
        conn = await mysql.createConnection(dbConfig);

        // 检查是否是特权User-Agent
        const isPrivileged = await isPrivilegedUserAgent(userAgent);

        // 检查是否在白名单中
        const isWhitelisted = await isWhitelistedIP(clientIP, conn);

        // 如果不是内网IP、不是特权User-Agent且不在白名单中，才进行访问限制检查
        if (!isInternalIP(clientIP) && !isPrivileged && !isWhitelisted) {
          // 1. 检查 IP 是否被屏蔽
          const [blocked] = await conn.execute(
            'SELECT * FROM blocked_ips WHERE ip = ?',
            [clientIP]
          );

          if (blocked.length > 0) {
            logger.warn('拦截已屏蔽的IP访问:', { ip: clientIP });
            return;
          }

          // 2. 检查 User-Agent 是否已被屏蔽且在封禁期内
          const [blockedUA] = await conn.execute(`
            SELECT *, 
            TIMESTAMPDIFF(HOUR, NOW(), unblock_at) as remaining_hours,
            TIMESTAMPDIFF(MINUTE, NOW(), unblock_at) % 60 as remaining_minutes
            FROM blocked_user_agents 
            WHERE user_agent = ? 
            AND NOW() < unblock_at
          `, [userAgent]);

          if (blockedUA.length > 0) {
            logger.warn('[Access] 拦截已屏蔽的User-Agent访问:', {
              user_agent: userAgent,
              remaining_hours: blockedUA[0].remaining_hours,
              remaining_minutes: blockedUA[0].remaining_minutes
            });
            return res.status(403).json({
              code: 10
            });
          }

          // 3. 检查IP最近一小时的访问次数
          const [hourlyRequests] = await conn.execute(`
            SELECT COUNT(*) as count, MIN(created_at) as first_request 
            FROM access_logs 
            WHERE ip = ? 
            AND created_at > DATE_SUB(NOW(), INTERVAL 1 HOUR)
          `, [clientIP]);

          // 4. 如果超过30次，自动封禁IP
          if (hourlyRequests[0].count >= 200) {  // 修改为200次
            logger.warn('[Access] IP访问过于频繁,已加入屏蔽列表:', {
              ip: clientIP,
              request_count: hourlyRequests[0].count
            });

            // 添加到屏蔽表
            await conn.execute(
              'INSERT INTO blocked_ips (ip, reason) VALUES (?, ?) ON DUPLICATE KEY UPDATE blocked_at = NOW()',
              [clientIP, '访问频率超限']
            );

            return res.status(403).json({
              code: 10
            });
          }
        }

        // 5. 记录正常的访问日志
        await conn.execute(`
          INSERT INTO access_logs (
            ip, 
            api, 
            params, 
            user_agent,
            accept_language,
            referer,
            response
          ) VALUES (?, ?, ?, ?, ?, ?, ?)
        `, [
          clientIP,
          req.path,
          JSON.stringify(req.body),
          userAgent,
          req.headers['accept-language'] || '',
          req.headers['referer'] || '',
          responseBody
        ]);

      } catch (err) {
        logger.error('记录访问日志失败:', err);
      } finally {
        if (conn) await conn.end();
      }
    });

    return originalJson.call(this, data);
  };

  // 6. 如果 IP 已被屏蔽且不是内网IP或特权User-Agent，直接返回错误
  const isPrivileged = await isPrivilegedUserAgent(userAgent);
  if (!isInternalIP(clientIP) && !isPrivileged) {
    try {
      const conn = await mysql.createConnection(dbConfig);
      const [blocked] = await conn.execute(
        'SELECT * FROM blocked_ips WHERE ip = ?',
        [clientIP]
      );
      await conn.end();

      if (blocked.length > 0) {
        return res.status(403).json({
          code: 10
        });
      }
    } catch (err) {
      logger.error('检查IP限制失败:', err);
    }
  }

  next();
}

// 中间件
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));  // 添加表单解析中间件
app.use(session({
  secret: 'cursor-98999899',
  resave: false,
  saveUninitialized: false
}));
app.use(logAccess);  // 添加访问日志中间件

// 存储密码错误次数
const loginAttempts = new Map();

// 锁定时间（毫秒）
const LOCK_DURATION = 30 * 60 * 1000; // 30分钟

// 最大尝试次数
const MAX_ATTEMPTS = 3;

// 检查是否被锁定
function isLocked(ip) {
  const attempt = loginAttempts.get(ip);
  if (!attempt) return false;

  // 如果锁定时间已过，重置记录
  if (attempt.lockedUntil && Date.now() > attempt.lockedUntil) {
    loginAttempts.delete(ip);
    return false;
  }

  return attempt.lockedUntil ? Date.now() < attempt.lockedUntil : false;
}

// 记录失败尝试
function recordFailedAttempt(ip) {
  const attempt = loginAttempts.get(ip) || { count: 0 };
  attempt.count++;

  if (attempt.count >= MAX_ATTEMPTS) {
    attempt.lockedUntil = Date.now() + LOCK_DURATION;
    logger.warn('IP已被锁定:', { ip, lockedUntil: new Date(attempt.lockedUntil) });
  }

  loginAttempts.set(ip, attempt);
  return attempt;
}

// 检查IP或设备ID是否已经试用过试用功能
async function checkTrialUsed(ip, deviceId) {
  // 去除 IPv6 前缀
  ip = ip.replace(/^::ffff:/, '');

  try {
    const conn = await mysql.createConnection(dbConfig);

    // 检查IP或设备ID是否使用过
    const [rows] = await conn.execute(
      'SELECT COUNT(*) as count FROM trials WHERE ip = ? OR device_id = ?',
      [ip, deviceId]
    );

    await conn.end();
    return rows[0].count > 0;

  } catch (err) {
    logger.error('检查试用记录失败:', err);
    return true; // 出错时当作已使用过
  }
}

// 记录试用信息
async function recordTrial(ip, deviceId) {
  let conn;
  try {
    conn = await mysql.createConnection(dbConfig);
    logger.info(' trials1');
    const insertSql = 'INSERT INTO trials (device_id, ip, created_at, trial_at) VALUES (?, ?, NOW(), NOW())';

    logger.info('[Trial Insert] 准备插入试用记录:', {
      sql: insertSql,
      device_id: deviceId,
      ip: ip,
      timestamp: new Date().toISOString()
    });

    const [result] = await conn.execute(insertSql, [deviceId, ip]);

    logger.info('[Trial Insert] 插入结果:', {
      success: true,
      insertId: result.insertId,
      affectedRows: result.affectedRows,
      device_id: deviceId,
      ip: ip
    });

    return true;
  } catch (err) {
    logger.error('[Trial Insert] 插入失败:', {
      error: err.message,
      code: err.code,
      device_id: deviceId,
      ip: ip
    });
    return false;
  } finally {
    if (conn) {
      try {
        await conn.end();
        logger.info('[Trial Insert] 数据库连接已关闭');
      } catch (err) {
        logger.error('[Trial Insert] 关闭数据库连接失败:', err);
      }
    }
  }
}

// 请求频率限制中间件
const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15分钟
  max: 100, // 修改为100次
  message: { code: 429, msg: '请求过于频繁,请稍后再试' },
  // 添加 skip 选项来检查白名单
  skip: async (req) => {
    let conn;
    try {
      const clientIP = req.ip.replace(/^::ffff:/, ''); // 去除 IPv6 前缀
      conn = await mysql.createConnection(dbConfig);
      const isWhitelisted = await isWhitelistedIP(clientIP, conn);
      return isWhitelisted; // 如果在白名单中返回 true，跳过限制
    } catch (err) {
      logger.error('检查IP白名单失败:', err);
      return false; // 发生错误时不跳过限制
    } finally {
      if (conn) await conn.end();
    }
  }
});

// 参数验证中间件
function validateParams(req, res, next) {
  const { device_id } = req.body;

  // // 验证device_id格式
  // if (!device_id || !/^[a-f0-9]{32}$/.test(device_id)) {
  //   return res.json({ code: 1, msg: '无效的设备ID1' });
  // }

  next();
}

// 激活码验证中间件
function validateActivationCode(req, res, next) {
  const { activation_code } = req.body;

  // 验证激活码格式
  if (!activation_code || !/^[A-Z0-9]{16}$/.test(activation_code)) {
    return res.json({ code: 1, msg: '无效的激活码7' });
  }

  next();
}

// 应用中间件
app.use(apiLimiter);

// 添加设备ID验证函数
function validateDeviceId(device_id) {
  // 验证是否是32位MD5值（小写字母和数字）
  return /^[a-f0-9]{32}$/.test(device_id);
}

// 验证 BIOS_UUID 格式
function validateBiosUuid(bios_uuid) {
  // 只验证非空和包含横杠
  return bios_uuid && bios_uuid.includes('-');
}

// 修改更新BIOS UUID接口
app.post('/api/update_bios_uuid', async (req, res) => {
  return res.json({ code: 0, msg: '0' });
  let conn;
  try {
    const { device_id, bios_uuid } = req.body;
    const clientIP = req.ip.replace(/^::ffff:/, '');

    // 验证参数
    if (!device_id && !bios_uuid) {
      logger.warn('[Update BIOS] 参数错误:', {
        device_id: !!device_id,
        bios_uuid: !!bios_uuid,
        client_ip: clientIP
      });
      return res.json({ code: 1, msg: '设备标识不能为空' });
    }

    // 验证bios_uuid格式(如果有)
    if (bios_uuid && !validateBiosUuid(bios_uuid)) {
      logger.warn('[Update BIOS] 无效的BIOS UUID:', { bios_uuid });
      return res.json({ code: 1, msg: '无效的BIOS UUID格式' });
    }

    // 验证device_id格式(如果有)
    if (device_id && !validateDeviceId(device_id)) {
      logger.warn('[Update BIOS] 无效的设备ID:', { device_id });
      return res.json({ code: 1, msg: '无效的设备ID2' });
    }

    conn = await mysql.createConnection(dbConfig);

    // 构建查询条件
    let whereClause = [];
    let params = [];

    if (device_id) {
      whereClause.push('device_id = ?');
      params.push(device_id);
    }
    if (bios_uuid) {
      whereClause.push('BIOS_UUID = ?');
      params.push(bios_uuid);
    }

    // 查询会员记录
    const [members] = await conn.execute(
      `SELECT * FROM members WHERE ${whereClause.join(' OR ')}`,
      params
    );

    if (members.length === 0) {
      logger.warn('[Update BIOS] 未找到会员记录:', {
        device_id,
        bios_uuid,
        client_ip: clientIP
      });
      return res.json({ code: 4, msg: '未找到会员记录' });
    }

    const member = members[0];

    // 如果已有BIOS UUID，验证是否匹配
    if (member.BIOS_UUID) {
      if (member.BIOS_UUID === bios_uuid) {
        logger.info('[Update BIOS] BIOS UUID验证成功:', {
          device_id,
          bios_uuid,
          client_ip: clientIP
        });
        return res.json({
          code: 0,
          msg: 'BIOS UUID验证成功',
          data: { bios_uuid: member.BIOS_UUID }
        });
      } else {
        logger.warn('[Update BIOS] BIOS UUID不匹配:', {
          device_id,
          existing_uuid: member.BIOS_UUID,
          new_uuid: bios_uuid,
          client_ip: clientIP
        });
        return res.json({
          code: 4,
          msg: 'BIOS UUID不匹配',
          data: { bios_uuid: member.BIOS_UUID }
        });
      }
    }

    // 更新BIOS UUID
    if (bios_uuid) {
      await conn.execute(
        'UPDATE members SET BIOS_UUID = ? WHERE id = ?',
        [bios_uuid, member.id]
      );

      logger.info('[Update BIOS] BIOS UUID更新成功:', {
        device_id,
        bios_uuid,
        member_id: member.id,
        client_ip: clientIP
      });
    }

    return res.json({
      code: 0,
      msg: 'BIOS UUID更新成功',
      data: { bios_uuid }
    });

  } catch (err) {
    logger.error('[Update BIOS] 更新失败:', {
      error: err.message,
      code: err.code,
      sql_state: err.sqlState,
      sql_message: err.sqlMessage,
      stack: err.stack,
      request: {
        device_id: req.body.device_id,
        bios_uuid: req.body.bios_uuid
      },
      client_ip: req.ip.replace(/^::ffff:/, '')
    });
    return res.json({ code: -1, msg: '服务器错误' });
  } finally {
    if (conn) await conn.end();
  }
});

// 添加批量上传账号接口
app.post('/api/upload_accounts', async (req, res) => {
  let conn;
  try {
    const accounts = req.body;

    // 验证请求体是否为数组
    if (!Array.isArray(accounts)) {
      return res.json({
        code: 1,
        msg: '请求格式错误，应该是账号数组'
      });
    }

    // 验证每个账号的必要字段
    for (const account of accounts) {
      if (!account.email || !account.password || !account.access_token || !account.refresh_token) {
        return res.json({
          code: 1,
          msg: '账号信息不完整，必须包含 email、password、access_token、refresh_token',
          data: account
        });
      }
    }

    conn = await mysql.createConnection(dbConfig);
    await conn.beginTransaction();

    // 构建批量插入的值
    const values = accounts.map(acc => [
      acc.email,
      acc.password,
      acc.access_token,
      acc.refresh_token,
      acc.source_from || 'upload',
      new Date(),
      0,
      0
    ]);

    // 修改SQL语句，使用正确的批量插入语法
    const placeholders = values.map(() => '(?, ?, ?, ?, ?, ?, ?, ?)').join(',');
    const flatValues = values.flat();

    const [result] = await conn.execute(`
      INSERT INTO cursor_accounts (
        email,
        password,
        access_token,
        refresh_token,
        source_from,
        created_at,
        used,
        need_verify
      ) VALUES ${placeholders}
    `, flatValues);

    await conn.commit();

    logger.info('[Upload Accounts] 成功上传账号:', {
      count: result.affectedRows,
      first_email: accounts[0].email,
      last_email: accounts[accounts.length - 1].email
    });

    return res.json({
      code: 0,
      msg: '上传成功',
      data: {
        total: result.affectedRows
      }
    });

  } catch (err) {
    if (conn) await conn.rollback();

    // 处理重复邮箱错误
    if (err.code === 'ER_DUP_ENTRY') {
      return res.json({
        code: 2,
        msg: '存在重复的邮箱账号'
      });
    }

    logger.error('[Upload Accounts] 上传失败:', {
      error: err.message,
      code: err.code,
      sql_state: err.sqlState,
      sql_message: err.sqlMessage
    });

    return res.json({
      code: -1,
      msg: '上传失败: ' + err.message
    });

  } finally {
    if (conn) await conn.end();
  }
});

// 修改 check_member 接口
app.post('/api/check_member', async (req, res) => {
  let conn;
  try {
    const clientIP = req.ip.replace(/^::ffff:/, '');
    const { device_id, bios_uuid } = req.body;

    // 验证参数
    if (!device_id && !bios_uuid) {
      logger.warn('[Check Member] 设备ID和BIOS UUID不能同时为空');
      return res.json({ code: 1, msg: '设备标识不能为空' });
    }

    // 如果提供了 device_id，验证格式
    if (device_id) {
      if (device_id.includes('-')) {
        logger.info('[Check Member] device_id 格式似乎是 UUID，将作为 bios_uuid 处理');
        if (!req.body.bios_uuid) {
          req.body.bios_uuid = device_id;
        }
        delete req.body.device_id;
      } else if (!validateDeviceId(device_id)) {
        logger.warn('[Check Member] 无效的设备ID:', { device_id });
        return res.json({ code: 1, msg: '无效的设备ID3' });
      }
    }

    // 验证 bios_uuid 格式(如果有)
    if (bios_uuid && !validateBiosUuid(bios_uuid)) {
      logger.warn('[Check Member] 无效的BIOS UUID:', { bios_uuid });
      return res.json({ code: 1, msg: '无效的BIOS UUID格式' });
    }

    conn = await mysql.createConnection(dbConfig);
    let isTimeLimitedMember = false;

    // 先检查时限会员
    if (bios_uuid && bios_uuid.trim() !== '') {
      const [timeLimitedMembers] = await conn.execute(`
        SELECT 
          id,
          activated_at,
          expire_at 
        FROM members 
        WHERE BIOS_UUID = ? 
          AND expire_at > NOW()
      `, [bios_uuid]);

      if (timeLimitedMembers.length > 0) {
        isTimeLimitedMember = true;
        const member = timeLimitedMembers[0];
        logger.info('[Check Member] 找到时限会员:', {
          bios_uuid,
          expire_at: member.expire_at
        });

      }
    }

    if (!isTimeLimitedMember) {
      // 检查额度会员
      if (bios_uuid && bios_uuid.trim() !== '') {
        const [quotaMembers] = await conn.execute(`
          SELECT 
            id,
            remaining_quota,
            total_quota,
            activated_at,
            expire_at 
          FROM quota_members 
          WHERE BIOS_UUID = ? 
            AND expire_at > NOW()
            AND remaining_quota >= 0
        `, [bios_uuid]);

        if (quotaMembers.length > 0) {
          const quotaMember = quotaMembers[0];
          logger.info('[Check Member] 找到额度会员:', {
            bios_uuid,
            remaining_quota: quotaMember.remaining_quota,
            expire_at: quotaMember.expire_at
          });

          return res.json({
            code: 0,
            data: {
              is_valid: true,
              is_quota_member: true,
              activate_time: quotaMember.activated_at,
              expire_time: quotaMember.expire_at,
              remaining_quota: quotaMember.remaining_quota,
              total_quota: quotaMember.total_quota
            }
          });
        }
      }
    }

    // 检查是否是特殊的 BIOS UUID 前缀
    const SPECIAL_PREFIX = '03000200-0400-0500-0006-000700080009-';
    if (bios_uuid && bios_uuid.trim() !== '' && bios_uuid.startsWith(SPECIAL_PREFIX)) {
      // 查询是否已存在该 BIOS UUID 的会员
      const [existingMembers] = await conn.execute(
        'SELECT * FROM members WHERE BIOS_UUID = ? AND expire_at > NOW()',
        [bios_uuid]
      );

      if (existingMembers.length === 0) {
        // 设置为北京时区
        await conn.execute('SET time_zone = "+08:00"');

        // 创建新会员记录
        await conn.execute(`
          INSERT INTO members (
            BIOS_UUID,
            activated_at,
            expire_at,
            activate_ip,
            created_at
          ) VALUES (
            ?,
            NOW(),
            DATE_ADD(NOW(), INTERVAL 1 MONTH),
            ?,
            NOW()
          )
        `, [bios_uuid, clientIP]);

        // 获取新创建的会员信息
        const [newMember] = await conn.execute(
          'SELECT activated_at, expire_at FROM members WHERE BIOS_UUID = ? ORDER BY id DESC LIMIT 1',
          [bios_uuid]
        );

        logger.info('[Check Member] 自动创建特殊BIOS UUID会员:', {
          bios_uuid,
          activate_time: newMember[0].activated_at,
          expire_time: newMember[0].expire_at,
          client_ip: clientIP
        });

        // 恢复默认时区
        await conn.execute('SET time_zone = "+00:00"');

        return res.json({
          code: 0,
          data: {
            is_valid: true,
            activate_time: newMember[0].activated_at,
            expire_time: newMember[0].expire_at
          }
        });
      }
    }

    // 原有的会员查询逻辑
    let members = [];

    // 优先查询 bios_uuid，确保非空才查询
    if (bios_uuid && bios_uuid.trim() !== '') {
      const [uuidMembers] = await conn.execute(
        'SELECT * FROM members WHERE BIOS_UUID = ? AND BIOS_UUID != "" AND expire_at > NOW()',
        [bios_uuid]
      );
      if (uuidMembers.length > 0) {
        members = uuidMembers;
        logger.info('[Check Member] 通过BIOS UUID找到会员:', {
          bios_uuid,
          member_id: uuidMembers[0].id,
          expire_at: uuidMembers[0].expire_at
        });
      } else {
        logger.info('[Check Member] BIOS UUID未找到会员:', { bios_uuid });
      }
    }

    // 如果bios_uuid没查到且有device_id时查询，确保非空才查询
    if (members.length === 0 && device_id && device_id.trim() !== '') {
      const [deviceMembers] = await conn.execute(
        'SELECT * FROM members WHERE device_id = ? AND device_id != "" AND expire_at > NOW()',
        [device_id]
      );
      if (deviceMembers.length > 0) {
        members = deviceMembers;
        logger.info('[Check Member] 通过device_id找到会员:', {
          device_id,
          member_id: deviceMembers[0].id,
          expire_at: deviceMembers[0].expire_at
        });
      } else {
        logger.info('[Check Member] device_id未找到会员:', { device_id });
      }
    }

    logger.info(`[Check Member] 会员查询结果:`, {
      device_found: device_id && members[0]?.device_id === device_id,
      uuid_found: bios_uuid && members[0]?.BIOS_UUID === bios_uuid,
      using: members[0]?.BIOS_UUID === bios_uuid ? 'bios_uuid' : 'device_id',
      found_members: members.length > 0
    });

    if (members.length > 0) {
      const member = members[0];
      const response = {
        code: 0,
        data: {
          is_valid: true,
          activate_time: member.activated_at,
          expire_time: member.expire_at
        }
      };
      logger.info(`[Check Member] 返回会员数据:`, response);
      return res.json(response);
    }

    // 2. 检查试用功能是否开启
    const enableTrial = await getSystemConfig('enable_trial');
    if (enableTrial !== 'true') {
      return res.json({
        code: 0,
        data: {
          is_valid: false,
          can_trial: false,
          msg: '试用功能已关闭，请激活会员'
        }
      });
    }

    // 3. 检查试用状态
    const [trials] = await conn.execute(
      'SELECT * FROM trials WHERE device_id = COALESCE(?, "") OR (ip = ? AND ip IS NOT NULL)',
      [
        device_id || null,  // 处理可能的 undefined
        clientIP || null    // 处理可能的 undefined
      ]
    );
    logger.info(`[Check Member] 试用查询结果:`, { found: trials.length > 0, trials });

    // 4. 返回状态
    const response = {
      code: 0,
      data: {
        is_valid: false,
        can_trial: trials.length === 0,
        msg: trials.length > 0 ? '请先激活会员或续费' : '可以试用'
      }
    };
    logger.info(`[Check Member] 返回试用状态:`, response);
    return res.json(response);

  } catch (err) {
    logger.error('[Check Member] 处理出错:', err);
    res.status(500).json({ code: 1, msg: '服务器错误' });
  } finally {
    if (conn) {
      try {
        await conn.end();
      } catch (err) {
        logger.error('[Check Member] 关闭数据库连接失败:', err);
      }
    }
  }
});

app.post('/api/activate_member', async (req, res) => {
  let conn;
  try {
    const { activation_code, device_id, bios_uuid, info } = req.body;
    const clientIP = req.ip.replace(/^::ffff:/, '');

    logger.info('[Activate] 收到激活请求:', {
      activation_code,
      device_id,
      bios_uuid,
      info,
      client_ip: clientIP
    });

    // 验证参数
    if (!activation_code || (!device_id && !bios_uuid)) {
      logger.warn('[Activate] 参数验证失败:', {
        has_code: !!activation_code,
        has_device_id: !!device_id,
        has_bios_uuid: !!bios_uuid
      });
      return res.json({ code: 1, msg: '激活码和设备标识不能为空' });
    }

    conn = await mysql.createConnection(dbConfig);

    // 1. 先检查是否是额度激活码
    await conn.execute('SET time_zone = "+08:00"');
    const [quotaCodes] = await conn.execute(
      'SELECT *, DATE_FORMAT(used_at, "%Y-%m-%d %H:%i:%s") as used_time, used_by FROM quota_activation_codes WHERE code = ?',
      [activation_code]
    );
    await conn.execute('SET time_zone = "+00:00"');

    // 如果是额度激活码
    if (quotaCodes.length > 0) {
      const quotaCode = quotaCodes[0];

      // 检查激活码是否已使用
      if (quotaCode.used === 1) {
        const usedByMessage = quotaCode.used_by === bios_uuid ? '【本机器】' : quotaCode.used_by || '未知';
        return res.json({
          code: 3,
          msg: `额度激活码已于 ${quotaCode.used_time} 被${usedByMessage}使用，只需激活一次，请检查会员有效期是否变更`,
          data: {
            used_time: quotaCode.used_time,
            used_by: quotaCode.used_by,
            ip: quotaCode.ip
          }
        });
      }

      // 检查是否已有额度会员记录
      const [existingQuotaMembers] = await conn.execute(
        `SELECT *, 
          remaining_quota >= 0 AND expire_at > NOW() as is_valid 
         FROM quota_members WHERE BIOS_UUID = ?`,
        [bios_uuid]
      );

      await conn.execute('SET time_zone = "+08:00"');
      if (existingQuotaMembers.length > 0) {
        const member = existingQuotaMembers[0];
        const isValid = member.is_valid === 1;

        logger.info('[Activate] 检查额度会员状态:', {
          bios_uuid,
          member_id: member.id,
          remaining_quota: member.remaining_quota,
          expire_at: member.expire_at,
          is_valid: isValid
        });

        if (!isValid) {
          // 情况1: 已到期或额度为0，重新计算会员时长和额度
          await conn.execute(`
            UPDATE quota_members 
            SET remaining_quota = ?,
                total_quota = ?,
                expire_at = DATE_ADD(NOW(), INTERVAL ? DAY),
                activated_at = NOW(),
                info = COALESCE(?, info)
            WHERE BIOS_UUID = ?
          `, [
            quotaCode.quota,
            quotaCode.quota,
            quotaCode.expire_days,
            info || null,  // 处理可能的 undefined
            bios_uuid
          ]);

          logger.info('[Activate] 重置额度会员:', {
            bios_uuid,
            member_id: member.id,
            new_quota: quotaCode.quota,
            expire_days: quotaCode.expire_days
          });
        } else {
          // 情况2: 未到期且有剩余额度，增加额度并延长有效期
          await conn.execute(`
            UPDATE quota_members 
            SET remaining_quota = remaining_quota + ?,
                total_quota = total_quota + ?,
                expire_at = DATE_ADD(expire_at, INTERVAL ? DAY)
            WHERE BIOS_UUID = ?
          `, [quotaCode.quota, quotaCode.quota, quotaCode.expire_days, bios_uuid]);

          logger.info('[Activate] 更新额度会员:', {
            bios_uuid,
            member_id: member.id,
            added_quota: quotaCode.quota,
            original_total: member.total_quota,
            original_remaining: member.remaining_quota,
            added_days: quotaCode.expire_days
          });
        }
      } else {
        // 创建新额度会员
        await conn.execute(`
          INSERT INTO quota_members (
            BIOS_UUID,
            remaining_quota,
            total_quota,
            activated_at,
            expire_at,
            activate_ip,
            created_at,
            info
          ) VALUES (
            ?,
            ?,
            ?,
            NOW(),
            DATE_ADD(NOW(), INTERVAL ? DAY),
            ?,
            NOW(),
            ?
          )
        `, [
          bios_uuid,
          quotaCode.quota,
          quotaCode.quota,
          quotaCode.expire_days,
          clientIP || null,  // 处理可能的 undefined
          info || null       // 处理可能的 undefined
        ]);

        // 添加日志记录以便调试
        logger.info('[Activate] 创建额度会员:', {
          bios_uuid,
          quota: quotaCode.quota,
          expire_days: quotaCode.expire_days,
          client_ip: clientIP || null,
          info: info || null
        });
      }

      // 标记额度激活码已使用
      await conn.execute(`
        UPDATE quota_activation_codes 
        SET used = 1,
            used_at = NOW(),
            used_by = ?,
            ip = ?
        WHERE code = ?
      `, [bios_uuid, clientIP, activation_code]);

      // 获取更新后的会员信息
      const [updatedMember] = await conn.execute(
        'SELECT * FROM quota_members WHERE BIOS_UUID = ?',
        [bios_uuid]
      );

      await conn.execute('SET time_zone = "+00:00"');

      // 计算需要锁定的账号数量 (每50额度一个账号，不足50的部分多分配一个)
      const lockCount = Math.ceil(quotaCode.quota / 50);

      const [accounts] = await conn.execute(`
        SELECT * FROM cursor_accounts 
        WHERE used = 0 
        AND (is_locked != 1 OR is_locked IS NULL)
        AND need_verify = 0
        LIMIT ?
      `, [lockCount]);

      if (accounts.length === 0) {
        return res.json({ code: 2, msg: '暂无可用账号' });
      }

      // 锁定所有分配的账号
      for (const account of accounts) {
        await conn.execute(`
          UPDATE cursor_accounts 
          SET used = 1,
            is_locked = 1,
            used_by = ?,
            used_at = NOW()
          WHERE id = ?
        `, [bios_uuid, account.id]);
      }

      // 记录锁定关系
      const expireAt = new Date(updatedMember[0].expire_at);
      for (const account of accounts) {
        await conn.execute(`
          INSERT INTO quota_member_accounts (
            member_id,
            account_id,
            expire_at
          ) VALUES (?, ?, ?)
        `, [updatedMember[0].id, account.id, expireAt]);
      }

      // 更新额度会员锁定账号数量
      await conn.execute(`
        UPDATE quota_members 
        SET locked_accounts_count = ?
        WHERE id = ?
      `, [accounts.length, updatedMember[0].id]);

      // 这里添加刷新账号的逻辑
      const [availableAccounts] = await conn.execute(`
        SELECT * FROM cursor_accounts 
        WHERE used = 0 
        AND (is_locked != 1 OR is_locked IS NULL)
        AND need_verify = 0
        LIMIT 1
      `);

      if (availableAccounts.length === 0) {
        return res.json({ code: 2, msg: '暂无可用账号' });
      }

      const account = availableAccounts[0]; // 获取第一个可用账号

      // 标记账号为已使用
      await conn.execute(`
        UPDATE cursor_accounts 
        SET used = 1,
            is_locked = 1,
            used_by = ?,
            used_at = NOW()
        WHERE id = ?
      `, [bios_uuid, account.id]);

      // 更新 quota_members 表中的 current_account_id
      await conn.execute(`
        UPDATE quota_members 
        SET current_account_id = ? 
        WHERE id = ?
      `, [account.id, updatedMember[0].id]);

      logger.info('[Activate] 更新额度会员当前账号:', {
        member_id: updatedMember[0].id,
        account_id: account.id
      });

      return res.json({
        code: 0,
        msg: '激活成功',
        data: {
          email: account.email,
          access_token: account.access_token,
          refresh_token: account.refresh_token,
          is_quota_member: true,
          remaining_quota: updatedMember[0].remaining_quota,
          total_quota: updatedMember[0].total_quota,
          activate_time: updatedMember[0].activated_at,
          expire_time: updatedMember[0].expire_at
        }
      });
    }

    // 2. 如果不是额度激活码，继续原有的激活码处理逻辑
    // 1. 验证激活码
    logger.info('[Activate] 开始验证激活码:', { activation_code });
    await conn.execute('SET time_zone = "+08:00"');  // 设置为北京时区
    const [codes] = await conn.execute(
      'SELECT *, DATE_FORMAT(used_at, "%Y-%m-%d %H:%i:%s") as used_time FROM activation_codes WHERE code = ?',
      [activation_code]
    );
    await conn.execute('SET time_zone = "+00:00"');  // 恢复默认时区

    logger.info('[Activate] 激活码查询结果:', {
      found: codes.length > 0,
      code_info: codes[0] || null
    });

    if (codes.length === 0) {
      return res.json({ code: 3, msg: '无效的激活码6' });
    }

    const code = codes[0];

    // 如果激活码已使用，返回使用信息
    if (code.used === 1) {
      return res.json({
        code: 3,
        msg: `激活码已于 ${code.used_time} 被设备 ${code.used_by || '未知'} 使用`,
        data: {
          used_time: code.used_time,
          used_by: code.used_by,
          ip: code.ip
        }
      });
    }

    // 分别查询 device_id 和 bios_uuid
    let existingMembers = [];
    if (bios_uuid) {
      const [uuidMembers] = await conn.execute(
        'SELECT * FROM members WHERE BIOS_UUID = ?',
        [bios_uuid]
      );
      existingMembers = uuidMembers;
      logger.info('[Activate] BIOS UUID查询结果:', {
        bios_uuid,
        found: uuidMembers.length > 0
      });
    }

    // 根据实际使用的会员记录更新查询条件
    const whereClause = 'BIOS_UUID = ?';
    const params = [bios_uuid];

    logger.info('[Activate] 最终查询条件:', {
      whereClause,
      params,
      existingMembersFound: existingMembers.length > 0
    });

    let activateTime, expireTime;

    if (existingMembers.length > 0) {
      // 已是会员，延长有效期
      const member = existingMembers[0];
      logger.info('[Activate] 当前会员状态:', {
        bios_uuid: member.BIOS_UUID,
        current_expire: member.expire_at,
        days_to_add: code.days,
        info
      });

      try {
        // 更新会员记录，使用 MySQL 的 DATE_ADD 函数并设置北京时区
        await conn.execute('SET time_zone = "+08:00"');  // 设置为北京时区

        const [beforeUpdate] = await conn.execute(
          `SELECT expire_at FROM members WHERE ${whereClause}`,
          params
        );
        logger.info('[Activate] 更新前状态:', { beforeUpdate });

        await conn.execute(`
          UPDATE members 
          SET expire_at = DATE_ADD(
            CASE 
              WHEN expire_at < NOW() THEN NOW() 
              ELSE expire_at 
            END, 
            INTERVAL ? DAY
          ),
          activate_ip = COALESCE(activate_ip, ?),
          info = COALESCE(?, info)
          WHERE ${whereClause}
        `, [
          code.days,
          clientIP || null,
          info || null,
          bios_uuid
        ]);

        // 验证更新结果
        const sql = `SELECT activated_at, expire_at FROM members WHERE ${whereClause}`;
        logger.info('[Activate] 执行验证SQL:', {
          sql,
          params,
          whereClause,
          time: new Date().toISOString()
        });

        const [afterUpdate] = await conn.execute(sql, params);

        logger.info('[Activate] 更新后状态:', {
          afterUpdate,
          found: afterUpdate && afterUpdate.length > 0,
          time: new Date().toISOString()
        });

        if (!afterUpdate || afterUpdate.length === 0) {
          logger.error('[Activate] 未找到更新后的会员记录:', {
            sql,
            params,
            whereClause,
            time: new Date().toISOString()
          });
          throw new Error('更新会员记录后未找到会员信息');
        }

        activateTime = afterUpdate[0].activated_at;
        expireTime = afterUpdate[0].expire_at;

        await conn.execute('SET time_zone = "+00:00"');  // 恢复默认时区
      } catch (err) {
        logger.error('[Activate] 更新会员记录失败:', {
          error: err.message,
          stack: err.stack,
          request: {
            bios_uuid
          },
          days: code.days
        });
        throw err;
      }
    } else if (bios_uuid) {
      try {
        logger.info('[Activate] 开始创建新会员');
        // 新会员，使用北京时间
        await conn.execute('SET time_zone = "+08:00"');  // 设置为北京时区

        logger.info('[Activate] 开始创建新会员:', {
          bios_uuid,
          days: code.days,
          clientIP
        });

        // 构建插入字段和值
        const insertFields = ['activated_at', 'expire_at', 'activate_ip', 'created_at', 'BIOS_UUID', 'info'];
        const insertValues = ['NOW()', 'DATE_ADD(NOW(), INTERVAL ? DAY)', '?', 'NOW()', '?', '?'];
        const insertParams = [
          code.days,
          clientIP || null,  // 如果 clientIP 为 undefined，使用 null
          bios_uuid,
          info || null      // 如果 info 为 undefined，使用 null
        ];

        logger.info('[Activate] 准备插入会员记录:', {
          fields: insertFields,
          values: insertValues,
          params: insertParams
        });

        await conn.execute(`
          INSERT INTO members (
            ${insertFields.join(', ')}
          ) VALUES (${insertValues.join(', ')})
        `, insertParams);

        // 获取插入的时间用于日志和返回
        const [newMember] = await conn.execute(
          `SELECT activated_at, expire_at FROM members WHERE ${whereClause}`,
          params
        );

        activateTime = newMember[0].activated_at;
        expireTime = newMember[0].expire_at;

        logger.info('[Activate] 新会员创建成功:', {
          bios_uuid,
          activate_time: activateTime,
          expire_time: expireTime
        });

        await conn.execute('SET time_zone = "+00:00"');  // 恢复默认时区
      } catch (err) {
        logger.error('[Activate] 创建新会员失败:', {
          error: err.message,
          code: err.code,
          sql_state: err.sqlState,
          sql_message: err.sqlMessage,
          stack: err.stack,
          request: {
            bios_uuid,
            activation_code
          }
        });
        throw err;
      }
    } else {
      return res.json({ code: 1, msg: '必须提供BIOS UUID' });
    }

    // 标记激活码已使用
    logger.info('[Activate] 开始标记激活码已使用:', {
      code: activation_code,
      used_by: bios_uuid,
      client_ip: clientIP
    });

    // 确保激活码被正确核销
    try {
      await conn.execute('SET time_zone = "+08:00"');  // 设置为北京时区
      await conn.execute(`
        UPDATE activation_codes 
        SET used = 1, 
            used_at = NOW(),
            used_by = ?,
            ip = ?
        WHERE code = ?
        AND used = 0  /* 确保只更新未使用的激活码 */
      `, [bios_uuid, clientIP, activation_code]);

      // 验证更新是否成功
      const [updatedCode] = await conn.execute(
        'SELECT used, used_at FROM activation_codes WHERE code = ?',
        [activation_code]
      );

      if (!updatedCode[0] || !updatedCode[0].used) {
        throw new Error('激活码核销失败');
      }

      logger.info('[Activate] 激活码已成功核销');
      await conn.execute('SET time_zone = "+00:00"');  // 恢复默认时区
    } catch (err) {
      logger.error('[Activate] 激活码核销失败:', {
        error: err.message,
        code: err.code,
        activation_code
      });
      throw err;
    }
    // 使用 MySQL 的时间函数来比较
    await conn.execute('SET time_zone = "+08:00"');  // 设置为北京时区
    // 获取一个可用账号
    const [accounts] = await conn.execute(`
      SELECT * FROM cursor_accounts 
      WHERE used = 0 
      AND (is_locked != 1 OR is_locked IS NULL)
      AND need_verify = 0
      LIMIT 1
    `);

    if (accounts.length === 0) {
      return res.json({ code: 2, msg: '暂无可用账号' });
    }

    // 获取第一个可用账号
    const account = accounts[0];  // 添加这行来定义 account 变量

    // 标记账号为已使用
    await conn.execute(`
      UPDATE cursor_accounts 
      SET used = 1,
          used_by = COALESCE(?, ""),
          used_at = NOW()
      WHERE id = ?
    `, [bios_uuid, account.id]);

    // 如果是会员,更新 members 表中的 current_account_id
    if (existingMembers.length > 0) {  // 这里改用 existingMembers
      await conn.execute(`
        UPDATE members 
        SET current_account_id = ? 
        WHERE id = ?
      `, [account.id, existingMembers[0].id]);  // 这里也改用 existingMembers

      logger.info('[Refresh] 更新会员当前账号:', {
        member_id: existingMembers[0].id,  // 这里也改用 existingMembers
        account_id: account.id
      });
    }

    // 记录刷新历史，使用北京时间
    const insertSql = `
      INSERT INTO refresh_history (
        device_id,
        account_id,
        refresh_time,
        ip
      ) VALUES (?, ?, now(), ?)
    `;

    const insertParams = [
      bios_uuid,
      account.id,
      clientIP
    ];

    logger.info('[Refresh] 准备执行SQL:', {
      sql: insertSql,
      params: insertParams
    });

    await conn.execute(insertSql, insertParams);
    await conn.execute('SET time_zone = "+00:00"');  // 恢复默认时区
    logger.info('[Refresh] 记录刷新历史:', {
      device_id: bios_uuid,
      account_id: account.id,
      ip: clientIP,
      sql: insertSql.replace(/\s+/g, ' ').trim()  // 格式化SQL便于阅读
    });

    return res.json({
      code: 0,
      data: {
        email: account.email,
        access_token: account.access_token,
        refresh_token: account.refresh_token,
        activate_time: activateTime,
        expire_time: expireTime
      }
    });

  } catch (err) {
    logger.error('[Activate] 激活失败:', {
      error: err.message,
      code: err.code,
      sql_state: err.sqlState,
      sql_message: err.sqlMessage,
      stack: err.stack,
      request: {
        device_id: req.body.device_id,
        bios_uuid: req.body.bios_uuid,
        activation_code: req.body.activation_code
      },
      client_ip: req.ip.replace(/^::ffff:/, '')
    });
    return res.json({ code: -1, msg: '服务器错误' });
  } finally {
    if (conn) {
      try {
        await conn.end();
        logger.info('[Activate] 数据库连接已关闭');
      } catch (err) {
        logger.error('[Activate] 关闭数据库连接失败:', err);
      }
    }
  }
});

// 修改数据迁移 API
app.post('/api/migrate_accounts', async (req, res) => {
  try {
    const conn = await mysql.createConnection(dbConfig);
    await conn.beginTransaction();

    try {
      // 检查旧表是否存在
      const [tables] = await conn.execute(`
        SELECT TABLE_NAME 
        FROM information_schema.TABLES 
        WHERE TABLE_SCHEMA = ? AND TABLE_NAME = 'accounts'
      `, [process.env.DB_NAME]);

      if (tables.length === 0) {
        return res.json({
          code: 1,
          msg: '旧表 accounts 不存在',
          details: {
            status: 'error',
            error: 'TABLE_NOT_FOUND'
          }
        });
      }

      // 获取旧表数据
      const [oldAccounts] = await conn.execute('SELECT * FROM accounts');
      logger.info(`找到 ${oldAccounts.length} 个账号需要迁移`);

      if (oldAccounts.length === 0) {
        return res.json({
          code: 0,
          msg: '没有需要迁移的数据',
          details: {
            status: 'info',
            total: 0,
            migrated: 0
          }
        });
      }

      // 迁移数据
      let migrated = 0;
      let failed = 0;
      const errors = [];

      for (const account of oldAccounts) {
        try {
          // 检查账号是否已存在
          const [exists] = await conn.execute(
            'SELECT id FROM cursor_accounts WHERE email = ?',
            [account.email]
          );

          if (exists.length > 0) {
            failed++;
            errors.push({
              email: account.email,
              error: 'ALREADY_EXISTS'
            });
            continue;
          }

          // 插入新数据
          const [result] = await conn.execute(
            'INSERT INTO cursor_accounts (email, password, access_token, refresh_token, used, used_by, used_at) VALUES (?, ?, ?, ?, ?, ?, ?)',
            [
              account.email,
              account.password || '',
              account.access_token || '',
              account.refresh_token || '',
              account.used || 0,
              account.used_by || null,
              account.used_at || null
            ]
          );

          if (result.affectedRows > 0) {
            migrated++;
          } else {
            failed++;
            errors.push({
              email: account.email,
              error: 'INSERT_FAILED'
            });
          }
        } catch (err) {
          failed++;
          errors.push({
            email: account.email,
            error: err.message
          });
          logger.error(`迁移账号 ${account.email} 失败:`, err);
        }
      }

      await conn.commit();

      return res.json({
        code: 0,
        msg: `迁移完成`,
        details: {
          status: 'success',
          total: oldAccounts.length,
          migrated: migrated,
          failed: failed,
          errors: errors
        }
      });

    } catch (err) {
      await conn.rollback();
      throw err;
    } finally {
      await conn.end();
    }

  } catch (err) {
    logger.error('数据迁移失败:', err);
    return res.json({
      code: -1,
      msg: '迁移失败',
      details: {
        status: 'error',
        error: err.message,
        stack: err.stack
      }
    });
  }
});

// 添加生成激活码的 API
app.post('/api/generate_activation_code', async (req, res) => {
  try {
    const apiKey = req.headers['x-api-key'];

    // 验证密钥
    if (!apiKey || apiKey !== config.apiKey) {
      return res.json({ code: 403, msg: '无效的密钥' });
    }

    const { days, count = 1 } = req.body;

    if (!days || days <= 0) {
      return res.json({ code: 1, msg: '参数错误' });
    }

    const conn = await mysql.createConnection(dbConfig);
    await conn.beginTransaction();

    try {
      const codes = [];
      for (let i = 0; i < count; i++) {
        // 生成激活码 (16位随机字符)
        const activationCode = crypto.randomBytes(8).toString('hex').toUpperCase();

        // 插入数据库
        await conn.execute(
          'INSERT INTO activation_codes (code, days) VALUES (?, ?)',
          [activationCode, days]
        );

        codes.push(activationCode);
      }

      await conn.commit();

      return res.json({
        code: 0,
        data: {
          codes: codes,
          days: days
        }
      });

    } catch (err) {
      await conn.rollback();
      throw err;
    } finally {
      await conn.end();
    }

  } catch (err) {
    logger.error('生成激活码出错:', {
      error: err.message,
      stack: err.stack,
      request: {
        days: req.body.days,
        count: req.body.count
      }
    });
    return res.json({ code: -1, msg: '服务器错误' });
  }
});

// 修改刷新账号 API
app.post('/api/refresh_account', async (req, res) => {
  logger.info(`[seven] refresh_account`);
  let conn;
  try {
    const { device_id, bios_uuid, info } = req.body;
    const clientIP = req.ip.replace(/^::ffff:/, '');

    // 验证参数 - 增强验证逻辑
    if ((!device_id || device_id.trim() === '') && (!bios_uuid || bios_uuid.trim() === '')) {
      logger.warn('[Refresh] 设备ID和BIOS UUID不能同时为空');
      return res.json({ code: 1, msg: '设备标识不能为空' });
    }

    // 如果提供了bios_uuid，验证其格式
    if (bios_uuid && bios_uuid.trim() !== '') {
      if (!validateBiosUuid(bios_uuid)) {
        logger.warn('[Refresh] 无效的BIOS UUID:', { bios_uuid });
        return res.json({ code: 1, msg: '无效的BIOS UUID格式' });
      }
    }

    // 添加对特殊 BIOS UUID 的检查
    if (bios_uuid === '03000200-0400-0500-0006-000700080009') {
      logger.warn('[Refresh] 检测到特殊BIOS UUID:', {
        bios_uuid,
        client_ip: clientIP
      });
      return res.json({
        code: 6,
        msg: '您的主板厂商出厂时未写入设备ID，请联系销售商更新破解助手版本解决，如果您收到过破解助手注册邮件，请直接从邮件中重新下载即可'
      });
    }

    conn = await mysql.createConnection({
      ...dbConfig,
      connectTimeout: 10000
    });

    // 分别查询 device_id 和 bios_uuid，确保非空才查询
    const [deviceMembers] = await conn.execute(
      'SELECT * FROM members WHERE device_id = ? AND expire_at > NOW()',
      [device_id && device_id.trim() !== '' ? device_id : null]
    );

    const [uuidMembers] = await conn.execute(
      'SELECT * FROM members WHERE BIOS_UUID = ? AND expire_at > NOW()',
      [bios_uuid && bios_uuid.trim() !== '' ? bios_uuid : null]
    );

    // 使用能查到会员的标识 - 先定义 useDeviceId
    const useDeviceId = !bios_uuid || (device_id && !uuidMembers.length);
    const validMembers = uuidMembers.length > 0 ? uuidMembers : deviceMembers;
    if (validMembers.length <= 0) {
      // 先检查额度会员
      if (bios_uuid && bios_uuid.trim() !== '') {
        const [quotaMembers] = await conn.execute(`
            SELECT * FROM quota_members 
            WHERE BIOS_UUID = ? 
              AND expire_at > NOW()
              AND remaining_quota >= 0
          `, [bios_uuid]);

        if (quotaMembers.length > 0) {
          const quotaMember = quotaMembers[0];

          // 检查额度是否小于50
          if (quotaMember.remaining_quota < 50) {
            return res.json({ code: 4, msg: `额度不足，请购买额度，当前剩余额度为 ${quotaMember.remaining_quota}` }); // 修改提示信息
          }

          // 先释放过期账号
          await conn.execute(`
              UPDATE cursor_accounts ca
              JOIN quota_member_accounts qma ON qma.account_id = ca.id
              SET ca.is_locked = 0
              WHERE qma.expire_at <= NOW()
            `);

          // 删除过期的锁定关系并更新会员锁定账号数量
          await conn.execute(`
              UPDATE quota_members qm
              SET qm.locked_accounts_count = qm.locked_accounts_count - (
                SELECT COUNT(*) 
                FROM quota_member_accounts qma 
                WHERE qma.member_id = qm.id 
                AND qma.expire_at <= NOW()
              )
              WHERE qm.id = ?
            `, [quotaMember.id]);

          await conn.execute(`
              DELETE FROM quota_member_accounts 
              WHERE expire_at <= NOW()
            `);

          let exchangedAccount = null;
          // 如果有足够额度，先兑换一个新账号
          if (quotaMember.remaining_quota >= 50) {
            // 查找可用的未锁定账号
            const [availableAccounts] = await conn.execute(`
                SELECT * FROM cursor_accounts 
                WHERE used = 0 
                AND (is_locked != 1 OR is_locked IS NULL)
                AND need_verify = 0
                LIMIT 1
              `);

            if (availableAccounts.length > 0) {
              // 锁定新账号
              const account = availableAccounts[0];
              await conn.execute(`
                  UPDATE cursor_accounts 
                  SET used = 1,
                      is_locked = 1,
                      used_by = ?,
                      used_at = NOW()
                  WHERE id = ?
                `, [bios_uuid, account.id]);

              // 记录锁定关系
              await conn.execute(`
                  INSERT INTO quota_member_accounts (
                    member_id,
                    account_id,
                    expire_at
                  ) VALUES (?, ?, ?)
                `, [quotaMember.id, account.id, quotaMember.expire_at]);

              // 扣减额度并更新锁定账号数量
              const usedQuota = 50;
              await conn.execute(`
                  UPDATE quota_members 
                  SET remaining_quota = remaining_quota - ?,
                      locked_accounts_count = locked_accounts_count + ?
                  WHERE id = ?
                `, [usedQuota, 1, quotaMember.id]);

              logger.info('[Refresh] 成功兑换新账号:', {
                bios_uuid,
                member_id: quotaMember.id,
                account_id: account.id,
                remaining_quota: quotaMember.remaining_quota - 50
              });

              exchangedAccount = account;
            } else {
              logger.warn('[Refresh] 无可用账号可兑换:', {
                bios_uuid,
                remaining_quota: quotaMember.remaining_quota
              });
              return res.json({ code: 2, msg: '暂无可用账号，请稍后再试' });
            }
          }

          // 如果成功兑换了新账号，直接使用它
          if (exchangedAccount) {
            // 记录使用历史
            await conn.execute(`
                INSERT INTO quota_usage_history (
                  member_id,
                  account_id,
                  used_at,
                  ip,
                  type,
                  quota_used
                ) VALUES (?, ?, NOW(), ?, ?, ?)
              `, [
              quotaMember.id,
              exchangedAccount.id,
              clientIP,
              'exchange', // 标记为兑换操作
              50         // 记录使用的额度
            ]);
          } else {
            // 如果没有兑换新账号，说明额度不足
            return res.json({ code: 2, msg: '您的额度不足50，无法兑换新账号' });
          }

          // 获取最新的会员信息
          const [updatedMember] = await conn.execute(`
              SELECT remaining_quota, locked_accounts_count
              FROM quota_members
              WHERE id = ?
            `, [quotaMember.id]);

          return res.json({
            code: 0,
            data: {
              email: exchangedAccount.email,
              access_token: exchangedAccount.access_token,
              refresh_token: exchangedAccount.refresh_token,
              is_quota_member: true,
              remaining_quota: updatedMember[0].remaining_quota,
              locked_accounts_count: updatedMember[0].locked_accounts_count
            }
          });
        }
      }
    }
    // 特殊处理的 BIOS_UUID - 移到这里
    const SPECIAL_BIOS_UUID = '03000200-0400-0500-0006-000700080009';

    // 如果是特殊的 BIOS_UUID，将 IP 地址附加到 used_by 中 - 最后定义 effectiveUsedBy
    const effectiveUsedBy = (bios_uuid === SPECIAL_BIOS_UUID) ?
      `${bios_uuid}_${clientIP}` :
      (useDeviceId ? device_id : bios_uuid);

    logger.info(`[Refresh] 会员查询结果:`, {
      device_found: deviceMembers.length > 0,
      uuid_found: uuidMembers.length > 0,
      using: !useDeviceId ? 'bios_uuid' : 'device_id'
    });

    // 更新当前设备最近使用的账号的 end_at
    await conn.execute(`
      UPDATE cursor_accounts 
      SET end_at = NOW(),
          need_verify = CASE 
            WHEN used_at IS NOT NULL 
            AND TIMESTAMPDIFF(MINUTE, used_at, NOW()) < 10 
            THEN 1 
            ELSE need_verify 
          END
      WHERE id = (
        SELECT id 
        FROM (
          SELECT id 
          FROM cursor_accounts 
          WHERE used_by = ? 
          AND end_at IS NULL 
          ORDER BY used_at DESC 
          LIMIT 1
        ) as latest
      )
    `, [effectiveUsedBy || null]);  // 处理可能的 undefined
    logger.info(`[seven] refresh_account refresh_time1`);
    // 同时更新 refresh_history 表的 refresh_time
    await conn.execute(`
      UPDATE refresh_history
      SET refresh_time = NOW()
      WHERE device_id = ?
      AND account_id = (
        SELECT id 
        FROM cursor_accounts 
        WHERE used_by = ? 
        ORDER BY used_at DESC 
        LIMIT 1
      )
    `, [effectiveUsedBy, effectiveUsedBy]);

    if (validMembers.length > 0) {
      const member = validMembers[0];
      logger.info('[Refresh] 会员刷新前状态:', {
        member_id: member.id,
        refresh_count: member.refresh_count,
        last_refresh_time: member.last_refresh_time
      });

      // 计算会员总天数(激活时间到到期时间)
      const [memberDays] = await conn.execute(`
        SELECT 
          DATEDIFF(expire_at, activated_at) as total_days,
          DATEDIFF(NOW(), activated_at) as days_since_activation
        FROM members
        WHERE id = ?
      `, [member.id]);

      // 添加空值检查
      const totalDays = memberDays[0]?.total_days || 0;
      const daysSinceActivation = memberDays[0]?.days_since_activation || 0;

      // 根据会员时长和激活时间设置每日和每小时账号限制
      const isFirstDay = daysSinceActivation === 0;  // 判断是否是首日
      const dailyLimit = isFirstDay ? 15 :  // 首日30次
        (totalDays >= 365 ? 15 : 15); // 年费15次，普通15次
      const hourlyLimit = isFirstDay ? 10 : // 首日每小时10次
        (totalDays >= 365 ? 10 : 10);  // 年费10次，普通10次

      logger.info('[Refresh] 会员类型检查:', {
        total_days: totalDays,
        days_since_activation: daysSinceActivation,
        is_first_day: isFirstDay,
        daily_limit: dailyLimit,
        hourly_limit: hourlyLimit,
        is_year_member: totalDays >= 365
      });

      // 检查今日已刷新的账号数量
      const [dailyRefresh] = await conn.execute(`
        SELECT COUNT(DISTINCT used_by) as count
        FROM cursor_accounts
        WHERE used_by = ?
        AND DATE(used_at) = CURDATE()
      `, [effectiveUsedBy]);

      // 在检查 dailyRefresh 之前添加新的检查
      const [usedAccounts] = await conn.execute(`
        SELECT 
          COUNT(DISTINCT account_id) as total_used,
          SUM(CASE WHEN requests >= 50 THEN 1 ELSE 0 END) as full_used
        FROM refresh_history rh
        WHERE rh.device_id = ?
          AND DATE(rh.refresh_time) = CURDATE()
      `, [effectiveUsedBy]);

      // 添加空值检查
      const totalUsed = usedAccounts[0]?.total_used || 0;
      const fullUsed = usedAccounts[0]?.full_used || 0;

      // 如果使用的账号数量超过15个,且所有账号的requests都达到50
      if (totalUsed >= 15 && totalUsed === fullUsed && totalUsed > 0) {
        logger.info('[Refresh] 当日账号额度已用完:', {
          device_id: effectiveUsedBy,
          total_used: totalUsed,
          full_used: fullUsed
        });

        return res.json({
          code: 5,
          msg: '当日额度已用完，请明日再试'
        });
      }

      // 原有的 dailyRefresh 检查继续保留
      const dailyCount = dailyRefresh[0]?.count || 0;  // 添加空值检查
      if (dailyCount >= dailyLimit) {
        logger.info('[Refresh] 超出每日账号限制:', {
          device_id: useDeviceId ? (device_id || null) : (bios_uuid || null),
          daily_count: dailyCount,
          daily_limit: dailyLimit,
          is_year_member: totalDays >= 365  // 使用 totalDays 替代 memberDays[0].total_days
        });

        return res.json({
          code: 5,
          msg: `今日刷新账号数已达上限(${dailyLimit}个)，请明天再试`
        });
      }

      // 使用 MySQL 的时间函数来比较
      await conn.execute('SET time_zone = "+08:00"');  // 设置为北京时区

      const [timeCheck] = await conn.execute(`
        SELECT 
          CASE 
            WHEN last_refresh_time IS NULL 
              OR HOUR(last_refresh_time) != HOUR(NOW()) 
              OR DATE(last_refresh_time) != DATE(NOW())
            THEN 1 
            ELSE 0 
          END as should_reset,
          refresh_count,
          CASE
            WHEN last_refresh_time IS NOT NULL 
            THEN DATE_FORMAT(
              DATE_ADD(last_refresh_time, INTERVAL 1 HOUR),
              '%Y-%m-%d %H:%i:%s'
            )
          END as next_refresh_time
        FROM members 
        WHERE id = ?
      `, [member.id]);

      // 添加空值检查
      const shouldReset = timeCheck[0]?.should_reset === 1;
      const currentCount = timeCheck[0]?.refresh_count || 0;
      const nextRefreshTime = timeCheck[0]?.next_refresh_time;

      if (shouldReset) {
        logger.info('[Refresh] 重置刷新计数');
        await conn.execute(
          'UPDATE members SET refresh_count = 1, last_refresh_time = NOW() WHERE id = ?',
          [member.id]
        );
      } else if (currentCount >= hourlyLimit) {
        logger.info('[Refresh] 超出每小时刷新限制:', {
          current_count: currentCount,
          hourly_limit: hourlyLimit,
          is_year_member: totalDays >= 365,
          next_refresh_time: nextRefreshTime
        });

        await conn.execute('SET time_zone = "+00:00"');  // 恢复默认时区

        return res.json({
          code: 5,
          msg: `刷新次数已达上限，请在 ${nextRefreshTime || '下个整点'} 后重试`
        });
      } else {
        logger.info('[Refresh] 增加刷新计数');
        await conn.execute(
          'UPDATE members SET refresh_count = refresh_count + 1, last_refresh_time = NOW() WHERE id = ?',
          [member.id]
        );
      }

      await conn.execute('SET time_zone = "+00:00"');  // 恢复默认时区
    } else {
      // 非会员，检查试用功能是否开启
      const enableTrial = await getSystemConfig('enable_trial');
      if (enableTrial !== 'true') {
        return res.json({
          code: 4,
          msg: '试用功能已关闭，请激活会员'
        });
      }

      // 检查试用状态
      const [trials] = await conn.execute(
        'SELECT * FROM trials WHERE device_id = COALESCE(?, "") OR (ip = ? AND ip IS NOT NULL)',
        [
          device_id || null,  // 处理可能的 undefined
          clientIP || null    // 处理可能的 undefined
        ]
      );

      if (trials.length > 0) {
        return res.json({
          code: 4,
          msg: '试用已用完，请激活会员'
        });
      }

      // 检查最近1小时内的试用次数
      const [recentTrials] = await conn.execute(`
        SELECT COUNT(*) as count 
        FROM trials 
        WHERE created_at > DATE_SUB(NOW(), INTERVAL 1 HOUR)
      `);

      if (recentTrials[0].count >= 3) {  // 如果1小时内已达到3次试用
        logger.warn('[Refresh] 试用次数已达上限:', {
          recent_count: recentTrials[0].count,
          time_window: '1小时',
          limit: 3,
          device_id,
          clientIP
        });

        return res.json({
          code: 7,
          msg: '每小时仅允许试用3次，请稍后再试'
        });
      }

      // 先记录试用信息
      await conn.execute(
        'INSERT INTO trials (device_id, ip, created_at, trial_at) VALUES (COALESCE(?, ""), ?, NOW(), NOW())',
        [
          device_id || null,  // 处理可能的 undefined
          clientIP || null    // 处理可能的 undefined
        ]
      );
      logger.info('[Refresh] 记录试用信息:', {
        device_id,
        clientIP,
        trial_count: recentTrials[0].count + 1,
        trials_remaining: 2 - recentTrials[0].count
      });
    }

    // 3. 分配新账号 - 修改这部分逻辑
    let account; // 将 account 变量声明提前
    let isReuse = false;
    let reuseSwithch = false; //暂时关闭重用开关

    // 首先查找可重用的账号
    const [reuseAccounts] = await conn.execute(`
      SELECT ca.* 
      FROM refresh_history rh
      JOIN cursor_accounts ca ON rh.account_id = ca.id
      WHERE rh.device_id = ?
        AND rh.requests < 50
        AND rh.check_time > rh.refresh_time
      ORDER BY rh.refresh_time DESC
      LIMIT 1
    `, [effectiveUsedBy || null]);  // 处理可能的 undefined

    if (reuseAccounts.length > 0 && reuseSwithch) {
      // 找到可重用的账号
      account = reuseAccounts[0]; // 使用前面声明的 account 变量
      isReuse = true;
      logger.info('[Refresh] 找到可重用账号:', {
        device_id: effectiveUsedBy,
        account_id: account.id,
        email: account.email,
        access_token: account.access_token ? '存在' : '不存在',
        refresh_token: account.refresh_token ? '存在' : '不存在'
      });
    } else {
      // 没有可重用的账号，分配新账号
      const [newAccounts] = await conn.execute(
          "SELECT * FROM cursor_accounts WHERE used = 0 AND (is_locked != 1 OR is_locked IS NULL) AND need_verify = 0 AND email LIKE '%.com' ORDER BY created_at DESC LIMIT 1"
      );

      if (newAccounts.length === 0) {
        return res.json({ code: 2, msg: '暂无可用账号，请稍后再试' });
      }

      account = newAccounts[0]; // 使用前面声明的 account 变量
      isReuse = false;
    }

    // 4. 标记账号为已使用
    await conn.execute('SET time_zone = "+08:00"');

    if (!isReuse) {
      // 如果是新账号，需要更新used状态
      await conn.execute(`
        UPDATE cursor_accounts 
        SET used = 1, 
            used_by = ?, 
            used_at = NOW() 
        WHERE id = ?
      `, [effectiveUsedBy, account.id]);
    }

    // 如果是会员,更新 members 表中的 current_account_id
    if (validMembers.length > 0) {
      await conn.execute(`
        UPDATE members 
        SET current_account_id = ? 
        WHERE id = ?
      `, [account.id, validMembers[0].id]);

      logger.info('[Refresh] 更新会员当前账号:', {
        member_id: validMembers[0].id,
        account_id: account.id
      });
    }

    // 记录刷新历史
    if (isReuse) {
      // 如果是重用账号，更新现有记录的refresh_time和is_reuse
      logger.info(`[seven] refresh_account refresh_time22`);
      await conn.execute(`
        UPDATE refresh_history 
        SET refresh_time = NOW(),
            ip = ?,
            is_reuse = 1,
            info = ?
        WHERE device_id = ? 
        AND account_id = ?
        ORDER BY refresh_time DESC 
        LIMIT 1
      `, [
        clientIP || null,  // 处理可能的 undefined
        info || null,      // 处理可能的 undefined
        effectiveUsedBy || null,  // 处理可能的 undefined
        account.id
      ]);
    } else {
      // 如果是新账号，插入新记录
      const insertSql = `
        INSERT INTO refresh_history (
          device_id,
          account_id,
          refresh_time,
          is_reuse,
          ip,
          info
        ) VALUES (?, ?, NOW(), ?, ?, ?)
      `;

      const insertParams = [
        effectiveUsedBy || null,  // 处理可能的 undefined
        account.id,
        0,  // is_reuse = false
        clientIP || null,  // 处理可能的 undefined
        info || null       // 处理可能的 undefined
      ];

      await conn.execute(insertSql, insertParams);
    }

    logger.info('[Refresh] 记录刷新历史:', {
      device_id: effectiveUsedBy,
      account_id: account.id,
      is_reuse: isReuse,
      ip: clientIP
    });

    return res.json({
      code: 0,
      data: {
        email: account.email,
        access_token: account.access_token,
        refresh_token: account.refresh_token,
        is_trial: validMembers.length === 0,
        is_reuse: isReuse  // 添加是否重用的标记
      }
    });

  } catch (err) {
    logger.error('[Refresh] 处理出错:', {
      error: err.message,
      stack: err.stack
      // ,
      // request: {
      //   device_id,
      //   bios_uuid
      // }
    });
    return res.json({ code: -1, msg: '服务器错误' });
  } finally {
    if (conn) await conn.end();
  }
});

// 在刷新账号时检查并释放过期的锁定账号
app.post('/api/release_expired_accounts', async (req, res) => {
  let conn;
  try {
    conn = await mysql.createConnection(dbConfig);

    // 查找过期的锁定账号关系
    const [expiredAccounts] = await conn.execute(`
      SELECT 
        qma.account_id,
        qma.member_id
      FROM quota_member_accounts qma
      WHERE qma.expire_at <= NOW()
    `);

    if (expiredAccounts.length > 0) {
      // 释放过期的锁定账号
      for (const acc of expiredAccounts) {
        await conn.execute(`
          UPDATE cursor_accounts 
          SET is_locked = 0
          WHERE id = ?
        `, [acc.account_id]);

        // 删除过期的锁定关系
        await conn.execute(`
          DELETE FROM quota_member_accounts 
          WHERE account_id = ?
        `, [acc.account_id]);

        // 更新会员的锁定账号数量
        await conn.execute(`
          UPDATE quota_members 
          SET locked_accounts_count = locked_accounts_count - 1
          WHERE id = ?
        `, [acc.member_id]);
      }

      logger.info('[Release Accounts] 释放过期锁定账号:', {
        count: expiredAccounts.length,
        account_ids: expiredAccounts.map(a => a.account_id)
      });
    }

    return res.json({
      code: 0,
      msg: '处理完成',
      data: {
        released_count: expiredAccounts.length
      }
    });

  } catch (err) {
    logger.error('[Release Accounts] 处理出错:', err);
    return res.json({ code: -1, msg: '服务器错误' });
  } finally {
    if (conn) await conn.end();
  }
});

// 添加获取待验证账号的 API
app.get('/api/verify_accounts', async (req, res) => {
  try {
    const conn = await mysql.createConnection(dbConfig);
    const [accounts] = await conn.execute(`
      SELECT id, email 
      FROM cursor_accounts 
      WHERE need_verify = 1
    `);
    await conn.end();

    return res.json({
      code: 0,
      data: accounts
    });
  } catch (err) {
    logger.error('获取待验证账号失败:', err);
    return res.json({ code: -1, msg: '服务器错误' });
  }
});

// 修改验证账号的函数
async function verifyAccount(access_token) {
  const API_URL = 'https://34.102.163.161/v1/completions';  // 使用 IP 地址
  const requestBody = {
    prompt: 'Hello',
    max_tokens: 1,
    model: 'claude-3-sonnet-20240229',
    temperature: 0
  };

  try {
    logger.info('发送验证请求:', {
      url: API_URL,
      headers: {
        'Authorization': `Bearer ${access_token.slice(0, 10)}...`,
        'Content-Type': 'application/json',
        'Host': 'api.cursor.sh'  // 添加 Host 头
      },
      body: requestBody
    });

    const agent = new https.Agent({
      rejectUnauthorized: false
    });

    const response = await fetch(API_URL, {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${access_token}`,
        'Content-Type': 'application/json',
        'Host': 'api.cursor.sh'  // 添加 Host 头
      },
      body: JSON.stringify(requestBody),
      agent: agent
    });

    const responseText = await response.text();
    logger.info('原始响应:', {
      status: response.status,
      statusText: response.statusText,
      text: responseText
    });

    let data;
    try {
      data = JSON.parse(responseText);
    } catch (err) {
      data = {
        error: 'Invalid JSON response: ' + responseText.slice(0, 100)
      };
    }

    // 修改验证逻辑
    const isValid = response.status === 200 && !data.error;

    return {
      isValid,
      request: {
        url: API_URL,
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${access_token.slice(0, 10)}...`,
          'Content-Type': 'application/json'
        },
        body: requestBody
      },
      response: {
        status: response.status,
        statusText: response.statusText,
        data: data,
        rawText: responseText.slice(0, 1000),
        headers: Object.fromEntries(response.headers)
      }
    };

  } catch (err) {
    logger.error('验证账号失败:', err);
    return {
      isValid: false,
      error: err.message,
      request: {
        url: API_URL,
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${access_token.slice(0, 10)}...`,
          'Content-Type': 'application/json'
        },
        body: requestBody
      },
      response: {
        error: err.message,
        stack: err.stack
      }
    };
  }
}

// 修改验证账号的 API
app.post('/api/verify_account', async (req, res) => {
  const conn = await mysql.createConnection(dbConfig);

  try {
    const { account_id } = req.body;

    logger.info('收到验证请求:', {
      account_id: account_id
    });

    if (!account_id) {
      return res.json({ code: 1, msg: '参数错误' });
    }

    // 获取账号信息
    const [accounts] = await conn.execute(
      'SELECT id, email, access_token FROM cursor_accounts WHERE id = ?',
      [account_id]
    );

    logger.info('查询账号结果:', {
      account_id: account_id,
      found: accounts.length > 0
    });

    if (accounts.length === 0) {
      return res.json({ code: 2, msg: '账号不存在' });
    }

    // 验证账号
    try {
      const verifyResult = await verifyAccount(accounts[0].access_token);

      logger.info('验证结果:', {
        account_id: account_id,
        email: accounts[0].email,
        isValid: verifyResult.isValid,
        response: verifyResult.response
      });

      if (verifyResult.isValid) {
        // 如果账号可用，重置使用状态
        await conn.execute(`
          UPDATE cursor_accounts 
          SET used = 0, 
              used_by = NULL, 
              used_at = NULL, 
              end_at = NULL, 
              need_verify = 0 
          WHERE id = ?
        `, [account_id]);

        logger.info('账号已重置:', {
          account_id: account_id,
          email: accounts[0].email
        });

        return res.json({
          code: 0,
          msg: '验证通过，账号已重置',
          data: {
            account_id,
            email: accounts[0].email,
            status: 'valid',
            details: verifyResult
          }
        });
      } else {
        // 如果账号不可用，只是清除验证标记
        await conn.execute(`
          UPDATE cursor_accounts 
          SET need_verify = 0 
          WHERE id = ?
        `, [account_id]);

        logger.info('账号验证未通过:', {
          account_id: account_id,
          email: accounts[0].email
        });

        return res.json({
          code: 0,
          msg: '验证未通过',
          data: {
            account_id,
            email: accounts[0].email,
            status: 'invalid',
            details: verifyResult
          }
        });
      }
    } catch (verifyErr) {
      logger.error('验证过程出错:', {
        account_id: account_id,
        email: accounts[0].email,
        error: verifyErr
      });
      throw verifyErr;
    }

  } catch (err) {
    logger.error('验证账号失败:', {
      error: err,
      stack: err.stack
    });
    return res.json({ code: -1, msg: '服务器错误: ' + err.message });
  } finally {
    await conn.end();
  }
});

// 添加服务启动时间变量
const startTime = new Date();

// 修改时区转换函数
function toBeijingTime(date) {
  // 创建一个新的日期对象，加上8小时得到北京时间
  const beijingDate = new Date(date.getTime() + 8 * 60 * 60 * 1000);
  return beijingDate.toISOString().replace('T', ' ').slice(0, 19);
}

// 添加 UTC 转换函数
function toUTCTime(beijingTimeStr) {
  // 将北京时间字符串转换为 UTC 时间
  const beijingTime = new Date(beijingTimeStr);
  return new Date(beijingTime.getTime() - 8 * 60 * 60 * 1000);
}

// 添加密码验证中间件
function requireAuth(req, res, next) {
  const session = req.session;
  if (session && session.isAuthenticated) {
    next();
  } else {
    res.redirect('/login');
  }
}

// 添加内网访问检查中间件
async function requireLocalAccess(req, res, next) {
  const clientIP = req.ip;  // 直接使用 req.ip 即可
  const userAgent = req.headers['user-agent'] || '';
  logger.info('访问IP:', { ip: clientIP });

  // 处理 IPv6 格式的 IP
  const ipv4 = clientIP.replace(/^::ffff:/, '');

  // 检查是否是特权User-Agent
  async function isPrivilegedUserAgent(userAgent) {
    let conn;
    try {
      conn = await mysql.createConnection(dbConfig);
      const [rows] = await conn.execute(
        'SELECT * FROM privileged_user_agents WHERE user_agent = ?',
        [userAgent]
      );
      return rows.length > 0;
    } catch (err) {
      logger.error('检查特权User-Agent失败:', err);
      return false;
    } finally {
      if (conn) await conn.end();
    }
  }

  // 严格的内网 IP 检查
  const isInternal = ipv4 === '127.0.0.1' ||
    ipv4 === 'localhost' ||
    ipv4 === '::1' ||
    ipv4.startsWith('192.168.') ||
    ipv4.startsWith('10.') ||
    (ipv4.startsWith('172.') &&
      parseInt(ipv4.split('.')[1]) >= 16 &&
      parseInt(ipv4.split('.')[1]) <= 31);

  // 检查是否是特权User-Agent
  const isPrivileged = await isPrivilegedUserAgent(userAgent);

  if (isInternal || isPrivileged) {
    logger.info('访问允许:', {
      ip: clientIP,
      ipv4,
      isInternal,
      isPrivileged,
      userAgent
    });
    next();
  } else {
    logger.warn('非法访问尝试:', {
      ip: clientIP,
      ipv4,
      userAgent
    });
    res.status(403).send(`
      <html>
        <head>
          <style>
            body {
              font-family: Arial, sans-serif;
              text-align: center;
              padding-top: 50px;
            }
            .dolphin {
              font-size: 50px;
              margin: 20px 0;
            }
            .message {
              color: #666;
              margin: 20px 0;
            }
            .ip {
              color: #999;
              font-size: 14px;
            }
          </style>
        </head>
        <body>
          <div class="dolphin">🐬</div>
          <h1>您的IP已被海豚记录</h1>
          <p class="message">请微笑 😊</p>
          <p class="ip">IP: ${ipv4}</p>
        </body>
      </html>
    `);
  }
}

// 修改登录页面路由
app.get('/login', (req, res) => {
  const clientIP = req.headers['x-real-ip'] ||
    req.headers['x-forwarded-for'] ||
    req.ip ||
    req.connection.remoteAddress;

  // 检查是否被锁定
  if (isLocked(clientIP)) {
    const attempt = loginAttempts.get(clientIP);
    const remainingTime = Math.ceil((attempt.lockedUntil - Date.now()) / 1000 / 60);
    res.send(`
      <html>
        <body>
          <h2>账号已锁定</h2>
          <p>由于多次输入错误密码，账号已被临时锁定</p>
          <p>请在 ${remainingTime} 分钟后重试</p>
        </body>
      </html>
    `);
    return;
  }

  res.send(`
    <html>
      <body>
        <h2>Cursor Pro 管理后台</h2>
        <form method="post" action="/login">
          <input type="password" name="password" placeholder="请输入管理密码" required>
          <button type="submit">登录</button>
        </form>
        ${loginAttempts.get(clientIP)?.count ?
      `<p style="color:red">密码错误，还剩 ${MAX_ATTEMPTS - loginAttempts.get(clientIP).count} 次机会</p>`
      : ''}
      </body>
    </html>
  `);
});

// 修改登录处理路由
app.post('/login', (req, res) => {
  const clientIP = req.headers['x-real-ip'] ||
    req.headers['x-forwarded-for'] ||
    req.ip ||
    req.connection.remoteAddress;

  // 检查是否被锁定
  if (isLocked(clientIP)) {
    const attempt = loginAttempts.get(clientIP);
    const remainingTime = Math.ceil((attempt.lockedUntil - Date.now()) / 1000 / 60);
    res.send(`
      <html>
        <body>
          <h2>账号已锁定</h2>
          <p>由于多次输入错误密码，账号已被临时锁定</p>
          <p>请在 ${remainingTime} 分钟后重试</p>
        </body>
      </html>
    `);
    return;
  }

  const { password } = req.body;
  if (password === 'cursor-98999899') {
    // 登录成功，清除失败记录
    loginAttempts.delete(clientIP);
    req.session.isAuthenticated = true;
    res.redirect('/key');  // 修改这里，重定向到 /s
  } else {
    // 记录失败尝试
    const attempt = recordFailedAttempt(clientIP);

    // 如果已被锁定，显示锁定信息
    if (attempt.lockedUntil) {
      const remainingTime = Math.ceil((attempt.lockedUntil - Date.now()) / 1000 / 60);
      res.send(`
        <html>
          <body>
            <h2>账号已锁定</h2>
            <p>由于多次输入错误密码，账号已被临时锁定</p>
            <p>请在 ${remainingTime} 分钟后重试</p>
          </body>
        </html>
      `);
      return;
    }

    res.send(`
      <html>
        <body>
          <h2>密码错误</h2>
          <p>请输入正确的管理密码</p>
          <p style="color:red">还剩 ${MAX_ATTEMPTS - attempt.count} 次机会</p>
          <a href="/login">返回重试</a>
        </body>
      </html>
    `);
  }
});

// 获取超限IP列表的接口
app.get('/api/limited_ips', requireAuth, async (req, res) => {
  let conn;
  try {
    conn = await mysql.createConnection(dbConfig);

    // 查询最近1小时内访问超过20次的IP
    const [limitedIps] = await conn.execute(`
      SELECT 
        ip,
        COUNT(*) as request_count,
        MIN(created_at) as first_request,
        MAX(created_at) as last_request
      FROM access_logs 
      WHERE created_at > DATE_SUB(NOW(), INTERVAL 1 HOUR)
      GROUP BY ip 
      HAVING COUNT(*) >= 20
      ORDER BY request_count DESC, last_request DESC
    `);

    return res.json({
      code: 0,
      data: limitedIps
    });
  } catch (err) {
    logger.error('获取超限IP列表失败:', err);
    return res.json({ code: -1, msg: '服务器错误' });
  } finally {
    if (conn) {
      await conn.end();
    }
  }
});

// 数据库初始化函数
async function initDatabase() {
  let conn;
  try {
    conn = await mysql.createConnection(dbConfig);

    // 创建 cursor_accounts 表
    await conn.execute(`
      CREATE TABLE IF NOT EXISTS cursor_accounts (
        id INT AUTO_INCREMENT PRIMARY KEY,
        email VARCHAR(255) NOT NULL,
        password VARCHAR(255) NOT NULL,
        access_token TEXT NOT NULL,
        refresh_token TEXT NOT NULL,
        used TINYINT(1) DEFAULT 0,
        used_by CHAR(100) DEFAULT NULL,
        used_at DATETIME DEFAULT NULL,
        end_at DATETIME DEFAULT NULL,
        need_verify TINYINT(1) DEFAULT 0,
        source_from VARCHAR(255) DEFAULT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        UNIQUE KEY unique_email (email)
      )
    `);

    // 检查并添加 source_from 字段(如果不存在)
    try {
      const [columns] = await conn.execute(`
        SELECT COLUMN_NAME 
        FROM INFORMATION_SCHEMA.COLUMNS 
        WHERE TABLE_NAME = 'cursor_accounts' 
        AND COLUMN_NAME = 'source_from'
        AND TABLE_SCHEMA = (SELECT DATABASE())
      `);

      if (columns.length === 0) {
        await conn.execute(`
          ALTER TABLE cursor_accounts 
          ADD COLUMN source_from VARCHAR(255) DEFAULT NULL
        `);
        logger.info('cursor_accounts 表 source_from 字段添加成功');
      }
    } catch (err) {
      logger.error('添加 source_from 字段失败:', err);
    }

    // 创建 activation_codes 表
    await conn.execute(`
      CREATE TABLE IF NOT EXISTS activation_codes (
        id INT AUTO_INCREMENT PRIMARY KEY,
        code VARCHAR(32) NOT NULL,
        days INT NOT NULL,
        used TINYINT(1) DEFAULT 0,
        used_by CHAR(100) DEFAULT NULL,
        used_at DATETIME DEFAULT NULL,
        ip VARCHAR(50) DEFAULT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        UNIQUE KEY unique_code (code),
        INDEX idx_ip (ip)
      )
    `);

    // 创建 members 表
    await conn.execute(`
      CREATE TABLE IF NOT EXISTS members (
        id INT AUTO_INCREMENT PRIMARY KEY,
        device_id CHAR(32) DEFAULT NULL,
        activated_at DATETIME NOT NULL,
        expire_at DATETIME NOT NULL,
        current_account_id INT DEFAULT NULL,
        last_refresh_time DATETIME DEFAULT NULL,
        refresh_count INT DEFAULT 0,
        activate_ip VARCHAR(50) DEFAULT NULL,
        BIOS_UUID VARCHAR(64) DEFAULT NULL COMMENT '设备BIOS UUID',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        UNIQUE KEY unique_device (device_id),
        UNIQUE KEY unique_bios (BIOS_UUID)
      )
    `);

    // 修改添加新字段的代码
    try {
      // 先检查字段是否存在
      const [columns] = await conn.execute(`
        SELECT COLUMN_NAME 
        FROM INFORMATION_SCHEMA.COLUMNS 
        WHERE TABLE_NAME = 'members' 
        AND TABLE_SCHEMA = (SELECT DATABASE())
      `);

      const existingColumns = columns.map(col => col.COLUMN_NAME.toLowerCase());

      // 逐个添加不存在的字段
      const columnsToAdd = [];
      if (!existingColumns.includes('last_refresh_time')) {
        columnsToAdd.push('ADD COLUMN last_refresh_time DATETIME DEFAULT NULL');
      }
      if (!existingColumns.includes('refresh_count')) {
        columnsToAdd.push('ADD COLUMN refresh_count INT DEFAULT 0');
      }
      if (!existingColumns.includes('activate_ip')) {
        columnsToAdd.push('ADD COLUMN activate_ip VARCHAR(50) DEFAULT NULL');
      }
      if (!existingColumns.includes('bios_uuid')) {
        columnsToAdd.push('ADD COLUMN BIOS_UUID VARCHAR(64) DEFAULT NULL COMMENT "设备BIOS UUID"');
      }

      // 检查索引是否存在
      const [indexes] = await conn.execute(`
        SHOW INDEX FROM members
      `);

      const existingIndexes = indexes.map(idx => idx.Key_name.toLowerCase());

      // 添加不存在的索引
      if (!existingIndexes.includes('idx_activate_ip')) {
        columnsToAdd.push('ADD INDEX idx_activate_ip (activate_ip)');
      }
      if (!existingIndexes.includes('idx_bios_uuid')) {
        columnsToAdd.push('ADD INDEX idx_bios_uuid (BIOS_UUID)');
      }

      // 如果有需要添加的字段或索引，执行 ALTER TABLE
      if (columnsToAdd.length > 0) {
        const alterSql = `ALTER TABLE members ${columnsToAdd.join(', ')}`;
        await conn.execute(alterSql);
        logger.info('members 表字段和索引更新成功:', {
          added_items: columnsToAdd
        });
      } else {
        logger.info('members 表所有字段和索引已存在');
      }
    } catch (err) {
      logger.error('更新 members 表结构失败:', {
        error: err.message,
        code: err.code,
        sql_state: err.sqlState,
        sql_message: err.sqlMessage,
        stack: err.stack
      });
    }

    // 创建试用限制表
    await conn.execute(`
      CREATE TABLE IF NOT EXISTS trial_limits (
        id INT AUTO_INCREMENT PRIMARY KEY,
        created_at DATETIME NOT NULL,
        expire_at DATETIME NOT NULL,
        INDEX idx_expire (expire_at)
      ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
    `);
    logger.info('trial_limits 表创建成功');

    // 创建试用记录表
    await conn.execute(`
      CREATE TABLE IF NOT EXISTS trials (
        id INT AUTO_INCREMENT PRIMARY KEY,
        ip VARCHAR(50) NOT NULL,
        device_id CHAR(32) NOT NULL,
        trial_at DATETIME NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        INDEX idx_ip (ip),
        INDEX idx_device (device_id)
      ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
    `);
    logger.info('trials 表创建成功');

    // 创建 IP 屏蔽表
    await conn.execute(`
      CREATE TABLE IF NOT EXISTS blocked_ips (
        id INT AUTO_INCREMENT PRIMARY KEY,
        ip VARCHAR(50) NOT NULL,
        reason VARCHAR(255) NOT NULL,
        blocked_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        UNIQUE KEY unique_ip (ip)
      ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
    `);

    // 创建 User-Agent 限制表
    await conn.execute(`
      CREATE TABLE IF NOT EXISTS blocked_user_agents (
        id INT AUTO_INCREMENT PRIMARY KEY,
        user_agent VARCHAR(500) NOT NULL,
        request_count INT NOT NULL,
        first_request DATETIME NOT NULL,
        last_request DATETIME NOT NULL,
        blocked_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        unblock_at DATETIME NOT NULL,  -- 添加解封时间字段
        UNIQUE KEY unique_ua (user_agent(255))
      ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
    `);

    // 添加 unblock_at 字段（如果不存在）
    try {
      const [columns] = await conn.execute(`
        SELECT COLUMN_NAME 
        FROM INFORMATION_SCHEMA.COLUMNS 
        WHERE TABLE_NAME = 'blocked_user_agents' 
        AND COLUMN_NAME = 'unblock_at'
        AND TABLE_SCHEMA = (SELECT DATABASE())
      `);

      if (columns.length === 0) {
        await conn.execute(`
          ALTER TABLE blocked_user_agents 
          ADD COLUMN unblock_at DATETIME NOT NULL
        `);
        logger.info('blocked_user_agents 表 unblock_at 字段添加成功');
      }
    } catch (err) {
      logger.error('添加 unblock_at 字段失败:', err);
    }

    // 创建系统配置表
    await conn.execute(`
      CREATE TABLE IF NOT EXISTS system_config (
        id INT AUTO_INCREMENT PRIMARY KEY,
        config_key VARCHAR(50) NOT NULL,
        config_value TEXT NOT NULL,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
        UNIQUE KEY unique_key (config_key)
      ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
    `);

    // 初始化试用功能开关配置（如果不存在）
    await conn.execute(`
      INSERT INTO system_config (config_key, config_value)
      VALUES ('enable_trial', 'true')
      ON DUPLICATE KEY UPDATE config_value = config_value
    `);

    logger.info('system_config 表创建并初始化成功');

    // 创建特权User-Agent表
    await conn.execute(`
      CREATE TABLE IF NOT EXISTS privileged_user_agents (
        id INT AUTO_INCREMENT PRIMARY KEY,
        user_agent VARCHAR(500) NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        UNIQUE KEY unique_user_agent (user_agent(255))
      ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
    `);
    logger.info('privileged_user_agents 表创建成功');

    // 初始化默认特权User-Agent
    await conn.execute(`
      INSERT IGNORE INTO privileged_user_agents (user_agent) 
      VALUES (
        'Mozilla/5.0 (Linux; U; Android 11; zh-CN; DT2002C Build/RKQ1.201217.002) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/100.0.4896.58 Quark/6.9.1.491 Mobile Safari/537.36'
      )
    `);
    logger.info('默认特权User-Agent已添加');

    // 创建激活码发送记录表
    await conn.execute(`
      CREATE TABLE IF NOT EXISTS activation_code_sends (
        id BIGINT NOT NULL AUTO_INCREMENT,
        code VARCHAR(32) NOT NULL,
        email VARCHAR(255) NOT NULL,
        days INT NOT NULL,
        send_time DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
        status TINYINT NOT NULL DEFAULT 1 COMMENT '1:发送成功 0:发送失败',
        error_msg TEXT,
        PRIMARY KEY (id),
        KEY idx_email (email),
        KEY idx_code (code),
        KEY idx_send_time (send_time)
      ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
    `);

    logger.info('数据库初始化完成');

    // 检查 version_updates 表是否存在
    const [tables] = await conn.execute(`
      SELECT TABLE_NAME 
      FROM information_schema.TABLES 
      WHERE TABLE_SCHEMA = ? AND TABLE_NAME = 'version_updates'
    `, [process.env.DB_NAME]);

    // 如果表不存在才创建
    if (tables.length === 0) {
      // 创建新的 version_updates 表
      await conn.execute(`
        CREATE TABLE version_updates (
          id INT AUTO_INCREMENT PRIMARY KEY,
          version VARCHAR(20) NOT NULL,
          platform ENUM('windows', 'mac_intel', 'mac_arm64', 'linux') NOT NULL,
          force_update BOOLEAN DEFAULT false,
          download_url TEXT NOT NULL,
          release_notes TEXT,
          created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
          UNIQUE KEY unique_version_platform (version, platform)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
      `);

      logger.info('version_updates 表创建成功');
    } else {
      // 修改 version_updates 表结构
      try {
        await conn.execute(`
          ALTER TABLE version_updates 
          MODIFY COLUMN platform ENUM('windows', 'mac_intel', 'mac_arm64', 'linux') NOT NULL
        `);

        const [columns] = await conn.execute(`
          SELECT COLUMN_NAME 
          FROM INFORMATION_SCHEMA.COLUMNS 
          WHERE TABLE_NAME = 'version_updates'
          AND TABLE_SCHEMA = (SELECT DATABASE())
        `);

        const existingColumns = columns.map(col => col.COLUMN_NAME.toLowerCase());

        if (!existingColumns.includes('force_update')) {
          await conn.execute(`
            ALTER TABLE version_updates 
            ADD COLUMN force_update BOOLEAN DEFAULT false
          `);
        }

        if (!existingColumns.includes('release_notes')) {
          await conn.execute(`
            ALTER TABLE version_updates 
            ADD COLUMN release_notes TEXT
          `);
        }

        // 检查并添加唯一索引
        const [indexes] = await conn.execute(`SHOW INDEX FROM version_updates`);
        const hasUniqueIndex = indexes.some(idx =>
          idx.Key_name === 'unique_version_platform'
        );

        if (!hasUniqueIndex) {
          await conn.execute(`
            ALTER TABLE version_updates 
            ADD UNIQUE KEY unique_version_platform (version, platform)
          `);
        }

        logger.info('version_updates 表结构更新成功');
      } catch (err) {
        logger.error('更新 version_updates 表结构失败:', err);
      }
    }

    logger.info('数据库初始化完成');

    // 检查 ip_whitelist 表是否存在
    const [whitelistTables] = await conn.execute(`
      SELECT TABLE_NAME 
      FROM information_schema.TABLES 
      WHERE TABLE_SCHEMA = ? AND TABLE_NAME = 'ip_whitelist'
    `, [process.env.DB_NAME]);

    // 如果表不存在则创建
    if (whitelistTables.length === 0) {
      await conn.execute(`
        CREATE TABLE ip_whitelist (
          id INT AUTO_INCREMENT PRIMARY KEY,
          ip VARCHAR(50) NOT NULL,
          description VARCHAR(255),
          created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
          UNIQUE KEY unique_ip (ip)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
      `);

      logger.info('ip_whitelist 表创建成功');
    } else {
      logger.info('ip_whitelist 表已存在');
    }

    // 在 initDatabase 函数中添加
    await conn.execute(`
      CREATE TABLE IF NOT EXISTS system_settings (
        \`key\` VARCHAR(50) PRIMARY KEY,
        \`value\` TEXT,
        \`updated_at\` TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
      ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
    `);

    // 检查 monitor_logs 表是否存在
    const [monitorTables] = await conn.execute(`
      SELECT TABLE_NAME 
      FROM information_schema.TABLES 
      WHERE TABLE_SCHEMA = ? AND TABLE_NAME = 'monitor_logs'
    `, [process.env.DB_NAME]);

    // 如果表不存在则创建
    if (monitorTables.length === 0) {
      await conn.execute(`
        CREATE TABLE monitor_logs (
          id BIGINT NOT NULL AUTO_INCREMENT,
          check_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
          has_inactive_sources BOOLEAN NOT NULL,
          inactive_sources TEXT,
          total_accounts INT NOT NULL,
          consumed_24h INT NOT NULL,
          alert_sent BOOLEAN NOT NULL,
          error_msg TEXT,
          source_stats JSON,
          PRIMARY KEY (id),
          INDEX idx_check_time (check_time)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
      `);
      logger.info('monitor_logs 表创建成功');
    } else {
      logger.info('monitor_logs 表已存在');
    }

    // 检查 cursor_domains 表是否存在
    const [domainTables] = await conn.execute(`
      SELECT TABLE_NAME 
      FROM information_schema.TABLES 
      WHERE TABLE_SCHEMA = ? AND TABLE_NAME = 'cursor_domains'
    `, [process.env.DB_NAME]);

    // 如果表不存在则创建
    if (domainTables.length === 0) {
      await conn.execute(`
        CREATE TABLE cursor_domains (
          id INT AUTO_INCREMENT PRIMARY KEY,
          domain VARCHAR(255) NOT NULL,
          status TINYINT(1) DEFAULT 1 COMMENT '1:启用 0:禁用',
          description TEXT,
          created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
          updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
          UNIQUE KEY unique_domain (domain)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
      `);
      logger.info('cursor_domains 表创建成功');
    } else {
      logger.info('cursor_domains 表已存在');
    }

    // 在 initDatabase 函数中添加 cursor_collect_logs 表创建代码
    // 检查 cursor_collect_logs 表是否存在
    const [collectTables] = await conn.execute(`
      SELECT TABLE_NAME 
      FROM information_schema.TABLES 
      WHERE TABLE_SCHEMA = ? AND TABLE_NAME = 'cursor_collect_logs'
    `, [process.env.DB_NAME]);

    // 如果表不存在则创建
    if (collectTables.length === 0) {
      await conn.execute(`
        CREATE TABLE cursor_collect_logs (
          id BIGINT NOT NULL AUTO_INCREMENT,
          email VARCHAR(255) NOT NULL,
          collect_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
          status TINYINT(1) NOT NULL COMMENT '1:成功 0:失败',
          error_msg TEXT,
          source_from VARCHAR(50),
          PRIMARY KEY (id),
          INDEX idx_email (email),
          INDEX idx_collect_time (collect_time),
          INDEX idx_status (status),
          INDEX idx_source (source_from)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
      `);
      logger.info('cursor_collect_logs 表创建成功');
    } else {
      logger.info('cursor_collect_logs 表已存在');
    }

    // 在 initDatabase 函数中添加以下代码
    await conn.execute(`
      CREATE TABLE IF NOT EXISTS activation_links (
        id INT PRIMARY KEY AUTO_INCREMENT,
        token VARCHAR(64) NOT NULL,
        days INT NOT NULL,
        created_at DATETIME NOT NULL,
        used TINYINT(1) DEFAULT 0,
        used_email VARCHAR(255),
        used_at DATETIME,
        UNIQUE KEY (token)
      ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
    `);
    logger.info('activation_links 表创建成功');

    // 检查 activation_links 表是否存在
    const [activationTables] = await conn.execute(`
      SELECT TABLE_NAME 
      FROM information_schema.TABLES 
      WHERE TABLE_SCHEMA = ? AND TABLE_NAME = 'activation_links'
    `, [process.env.DB_NAME]);

    // 如果表不存在则创建
    if (activationTables.length === 0) {
      await conn.execute(`
        CREATE TABLE activation_links (
          id INT PRIMARY KEY AUTO_INCREMENT,
          token VARCHAR(64) NOT NULL,
          days INT NOT NULL,
          created_at DATETIME NOT NULL,
          used TINYINT(1) DEFAULT 0,
          used_email VARCHAR(255),
          used_at DATETIME,
          UNIQUE KEY (token)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
      `);
      logger.info('activation_links 表创建成功');
    }

    // 创建公告表
    await conn.execute(`
      CREATE TABLE IF NOT EXISTS notices (
        id INT PRIMARY KEY AUTO_INCREMENT,
        content TEXT NOT NULL,
        status TINYINT DEFAULT 1 COMMENT '状态 1-启用 0-禁用',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
      ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
    `);
    logger.info('notices 表创建成功');

  } catch (err) {
    logger.error('初始化数据库失败:', {
      error: err.message,
      code: err.code,
      sql_state: err.sqlState,
      sql_message: err.sqlMessage,
      stack: err.stack
    });
    throw err;
  } finally {
    if (conn) await conn.end();
  }
}

// 添加获取系统配置的函数
async function getSystemConfig(key) {
  let conn;
  try {
    conn = await mysql.createConnection(dbConfig);
    const [rows] = await conn.execute(
      'SELECT config_value FROM system_config WHERE config_key = ?',
      [key]
    );
    return rows.length > 0 ? rows[0].config_value : null;
  } catch (err) {
    logger.error('获取系统配置失败:', err);
    return null;
  } finally {
    if (conn) await conn.end();
  }
}

// 修改每日验证任务
cron.schedule('0 3 * * *', async () => {  // 每天凌晨3点执行
  logger.info('开始执行账号验证任务');

  try {
    const conn = await mysql.createConnection(dbConfig);

    // 获取所有待验证的账号
    const [accounts] = await conn.execute(`      SELECT id, email, access_token 
      FROM cursor_accounts 
      WHERE need_verify = 1
    `);

    logger.info(`找到 ${accounts.length} 个待验证账号`);

    // 逐个验证账号
    for (const account of accounts) {
      const verifyResult = await verifyAccount(account.access_token);

      if (verifyResult.isValid) {  // 使用 isValid 属性
        // 如果账号可用，重置使用状态
        await conn.execute(`
          UPDATE cursor_accounts 
          SET used = 0, 
              used_by = NULL, 
              used_at = NULL, 
              end_at = NULL, 
              need_verify = 0 
          WHERE id = ?
        `, [account.id]);

        logger.info('账号验证通过，已重置:', {
          account_id: account.id,
          email: account.email,
          details: verifyResult
        });
      } else {
        // 如果账号不可用，只是清除验证标记
        await conn.execute(`
          UPDATE cursor_accounts 
          SET need_verify = 0 
          WHERE id = ?
        `, [account.id]);

        logger.info('账号验证未通过:', {
          account_id: account.id,
          email: account.email,
          details: verifyResult
        });
      }
    }

    await conn.end();
    logger.info('账号验证任务完成');

  } catch (err) {
    logger.error('账号验证任务出错:', err);
  }
}, {
  timezone: 'Asia/Shanghai'  // 使用北京时间
});

// 添加屏蔽 IP 的接口
app.post('/api/block_ip', requireAuth, async (req, res) => {
  const { ip } = req.body;
  let conn;

  try {
    conn = await mysql.createConnection(dbConfig);
    await conn.execute(
      'INSERT INTO blocked_ips (ip, reason) VALUES (?, ?) ON DUPLICATE KEY UPDATE blocked_at = NOW()',
      [ip, '访问频率超限']
    );

    logger.info('IP已被屏蔽:', { ip });
    return res.json({ code: 0, msg: '屏蔽成功' });
  } catch (err) {
    logger.error('屏蔽IP失败:', err);
    return res.json({ code: -1, msg: '操作失败' });
  } finally {
    if (conn) await conn.end();
  }
});

// 修改解除屏蔽的接口
app.post('/api/unblock_ip', requireAuth, async (req, res) => {
  const { ip } = req.body;
  let conn;

  try {
    conn = await mysql.createConnection(dbConfig);

    // 开始事务
    await conn.beginTransaction();

    try {
      // 1. 从屏蔽表中删除 IP
      await conn.execute('DELETE FROM blocked_ips WHERE ip = ?', [ip]);

      // 2. 清理该 IP 最近一小时的访问记录
      await conn.execute(`
        DELETE FROM access_logs 
        WHERE ip = ? 
        AND created_at > DATE_SUB(NOW(), INTERVAL 1 HOUR)
      `, [ip]);

      // 提交事务
      await conn.commit();

      logger.info('IP已解除屏蔽并清理访问记录:', {
        ip,
        action: 'unblock_and_clean'
      });

      return res.json({
        code: 0,
        msg: '解除成功',
        data: {
          ip,
          cleaned: true
        }
      });

    } catch (err) {
      // 如果出错，回滚事务
      await conn.rollback();
      throw err;
    }

  } catch (err) {
    logger.error('解除屏蔽失败:', {
      error: err.message,
      stack: err.stack,
      ip: ip
    });
    return res.json({
      code: -1,
      msg: '操作失败',
      error: err.message
    });
  } finally {
    if (conn) {
      try {
        await conn.end();
      } catch (err) {
        logger.error('关闭数据库连接失败:', err);
      }
    }
  }
});

// 添加更新系统配置的API
app.post('/api/update_config', requireAuth, async (req, res) => {
  const { key, value } = req.body;
  let conn;

  try {
    conn = await mysql.createConnection(dbConfig);
    await conn.execute(
      'UPDATE system_config SET config_value = ? WHERE config_key = ?',
      [value, key]
    );

    logger.info('系统配置已更新:', { key, value });
    return res.json({ code: 0, msg: '更新成功' });
  } catch (err) {
    logger.error('更新系统配置失败:', err);
    return res.json({ code: -1, msg: '更新失败' });
  } finally {
    if (conn) await conn.end();
  }
});

// 添加获取系统配置的API
app.get('/api/get_config', requireAuth, async (req, res) => {
  const { key } = req.query;

  try {
    const value = await getSystemConfig(key);
    return res.json({
      code: 0,
      data: {
        key,
        value
      }
    });
  } catch (err) {
    logger.error('获取系统配置失败:', err);
    return res.json({ code: -1, msg: '获取失败' });
  }
});

// 获取当前生效的公告
app.get('/api/notice', async (req, res) => {
  let conn;
  try {
    conn = await mysql.createConnection(dbConfig);

    const [notices] = await conn.execute(`
      SELECT content 
      FROM notices 
      WHERE status = 1 
      ORDER BY updated_at DESC 
      LIMIT 1
    `);

    return res.json({
      code: 0,
      data: notices.length > 0 ? notices[0].content : ''
    });
  } catch (err) {
    logger.error('获取公告失败:', err);
    return res.json({ code: -1, msg: '获取公告失败' });
  } finally {
    if (conn) await conn.end();
  }
});

// 更新公告内容 (需要管理员权限)
app.post('/api/notice', requireAuth, async (req, res) => {
  let conn;
  try {
    const { content, status } = req.body;

    if (typeof content !== 'string') {
      return res.json({ code: 1, msg: '公告内容无效' });
    }

    conn = await mysql.createConnection(dbConfig);

    // 先禁用所有公告
    await conn.execute('UPDATE notices SET status = 0');

    // 插入新公告
    await conn.execute(`
      INSERT INTO notices (content, status) 
      VALUES (?, ?)
    `, [content, status ? 1 : 0]);

    logger.info('公告已更新');
    return res.json({ code: 0, msg: '更新成功' });
  } catch (err) {
    logger.error('更新公告失败:', err);
    return res.json({ code: -1, msg: '更新失败' });
  } finally {
    if (conn) await conn.end();
  }
});

// 添加公告管理页面路由
app.get('/notice', requireAuth, async (req, res) => {
  try {
    const template = await loadHtmlTemplate('notice');
    res.send(template);
  } catch (err) {
    logger.error('加载公告管理页面失败:', err);
    res.status(500).send('服务器错误');
  }
});

// 添加发送状态Map
const sendingStatus = new Map();

// 添加发送激活码邮件的API
app.post('/api/send_activation_code', requireAuth, async (req, res) => {
  const { email, days } = req.body;
  let conn;
  let activationCode;

  try {
    // 参数验证
    if (!email || !days) {
      return res.json({ code: 1, msg: '邮箱和天数不能为空' });
    }

    if (!email.match(/^[^\s@]+@[^\s@]+\.[^\s@]+$/)) {
      return res.json({ code: 1, msg: '邮箱格式不正确' });
    }

    // 检查是否正在发送
    if (sendingStatus.get(email)) {
      return res.json({ code: 2, msg: '正在发送中，请稍候...' });
    }

    // 设置发送状态
    sendingStatus.set(email, true);

    // 确保 days 是整数
    const daysInt = parseInt(days, 10);
    if (isNaN(daysInt) || daysInt < 1 || daysInt > 3650) {
      sendingStatus.delete(email);  // 清除发送状态
      return res.json({ code: 1, msg: '天数必须是1-3650之间的整数' });
    }

    // 连接数据库
    try {
      conn = await mysql.createConnection(dbConfig);
    } catch (err) {
      sendingStatus.delete(email);  // 清除发送状态
      logger.error('数据库连接失败:', err);
      return res.json({ code: -1, msg: '数据库连接失败' });
    }

    // 生成16位激活码
    activationCode = crypto.randomBytes(8).toString('hex').toUpperCase();

    // 保存激活码
    try {
      await conn.execute(
        'INSERT INTO activation_codes (code, days) VALUES (?, ?)',
        [activationCode, daysInt]
      );
    } catch (err) {
      sendingStatus.delete(email);  // 清除发送状态
      logger.error('保存激活码失败:', err);
      return res.json({ code: -1, msg: '保存激活码失败' });
    }

    // 发送邮件
    logger.info('开始发送激活码邮件:', { email, days: daysInt, activationCode });

    const mailOptions = {
      from: '"海豚激活系统" <2686264538@qq.com>',
      to: email || '',  // 确保 email 不为 undefined
      subject: '海豚 Cursor 激活码',
      html: await getActivationEmailTemplate(activationCode, daysInt)
    };

    try {
      // 发送邮件
      const info = await transporter.sendMail(mailOptions);

      // 记录发送成功
      await conn.execute(
        'INSERT INTO activation_code_sends (code, email, days, status) VALUES (?, ?, ?, 1)',
        [activationCode, email, daysInt]
      );

      logger.info('邮件发送成功:', {
        email: email,
        messageId: info.messageId,
        response: info.response,
        activationCode
      });

      sendingStatus.delete(email);  // 清除发送状态
      return res.json({
        code: 0,
        msg: '激活码已发送到邮箱',
        data: {
          code: activationCode,
          email,
          days: daysInt
        }
      });
    } catch (err) {
      // 记录发送失败
      await conn.execute(
        'INSERT INTO activation_code_sends (code, email, days, status, error_msg) VALUES (?, ?, ?, 0, ?)',
        [activationCode, email, daysInt, err.message]
      );

      logger.error('邮件发送失败:', {
        error: err.message,
        stack: err.stack,
        email: email
      });
      sendingStatus.delete(email);  // 清除发送状态
      return res.json({ code: -1, msg: '发送失败: ' + err.message });
    }
  } catch (err) {
    logger.error('处理请求失败:', err);
    sendingStatus.delete(email);  // 清除发送状态
    return res.json({ code: -1, msg: '处理请求失败: ' + (err.message || '未知错误') });
  } finally {
    if (conn) {
      try {
        await conn.end();
      } catch (err) {
        logger.error('关闭数据库连接失败:', err);
      }
    }
  }
});

// 在启动服务器前初始化数据库
app.listen(port, async () => {
  try {
    await initDatabase();
    await createAccessLogTable();  // 确保这行代码被执行

    logger.info(`API server running on port ${port}`);
    console.log(`API server running on port ${port}`);
  } catch (err) {
    logger.error('服务器启动失败:', err);
    process.exit(1);
  }
});

// 添加获取发送记录的API
app.get('/api/send_records', requireAuth, async (req, res) => {
  let conn;
  try {
    const page = parseInt(req.query.page) || 1;
    const pageSize = 20;
    const offset = (page - 1) * pageSize;

    conn = await mysql.createConnection(dbConfig);

    // 获取总记录数
    const [countResult] = await conn.execute(
      'SELECT COUNT(*) as total FROM activation_code_sends'
    );
    const total = countResult[0].total;
    const totalPages = Math.ceil(total / pageSize);

    // 获取当前页的记录
    const [records] = await conn.execute(`
      SELECT 
        DATE_FORMAT(send_time, '%Y-%m-%d %H:%i:%s') as send_time,
        email,
        code,
        days,
        status,
        error_msg
      FROM activation_code_sends 
      ORDER BY send_time DESC 
      LIMIT ? OFFSET ?
    `, [pageSize, offset]);

    return res.json({
      code: 0,
      data: {
        records,
        total_pages: totalPages,
        current_page: page,
        total_records: total
      }
    });
  } catch (err) {
    logger.error('获取发送记录失败:', err);
    return res.json({ code: -1, msg: '获取记录失败' });
  } finally {
    if (conn) await conn.end();
  }
});

// 添加删除发送记录的API
app.post('/api/delete_send_record', requireAuth, async (req, res) => {
  const { id } = req.body;
  let conn;

  try {
    conn = await mysql.createConnection(dbConfig);

    // 删除记录
    await conn.execute(
      'DELETE FROM activation_code_sends WHERE id = ?',
      [id]
    );

    logger.info('发送记录已删除:', { id });
    return res.json({ code: 0, msg: '删除成功' });
  } catch (err) {
    logger.error('删除发送记录失败:', err);
    return res.json({ code: -1, msg: '删除失败' });
  } finally {
    if (conn) await conn.end();
  }
});

// 添加重置所有会员刷新次数的API
app.post('/api/reset_all_refresh_count', requireAuth, async (req, res) => {
  let conn;
  try {
    conn = await mysql.createConnection(dbConfig);

    await conn.execute(`
      UPDATE members 
      SET refresh_count = 0, 
          last_refresh_time = NULL 
      WHERE expire_at > NOW()
    `);

    logger.info('[Admin] 已重置所有会员的刷新次数');
    return res.json({
      code: 0,
      msg: '重置成功'
    });
  } catch (err) {
    logger.error('重置刷新次数失败:', err);
    return res.json({
      code: -1,
      msg: '重置失败: ' + err.message
    });
  } finally {
    if (conn) await conn.end();
  }
});

// 1. 检查更新接口
app.get('/api/check_update', async (req, res) => {
  let conn;
  try {
    const { platform } = req.query;

    // 验证平台参数
    if (!['windows', 'mac_intel', 'mac_arm64', 'linux'].includes(platform)) {
      return res.json({
        code: 1,
        msg: '无效的平台参数'
      });
    }

    conn = await mysql.createConnection(dbConfig);

    // 获取指定平台的最新版本信息
    const [versions] = await conn.execute(`
      SELECT version, force_update, release_notes, download_url
      FROM version_updates 
      WHERE platform = ?
      ORDER BY created_at DESC 
      LIMIT 1
    `, [platform]);

    if (versions.length === 0) {
      return res.json({
        code: 1,
        msg: '未找到版本信息'
      });
    }

    return res.json({
      code: 0,
      data: {
        version: versions[0].version,
        force_update: versions[0].force_update === 1,
        release_notes: versions[0].release_notes,
        download_url: versions[0].download_url
      }
    });
  } catch (err) {
    logger.error('检查更新失败:', err);
    return res.json({ code: -1, msg: '服务器错误' });
  } finally {
    if (conn) await conn.end();
  }
});

// 2. 下载更新接口
app.get('/api/download_update', async (req, res) => {
  let conn;
  try {
    const { platform, version } = req.query;

    // 验证平台参数
    if (!['windows', 'mac_intel', 'mac_arm64', 'linux'].includes(platform)) {
      return res.json({
        code: 1,
        msg: '无效的平台参数'
      });
    }

    conn = await mysql.createConnection(dbConfig);

    // 获取指定平台和版本的下载地址
    const [versions] = await conn.execute(`
      SELECT download_url 
      FROM version_updates 
      WHERE platform = ? 
      ${version ? 'AND version = ?' : ''}
      ORDER BY created_at DESC 
      LIMIT 1
    `, version ? [platform, version] : [platform]);

    if (versions.length === 0) {
      return res.json({
        code: 1,
        msg: '未找到更新包'
      });
    }

    // 重定向到下载地址
    return res.redirect(versions[0].download_url);
  } catch (err) {
    logger.error('获取下载地址失败:', err);
    return res.json({ code: -1, msg: '服务器错误' });
  } finally {
    if (conn) await conn.end();
  }
});

// 3. 发布新版本接口
app.post('/api/publish_update', requireAuth, async (req, res) => {
  const { version, platform, force_update, download_url, release_notes } = req.body;
  let conn;

  try {
    // 参数验证
    if (!version || !platform || !download_url) {
      logger.warn('发布版本参数不完整:', {
        version,
        platform,
        download_url,
        missing: {
          version: !version,
          platform: !platform,
          download_url: !download_url
        }
      });
      return res.json({
        code: 1,
        msg: '版本号、平台和下载地址不能为空',
        details: {
          missing: {
            version: !version,
            platform: !platform,
            download_url: !download_url
          }
        }
      });
    }

    // 验证平台参数
    if (!['windows', 'mac_intel', 'mac_arm64', 'linux'].includes(platform)) {
      logger.warn('无效的平台参数:', {
        platform,
        valid_platforms: ['windows', 'mac_intel', 'mac_arm64', 'linux']
      });
      return res.json({
        code: 1,
        msg: '无效的平台参数',
        details: {
          platform,
          valid_platforms: ['windows', 'mac_intel', 'mac_arm64', 'linux']
        }
      });
    }

    conn = await mysql.createConnection(dbConfig);

    // 检查版本是否已存在
    const [existing] = await conn.execute(
      'SELECT id FROM version_updates WHERE version = ? AND platform = ?',
      [version, platform]
    );

    if (existing.length > 0) {
      logger.warn('版本已存在:', {
        version,
        platform,
        existing_id: existing[0].id
      });
      return res.json({
        code: 2,
        msg: `该平台的版本已存在`,
        details: {
          version,
          platform,
          existing_id: existing[0].id
        }
      });
    }

    // 插入新版本信息
    try {
      const [result] = await conn.execute(`
        INSERT INTO version_updates (
          version,
          platform,
          force_update, 
          download_url, 
          release_notes
        ) VALUES (?, ?, ?, ?, ?)
      `, [
        version,
        platform,
        force_update ? 1 : 0,
        download_url,
        release_notes || ''
      ]);

      logger.info('新版本发布成功:', {
        version,
        platform,
        force_update,
        download_url,
        insert_id: result.insertId
      });

      return res.json({
        code: 0,
        msg: '发布成功',
        data: {
          id: result.insertId,
          version,
          platform,
          force_update,
          download_url,
          release_notes
        }
      });
    } catch (insertErr) {
      logger.error('插入版本记录失败:', {
        error: insertErr.message,
        code: insertErr.code,
        sql_state: insertErr.sqlState,
        sql_message: insertErr.sqlMessage,
        version,
        platform
      });
      throw insertErr;
    }

  } catch (err) {
    logger.error('发布新版本失败:', {
      error: err.message,
      code: err.code,
      sql_state: err.sqlState,
      sql_message: err.sqlMessage,
      stack: err.stack,
      request: {
        version,
        platform,
        force_update,
        download_url
      }
    });
    return res.json({
      code: -1,
      msg: '服务器错误',
      details: {
        error: err.message,
        sql_error: err.sqlMessage,
        code: err.code
      }
    });
  } finally {
    if (conn) {
      try {
        await conn.end();
        logger.info('数据库连接已关闭');
      } catch (err) {
        logger.error('关闭数据库连接失败:', err);
      }
    }
  }
});

// 4. 获取版本历史接口
app.get('/api/update_history', requireAuth, async (req, res) => {
  let conn;
  try {
    conn = await mysql.createConnection(dbConfig);

    // 获取所有版本记录
    const [versions] = await conn.execute(`
      SELECT 
        version,
        platform,
        force_update,
        download_url,
        release_notes,
        DATE_FORMAT(created_at, '%Y-%m-%d %H:%i:%s') as created_at
      FROM version_updates 
      ORDER BY platform, created_at DESC
    `);

    return res.json({
      code: 0,
      data: versions.map(v => ({
        ...v,
        force_update: v.force_update === 1
      }))
    });
  } catch (err) {
    // 记录详细错误信息
    logger.error('获取版本历史失败:', {
      error: err.message,
      code: err.code,
      sql_state: err.sqlState,
      sql_message: err.sqlMessage,
      stack: err.stack
    });

    // 返回详细错误信息到前端
    return res.json({
      code: -1,
      msg: '获取版本历史失败',
      details: {
        error: err.message,
        sql_error: err.sqlMessage,
        code: err.code
      }
    });
  } finally {
    if (conn) {
      try {
        await conn.end();
        logger.info('数据库连接已关闭');
      } catch (err) {
        logger.error('关闭数据库连接失败:', err);
      }
    }
  }
});

// 添加删除版本API
app.post('/api/delete_version', requireAuth, async (req, res) => {
  const { version, platform } = req.body;
  let conn;

  try {
    if (!version || !platform) {
      return res.json({ code: 1, msg: '版本号和平台不能为空' });
    }

    conn = await mysql.createConnection(dbConfig);
    await conn.execute(
      'DELETE FROM version_updates WHERE version = ? AND platform = ?',
      [version, platform]
    );

    logger.info('版本已删除:', { version, platform });
    return res.json({ code: 0, msg: '删除成功' });
  } catch (err) {
    logger.error('删除版本失败:', err);
    return res.json({ code: -1, msg: '删除失败' });
  } finally {
    if (conn) await conn.end();
  }
});
// 添加编辑版本API
app.post('/api/edit_version', requireAuth, async (req, res) => {
  const { version, platform, force_update, download_url, release_notes } = req.body;
  let conn;

  try {
    if (!version || !platform || !download_url) {
      return res.json({ code: 1, msg: '版本号、平台和下载地址不能为空' });
    }

    conn = await mysql.createConnection(dbConfig);

    await conn.execute(`
      UPDATE version_updates 
      SET force_update = ?, 
          download_url = ?, 
          release_notes = ? 
      WHERE version = ? AND platform = ?
    `, [force_update ? 1 : 0, download_url, release_notes || '', version, platform]);

    logger.info('版本已更新:', { version, platform });
    return res.json({ code: 0, msg: '更新成功' });
  } catch (err) {
    logger.error('更新版本失败:', err);
    return res.json({ code: -1, msg: '更新失败' });
  } finally {
    if (conn) await conn.end();
  }
});

// 查询剩余刷新次数接口
app.post('/api/check_refresh_limit', async (req, res) => {
  let conn;
  try {
    const { device_id, bios_uuid } = req.body;

    // 验证参数
    if (!device_id && !bios_uuid) {
      return res.json({ code: 1, msg: '设备标识不能为空' });
    }

    conn = await mysql.createConnection(dbConfig);

    // 构建查询条件，只使用非空值
    let whereConditions = [];
    let queryParams = [];

    if (device_id && device_id.trim() !== '') {
      whereConditions.push('device_id = ?');
      queryParams.push(device_id);
    }

    if (bios_uuid && bios_uuid.trim() !== '') {
      whereConditions.push('BIOS_UUID = ?');
      queryParams.push(bios_uuid);
    }

    if (whereConditions.length === 0) {
      return res.json({ code: 1, msg: '设备标识不能为空' });
    }

    // 查询会员信息
    const [members] = await conn.execute(`
      SELECT * FROM members 
      WHERE (${whereConditions.join(' OR ')}) 
      AND expire_at > NOW()
    `, queryParams);

    if (members.length === 0) {
      return res.json({ code: 4, msg: '未找到有效会员' });
    }

    const member = members[0];

    // 计算会员总天数
    const [memberDays] = await conn.execute(`
      SELECT DATEDIFF(expire_at, activated_at) as total_days
      FROM members
      WHERE id = ?
    `, [member.id]);

    // 设置限制
    const dailyLimit = memberDays[0].total_days >= 365 ? 20 : 10;
    const hourlyLimit = memberDays[0].total_days >= 365 ? 5 : 3;

    // 查询今日已用次数
    const [dailyUsed] = await conn.execute(`
      SELECT COUNT(DISTINCT used_by) as count
      FROM cursor_accounts
      WHERE used_by = ?
      AND DATE(used_at) = CURDATE()
    `, [device_id || bios_uuid]);

    // 查询本小时已用次数
    const [timeCheck] = await conn.execute(`
      SELECT 
        CASE 
          WHEN last_refresh_time IS NULL 
            OR HOUR(last_refresh_time) != HOUR(NOW()) 
            OR DATE(last_refresh_time) != DATE(NOW())
          THEN 0 
          ELSE refresh_count 
        END as hour_count
      FROM members 
      WHERE id = ?
    `, [member.id]);

    return res.json({
      code: 0,
      data: {
        is_year_member: memberDays[0].total_days >= 365,
        daily: {
          limit: dailyLimit,
          used: dailyUsed[0].count,
          remaining: dailyLimit - dailyUsed[0].count
        },
        hourly: {
          limit: hourlyLimit,
          used: timeCheck[0].hour_count,
          remaining: hourlyLimit - timeCheck[0].hour_count
        }
      }
    });

  } catch (err) {
    logger.error('[Check Limit] 查询失败:', {
      error: err.message,
      stack: err.stack,
      request: {
        device_id: req.body.device_id,
        bios_uuid: req.body.bios_uuid
      }
    });
    return res.json({ code: -1, msg: '服务器错误' });
  } finally {
    if (conn) await conn.end();
  }
});

// 添加根路由重定向
// app.get('/', (req, res) => {
//   res.redirect('/s');
// });

// 添加检查IP是否在白名单中的函数
async function isWhitelistedIP(ip, conn) {
  const [whitelisted] = await conn.execute(
    'SELECT * FROM ip_whitelist WHERE ip = ?',
    [ip]
  );
  return whitelisted.length > 0;
}

// 添加白名单管理API
app.post('/api/add_whitelist_ip', requireAuth, async (req, res) => {
  const { ip, description } = req.body;
  let conn;

  try {
    if (!ip) {
      return res.json({ code: 1, msg: 'IP地址不能为空' });
    }

    conn = await mysql.createConnection(dbConfig);

    await conn.execute(
      'INSERT INTO ip_whitelist (ip, description) VALUES (?, ?) ON DUPLICATE KEY UPDATE description = ?',
      [ip, description || '', description || '']
    );

    logger.info('IP已添加到白名单:', { ip, description });
    return res.json({ code: 0, msg: '添加成功' });
  } catch (err) {
    logger.error('添加白名单失败:', err);
    return res.json({ code: -1, msg: '操作失败' });
  } finally {
    if (conn) await conn.end();
  }
});

app.post('/api/remove_whitelist_ip', requireAuth, async (req, res) => {
  const { ip } = req.body;
  let conn;

  try {
    conn = await mysql.createConnection(dbConfig);
    await conn.execute('DELETE FROM ip_whitelist WHERE ip = ?', [ip]);

    logger.info('IP已从白名单移除:', { ip });
    return res.json({ code: 0, msg: '移除成功' });
  } catch (err) {
    logger.error('移除白名单失败:', err);
    return res.json({ code: -1, msg: '操作失败' });
  } finally {
    if (conn) await conn.end();
  }
});

app.get('/api/whitelist_ips', requireAuth, async (req, res) => {
  let conn;
  try {
    conn = await mysql.createConnection(dbConfig);

    const [ips] = await conn.execute(`
      SELECT 
        ip,
        description,
        DATE_FORMAT(created_at, '%Y-%m-%d %H:%i:%s') as created_at
      FROM ip_whitelist 
      ORDER BY created_at DESC
    `);

    return res.json({
      code: 0,
      data: ips
    });
  } catch (err) {
    logger.error('获取白名单列表失败:', err);
    return res.json({ code: -1, msg: '获取失败' });
  } finally {
    if (conn) await conn.end();
  }
});

// 获取Cursor可用域名列表
app.get('/api/cursor_domains', async (req, res) => {
  let conn;
  try {
    conn = await mysql.createConnection(dbConfig);

    const [domains] = await conn.execute(`
      SELECT 
        id,
        domain
      FROM cursor_domains
      WHERE status = 1
      ORDER BY created_at DESC
    `);

    return res.json({
      code: 0,
      data: domains
    });
  } catch (err) {
    logger.error('获取Cursor域名列表失败:', err);
    return res.json({ code: -1, msg: '服务器错误' });
  } finally {
    if (conn) {
      await conn.end();
    }
  }
});

// 添加采集记录接口
app.post('/api/collect_log', async (req, res) => {
  let conn;
  try {
    const {
      email,
      status,
      error_msg,
      source_from
    } = req.body;

    // 验证必填参数
    if (!email || typeof status !== 'boolean') {
      return res.json({
        code: 1,
        msg: '邮箱和状态不能为空'
      });
    }

    conn = await mysql.createConnection(dbConfig);

    // 记录采集日志，添加 collect_time 字段
    const [result] = await conn.execute(`
      INSERT INTO cursor_collect_logs (
        email,
        status,
        error_msg,
        source_from,
        collect_time
      ) VALUES (?, ?, ?, ?, NOW())
    `, [
      email,
      status ? 1 : 0,
      error_msg || null,
      source_from || null
    ]);

    logger.info('采集记录已保存:', {
      email,
      status,
      source: source_from,
      log_id: result.insertId,
      collect_time: new Date()
    });

    return res.json({
      code: 0,
      msg: '记录成功',
      data: {
        id: result.insertId
      }
    });

  } catch (err) {
    logger.error('保存采集记录失败:', {
      error: err.message,
      stack: err.stack,
      request: {
        email: req.body.email,
        status: req.body.status,
        source: req.body.source_from
      }
    });
    return res.json({ code: -1, msg: '服务器错误' });
  } finally {
    if (conn) {
      await conn.end();
    }
  }
});

// 添加获取采集记录列表接口
app.get('/api/collect_logs', requireAuth, async (req, res) => {
  let conn;
  try {
    const page = parseInt(req.query.page) || 1;
    const pageSize = 20;
    const offset = (page - 1) * pageSize;

    conn = await mysql.createConnection(dbConfig);

    // 获取总记录数
    const [total] = await conn.execute(
      'SELECT COUNT(*) as count FROM cursor_collect_logs'
    );

    // 获取分页数据
    const [logs] = await conn.execute(`
      SELECT 
        id,
        email,
        DATE_FORMAT(collect_time, '%Y-%m-%d %H:%i:%s') as collect_time,
        status,
        error_msg,
        source_from
      FROM cursor_collect_logs
      ORDER BY collect_time DESC
      LIMIT ? OFFSET ?
    `, [pageSize, offset]);

    return res.json({
      code: 0,
      data: {
        total: total[0].count,
        page,
        pageSize,
        list: logs
      }
    });

  } catch (err) {
    logger.error('获取采集记录失败:', err);
    return res.json({ code: -1, msg: '服务器错误' });
  } finally {
    if (conn) {
      await conn.end();
    }
  }
});

// ---------------------------
// 新增【一键退货】接口：预览退货信息
// 输入电子邮箱，查询激活发送记录、发送时间、以及激活码激活时的设备识别ID，然后在 members 表中查找对应会员记录
app.get('/api/refund_preview', requireAuth, async (req, res) => {
  const { email, code } = req.query;

  if (!email && !code) {
    return res.json({ code: 1, msg: '请提供电子邮箱或激活码' });
  }

  let conn;
  try {
    conn = await mysql.createConnection(dbConfig);

    let record;
    if (email) {
      // 通过邮箱查询激活码发送记录
      const [sendRecords] = await conn.execute(
        'SELECT code, DATE_FORMAT(send_time, "%Y-%m-%d %H:%i:%s") as send_time, email FROM activation_code_sends WHERE email = ? ORDER BY send_time DESC LIMIT 1',
        [email]
      );
      if (sendRecords.length === 0) {
        return res.json({ code: 2, msg: '未找到该邮箱的激活码发送记录' });
      }
      record = sendRecords[0];
    } else {
      // 直接查询激活码
      const [codeInfo] = await conn.execute(
        'SELECT ac.code, acs.email, DATE_FORMAT(acs.send_time, "%Y-%m-%d %H:%i:%s") as send_time FROM activation_codes ac LEFT JOIN activation_code_sends acs ON ac.code = acs.code WHERE ac.code = ?',
        [code]
      );
      if (codeInfo.length === 0) {
        return res.json({ code: 2, msg: '未找到该激活码' });
      }
      record = codeInfo[0];
    }

    // 查询激活信息
    logger.info('[Refund Preview] 查询激活码使用信息:', { code: record.code });
    const [codeRecords] = await conn.execute(
      'SELECT used_by FROM activation_codes WHERE code = ? AND used = 1',
      [record.code]
    );
    logger.info('[Refund Preview] 激活码使用信息查询结果:', {
      found: codeRecords.length > 0,
      records: codeRecords
    });

    if (codeRecords.length === 0) {
      logger.warn('[Refund Preview] 激活码未使用:', { code: record.code });
      return res.json({ code: 3, msg: '激活码未激活或未找到激活信息' });
    }
    const used_by = codeRecords[0].used_by;

    // 查询会员记录
    logger.info('[Refund Preview] 查询会员记录:', { used_by });
    const [members] = await conn.execute(
      'SELECT * FROM members WHERE (device_id = ? AND device_id != "") OR (BIOS_UUID = ? AND BIOS_UUID != "")',
      [used_by, used_by]
    );
    logger.info('[Refund Preview] 会员记录查询结果:', {
      found: members.length > 0,
      records: members
    });

    if (members.length === 0) {
      logger.warn('[Refund Preview] 未找到会员记录:', { used_by });
      return res.json({ code: 4, msg: '未找到对应会员记录' });
    }
    const memberRecord = members[0];

    logger.info('[Refund Preview] 查询成功，返回结果');
    return res.json({
      code: 0,
      msg: '查询成功，请确认以下信息后进行退货操作',
      data: {
        email: record.email,
        activation_code: record.code,
        send_time: record.send_time,
        used_by: used_by,
        member_info: memberRecord
      }
    });
  } catch (err) {
    logger.error('[Refund Preview] 查询退货信息失败:', {
      error: err.message,
      code: err.code,
      sql_state: err.sqlState,
      sql_message: err.sqlMessage,
      stack: err.stack,
      email
    });
    return res.json({ code: -1, msg: '查询退货信息失败', error: err.message });
  } finally {
    if (conn) await conn.end();
  }
});

// ---------------------------
// 新增【一键退货】接口：确认退货操作
// 管理员确认后，删除 members 表中对应的记录
app.post('/api/refund_confirm', requireAuth, async (req, res) => {
  const { type, value, confirm } = req.body;

  if (!value) {
    return res.json({ code: 1, msg: '参数不能为空' });
  }
  if (!confirm) {
    return res.json({ code: 2, msg: '请确认是否进行退货操作' });
  }

  let conn;
  try {
    conn = await mysql.createConnection(dbConfig);

    let record;
    if (type === 'email') {
      // 通过邮箱查询
      const [sendRecords] = await conn.execute(
        'SELECT code, DATE_FORMAT(send_time, "%Y-%m-%d %H:%i:%s") as send_time, email FROM activation_code_sends WHERE email = ? ORDER BY send_time DESC LIMIT 1',
        [value]
      );
      if (sendRecords.length === 0) {
        return res.json({ code: 2, msg: '未找到该邮箱的激活码发送记录' });
      }
      record = sendRecords[0];
    } else {
      // 直接查询激活码
      const [codeInfo] = await conn.execute(
        'SELECT ac.code, acs.email, DATE_FORMAT(acs.send_time, "%Y-%m-%d %H:%i:%s") as send_time FROM activation_codes ac LEFT JOIN activation_code_sends acs ON ac.code = acs.code WHERE ac.code = ?',
        [value]
      );
      if (codeInfo.length === 0) {
        return res.json({ code: 2, msg: '未找到该激活码' });
      }
      record = codeInfo[0];
    }

    // 查询激活信息，获取 used_by
    const [codeRecords] = await conn.execute(
      'SELECT used_by FROM activation_codes WHERE code = ? AND used = 1',
      [record.code]
    );
    if (codeRecords.length === 0) {
      return res.json({ code: 3, msg: '激活码未激活或未找到激活信息' });
    }
    const used_by = codeRecords[0].used_by;

    // 根据 used_by 在 members 表中查找对应会员记录
    const [members] = await conn.execute(
      'SELECT * FROM members WHERE (device_id = ? AND device_id != "") OR (BIOS_UUID = ? AND BIOS_UUID != "")',
      [used_by, used_by]
    );
    if (members.length === 0) {
      return res.json({ code: 4, msg: '未找到对应会员记录' });
    }
    const memberRecord = members[0];

    // 删除会员记录
    await conn.execute(
      'DELETE FROM members WHERE id = ?',
      [memberRecord.id]
    );

    return res.json({
      code: 0,
      msg: '退货操作成功，会员记录已删除',
      data: {
        email: record.email,
        activation_code: record.code,
        send_time: record.send_time,
        used_by: used_by,
        deleted_member: memberRecord
      }
    });
  } catch (err) {
    logger.error('[Refund Confirm] 退货操作失败:', {
      error: err.message,
      stack: err.stack,
      email
    });
    return res.json({ code: -1, msg: '退货操作失败', error: err.message });
  } finally {
    if (conn) await conn.end();
  }
});

// 添加生成激活链接的 API
app.post('/api/generate_activation_link', requireAuth, async (req, res) => {
  try {
    const apiKey = req.headers['x-api-key'];

    // 验证密钥
    if (!apiKey || apiKey !== config.apiKey) {
      return res.json({ code: 403, msg: '无效的密钥' });
    }

    const { days } = req.body;

    if (!days || days <= 0 || days > 3650) {
      return res.json({ code: 1, msg: '天数必须在1-3650之间' });
    }

    // 生成随机token (32位)
    const token = crypto.randomBytes(16).toString('hex');
    const conn = await mysql.createConnection(dbConfig);

    try {
      // 保存token和对应的天数到数据库
      await conn.execute(
        'INSERT INTO activation_links (token, days, created_at, used) VALUES (?, ?, NOW(), 0)',
        [token, days]
      );

      // 生成激活链接
      const activationLink = `${config.baseUrl}/activate/${token}`;

      return res.json({
        code: 0,
        data: {
          link: activationLink,
          days: days
        }
      });
    } finally {
      await conn.end();
    }

  } catch (err) {
    logger.error('生成激活链接出错:', err);
    return res.json({ code: -1, msg: '服务器错误' });
  }
});

// 处理激活页面的路由
app.get('/activate/:token', async (req, res) => {
  const { token } = req.params;
  const conn = await mysql.createConnection(dbConfig);

  try {
    // 验证token
    const [links] = await conn.execute(
      'SELECT * FROM activation_links WHERE token = ? AND used = 0',
      [token]
    );

    if (links.length === 0) {
      return res.send('链接无效或已过期');
    }

    const link = links[0];

    // 返回激活页面
    try {
      const template = await loadHtmlTemplate('activate');
      res.send(template
        .replace('${token}', token)
        .replace('${days}', link.days)
      );
    } catch (err) {
      logger.error('加载激活页面模板失败:', err);
      res.status(500).send('服务器错误');
    }

  } catch (err) {
    logger.error('处理激活页面出错:', err);
    res.send('服务器错误');
  } finally {
    await conn.end();
  }
});

// 处理链接激活的API
app.post('/api/activate_by_link', async (req, res) => {
  const { email, token } = req.body;
  let conn;

  try {
    if (!email || !token) {
      return res.json({ code: 1, msg: '参数错误' });
    }

    if (!email.match(/^[^\s@]+@[^\s@]+\.[^\s@]+$/)) {
      return res.json({ code: 1, msg: '邮箱格式不正确' });
    }

    conn = await mysql.createConnection(dbConfig);
    await conn.beginTransaction();

    // 验证并获取链接信息
    const [links] = await conn.execute(
      'SELECT * FROM activation_links WHERE token = ? AND used = 0',
      [token]
    );

    if (links.length === 0) {
      return res.json({ code: 1, msg: '链接无效或已过期' });
    }

    const link = links[0];
    const daysInt = link.days;  // 添加这行来定义 daysInt

    // 生成激活码
    const activationCode = crypto.randomBytes(8).toString('hex').toUpperCase();

    // 保存激活码，包含渠道号
    await conn.execute(
      'INSERT INTO activation_codes (code, days) VALUES (?, ?)',
      [activationCode, link.days]  // 移除多余的逗号和问号
    );

    // 记录发送记录
    await conn.execute(
      'INSERT INTO activation_code_sends (code, email, days, status) VALUES (?, ?, ?, 1)',
      [activationCode, email, daysInt]
    );

    // 标记链接已使用
    await conn.execute(
      'UPDATE activation_links SET used = 1, used_email = ?, used_at = NOW() WHERE id = ?',
      [email, link.id]
    );

    // 发送邮件
    const mailOptions = {
      from: '"海豚激活系统" <2686264538@qq.com>',
      to: email || '',
      subject: '海豚 Cursor 激活码',
      html: await getActivationEmailTemplate(activationCode, daysInt)
    };

    await transporter.sendMail(mailOptions);
    await conn.commit();

    return res.json({ code: 0, msg: '激活码已发送' });

  } catch (err) {
    if (conn) await conn.rollback();
    logger.error('处理激活请求出错:', err);
    return res.json({ code: -1, msg: '服务器错误' });
  } finally {
    if (conn) await conn.end();
  }
});

// 批量生成激活链接页面
app.get('/seven', requireAuth, async (req, res) => {
  let conn;
  try {
    conn = await mysql.createConnection(dbConfig);

    try {
      const template = await loadHtmlTemplate('batch-generate-links');
      res.send(template);
    } catch (err) {
      logger.error('加载批量生成链接页面失败:', err);
      res.status(500).send('服务器错误');
    }
  } catch (err) {
    logger.error('批量生成链接页面渲染失败:', err);
    res.status(500).send('服务器错误');
  } finally {
    if (conn) await conn.end();
  }
});

// 批量生成激活链接的API
app.post('/api/batch_generate_links', requireAuth, async (req, res) => {
  let conn;
  try {
    const apiKey = req.headers['x-api-key'];

    // 验证密钥
    if (!apiKey || apiKey !== config.apiKey) {
      return res.json({ code: 403, msg: '无效的密钥' });
    }

    const { days, count } = req.body;

    if (!days || !count || days < 1 || count < 1 || count > 10000) {
      return res.json({ code: 1, msg: '参数无效' });
    }

    conn = await mysql.createConnection(dbConfig);
    const links = [];

    for (let i = 0; i < count; i++) {
      const token = crypto.randomBytes(16).toString('hex');
      const [result] = await conn.execute(
        'INSERT INTO activation_links (token, days, created_at) VALUES (?, ?, NOW())',
        [token, days]
      );

      links.push({
        link: `${config.baseUrl}/activate/${token}`,
        days: days
      });
    }

    res.json({ code: 0, data: links });
  } catch (err) {
    logger.error('批量生成激活链接失败:', err);
    res.json({ code: 1, msg: '生成失败' });
  } finally {
    if (conn) await conn.end();
  }
});

// 生成激活码的HTML表单
app.get('/s', requireAuth, async (req, res) => {
  try {
    const template = await loadHtmlTemplate('generate-codes');
    res.send(template);
  } catch (err) {
    logger.error('加载生成激活码页面失败:', err);
    res.status(500).send('服务器错误');
  }
});

// 激活码查询页面
app.get('/codes', requireAuth, async (req, res) => {
  try {
    const template = await loadHtmlTemplate('query-codes');
    res.send(template);
  } catch (err) {
    logger.error('加载激活码查询页面失败:', err);
    res.status(500).send('服务器错误');
  }
});

// 生成激活码API
app.post('/api/generate_codes', requireAuth, async (req, res) => {
  let conn;
  try {
    const apiKey = req.headers['x-api-key'];

    // 验证密钥
    if (!apiKey || apiKey !== config.apiKey) {
      return res.json({ code: 403, msg: '无效的密钥' });
    }

    const { count, days } = req.body;

    // 参数验证
    if (!count || !days || count < 1 || days < 1 || count > 100) {
      return res.json({ code: 1, msg: '数量或天数参数无效' });
    }

    conn = await mysql.createConnection(dbConfig);

    // 检查表结构，如果存在channel_code列则删除
    try {
      await conn.execute(`
        ALTER TABLE activation_codes 
        DROP COLUMN IF EXISTS channel_code
      `);
    } catch (err) {
      logger.warn('[Generate Codes] 删除channel_code列失败(可能不存在):', err);
    }

    const codes = [];
    for (let i = 0; i < count; i++) {
      // 生成16位随机激活码
      const code = crypto.randomBytes(8).toString('hex').toUpperCase();

      // 插入数据库 - 只使用必要的字段
      await conn.execute(`
        INSERT INTO activation_codes (
          code, 
          days, 
          created_at
        ) VALUES (?, ?, NOW())
      `, [code, days]);

      codes.push(code);
    }

    // 记录生成日志
    logger.info('[Generate Codes] 生成成功:', {
      count,
      days,
      codes: codes.length
    });

    return res.json({
      code: 0,
      data: {
        codes,
        count: codes.length,
        days
      }
    });
  } catch (err) {
    logger.error('[Generate Codes] 生成失败:', err);
    return res.json({ code: -1, msg: '服务器错误' });
  } finally {
    if (conn) await conn.end();
  }
});

// 查询激活码API
app.post('/api/query_codes', requireAuth, async (req, res) => {
  let conn;
  try {
    const { status } = req.body;

    conn = await mysql.createConnection(dbConfig);

    let sql = 'SELECT * FROM activation_codes WHERE 1=1';
    const params = [];

    if (status !== '') {
      sql += ' AND used = ?';
      params.push(parseInt(status));
    }

    sql += ' ORDER BY created_at DESC LIMIT 1000';

    const [codes] = await conn.execute(sql, params);

    return res.json({ code: 0, data: codes });
  } catch (err) {
    logger.error('[Query Codes] 查询失败:', err);
    return res.json({ code: -1, msg: '服务器错误' });
  } finally {
    if (conn) await conn.end();
  }
});

// 添加新的管理页面路由
app.get('/key', requireAuth, async (req, res) => {
  try {
    const template = await loadHtmlTemplate('key');
    res.send(template);
  } catch (err) {
    logger.error('加载管理页面失败:', err);
    res.status(500).send('服务器错误');
  }
});

// 添加销量统计页面路由
app.get('/sales', requireAuth, async (req, res) => {
  try {
    const template = await loadHtmlTemplate('sales');
    res.send(template);
  } catch (err) {
    logger.error('加载销量统计页面失败:', err);
    res.status(500).send('服务器错误');
  }
});

// 添加历史激活量数据API
app.get('/api/sales/history', requireAuth, async (req, res) => {
  let conn;
  try {
    conn = await mysql.createConnection(dbConfig);

    // 获取最近30天的激活量数据
    const [rows] = await conn.execute(`
      SELECT 
        DATE(activated_at) as date,
        COUNT(*) as count
      FROM members
      WHERE activated_at >= DATE_SUB(CURDATE(), INTERVAL 30 DAY)
      GROUP BY DATE(activated_at)
      ORDER BY date ASC
    `);

    // 处理数据，确保日期连续
    const result = {
      dates: [],
      counts: []
    };

    // 生成最近30天的日期列表
    const today = new Date();
    for (let i = 29; i >= 0; i--) {
      const date = new Date(today);
      date.setDate(date.getDate() - i);
      const dateStr = date.toISOString().split('T')[0];
      result.dates.push(dateStr);

      // 查找对应日期的数据
      const row = rows.find(r => r.date.toISOString().split('T')[0] === dateStr);
      result.counts.push(row ? row.count : 0);
    }

    res.json({
      code: 0,
      data: result
    });
  } catch (err) {
    logger.error('获取历史激活量数据失败:', err);
    res.json({ code: -1, msg: '获取数据失败' });
  } finally {
    if (conn) await conn.end();
  }
});

// 添加今日每小时销量数据API
app.get('/api/sales/today', requireAuth, async (req, res) => {
  let conn;
  try {
    conn = await mysql.createConnection(dbConfig);

    // 获取今日每小时的激活量
    const [rows] = await conn.execute(`
      SELECT 
        HOUR(activated_at) as hour,
        COUNT(*) as count
      FROM members
      WHERE DATE(activated_at) = CURDATE()
      GROUP BY HOUR(activated_at)
      ORDER BY hour ASC
    `);

    // 处理数据，补充空缺小时
    const result = {
      hours: [],
      counts: []
    };

    // 生成0-23小时
    for (let i = 0; i < 24; i++) {
      result.hours.push(i.toString().padStart(2, '0') + ':00');
      const row = rows.find(r => r.hour === i);
      result.counts.push(row ? row.count : 0);
    }

    res.json({
      code: 0,
      data: result
    });
  } catch (err) {
    logger.error('获取今日激活量数据失败:', err);
    res.json({ code: -1, msg: '获取数据失败' });
  } finally {
    if (conn) await conn.end();
  }
});

// 添加验证账号统计和管理页面
app.get('/verify', requireAuth, async (req, res) => {
  let conn;
  try {
    conn = await mysql.createConnection(dbConfig);

    // 获取查询参数
    const startDate = req.query.start_date || toBeijingTime(new Date(Date.now() - 7 * 24 * 60 * 60 * 1000)).split(' ')[0]; // 默认7天前
    const endDate = req.query.end_date || toBeijingTime(new Date()).split(' ')[0]; // 默认今天

    // 查询时间段内每天需要验证的账号数量
    const [dailyStats] = await conn.execute(`
      SELECT 
        DATE(end_at) as date,
        COUNT(*) as count
      FROM cursor_accounts 
      WHERE need_verify = 1 
        AND end_at >= ? 
        AND end_at <= DATE_ADD(?, INTERVAL 1 DAY)
      GROUP BY DATE(end_at)
      ORDER BY date DESC
    `, [startDate, endDate]);

    // 获取账号总数和未使用账号数
    const [accountStats] = await conn.execute(`
      SELECT 
        COUNT(*) as total_accounts,
        SUM(CASE WHEN used = 0 THEN 1 ELSE 0 END) as unused_accounts
      FROM cursor_accounts
    `);

    // 获取最近30天的激活量数据
    const [activationStats] = await conn.execute(`
      SELECT 
        DATE_FORMAT(activated_at, '%Y-%m-%d') as date,
        COUNT(*) as count
      FROM members
      WHERE activated_at >= DATE_SUB(CURDATE(), INTERVAL 30 DAY)
      GROUP BY DATE(activated_at)
      ORDER BY date ASC
    `);

    // 处理激活量数据，确保日期连续
    const chartData = {
      dates: [],
      counts: []
    };

    // 生成最近30天的日期列表
    const today = new Date();
    for (let i = 29; i >= 0; i--) {
      const date = new Date(today);
      date.setDate(date.getDate() - i);
      const dateStr = date.toISOString().split('T')[0];
      chartData.dates.push(dateStr);

      // 查找对应日期的数据
      const row = activationStats.find(r => r.date === dateStr);
      chartData.counts.push(row ? row.count : 0);
    }

    try {
      const template = await loadHtmlTemplate('verify');
      res.send(template
        .replace('${startDate}', startDate)
        .replace('${endDate}', endDate)
        .replace('${totalAccounts}', accountStats[0].total_accounts)
        .replace('${unusedAccounts}', accountStats[0].unused_accounts)
        .replace('${usageRate}', ((accountStats[0].total_accounts - accountStats[0].unused_accounts) / accountStats[0].total_accounts * 100).toFixed(1))
        .replace('${dailyStats}', dailyStats.length > 0 ? `
            <table class="stats-table">
              <thead>
                <tr>
                  <th>日期</th>
                  <th>需验证账号数量</th>
                  <th>操作</th>
                </tr>
              </thead>
              <tbody>
                ${dailyStats.map(stat => `
                  <tr>
                    <td>${stat.date.toISOString().split('T')[0]}</td>
                    <td>${stat.count}</td>
                    <td>
                      <button class="reset-btn" onclick="resetAccounts('${stat.date.toISOString().split('T')[0]}')">
                        重置账号
                      </button>
                    </td>
                  </tr>
                `).join('')}
              </tbody>
            </table>
          ` : `
            <div class="no-data">
              所选时间范围内没有需要验证的账号
            </div>
        `)
        .replace('${chartData}', JSON.stringify(chartData))
      );
    } catch (err) {
      logger.error('加载验证账号统计页面失败:', err);
      res.status(500).send('服务器错误');
    }
  } catch (err) {
    logger.error('获取验证账号统计失败:', err);
    res.status(500).send('服务器错误');
  } finally {
    if (conn) await conn.end();
  }
});

// 添加重置指定日期需验证账号的API
app.post('/api/reset_verify_accounts', requireAuth, async (req, res) => {
  let conn;
  try {
    const { date } = req.body;

    if (!date) {
      return res.json({ code: 1, msg: '日期参数不能为空' });
    }

    conn = await mysql.createConnection(dbConfig);

    // 重置指定日期的需验证账号
    const [result] = await conn.execute(`
      UPDATE cursor_accounts 
      SET used = 0,
          used_by = NULL,
          used_at = NULL,
          end_at = NULL,
          need_verify = 0
      WHERE need_verify = 1 
        AND DATE(end_at) = ?
    `, [date]);

    logger.info('重置验证账号完成:', {
      date,
      affected_rows: result.affectedRows
    });

    return res.json({
      code: 0,
      msg: '重置成功',
      data: {
        affected_rows: result.affectedRows
      }
    });
  } catch (err) {
    logger.error('重置验证账号失败:', err);
    return res.json({ code: -1, msg: '重置失败: ' + err.message });
  } finally {
    if (conn) await conn.end();
  }
});

// 添加批量退货页面路由
app.get('/re', requireAuth, async (req, res) => {
  try {
    const template = await loadHtmlTemplate('re');
    res.send(template);
  } catch (err) {
    logger.error('加载批量退货页面失败:', err);
    res.status(500).send('服务器错误');
  }
});

// 添加解除锁定页面路由
app.get('/unlock', requireAuth, async (req, res) => {
  try {
    const template = await loadHtmlTemplate('unlock');
    res.send(template);
  } catch (err) {
    logger.error('加载解除锁定页面失败:', err);
    res.status(500).send('服务器错误');
  }
});

// 添加解除锁定API
app.post('/api/unlock_refresh', requireAuth, async (req, res) => {
  let conn;

  try {
    conn = await mysql.createConnection(dbConfig);
    await conn.beginTransaction();

    // 重置最近一小时内的刷新计数
    const [result] = await conn.execute(`
      UPDATE members 
      SET refresh_count = 0,
          last_refresh_time = NULL
      WHERE last_refresh_time >= DATE_SUB(NOW(), INTERVAL 1 HOUR)
    `);

    // 删除最近一小时内的刷新记录
    await conn.execute(`
      DELETE FROM cursor_accounts 
      WHERE used_at >= DATE_SUB(NOW(), INTERVAL 1 HOUR)
    `);

    await conn.commit();

    logger.info('[Unlock Refresh] 解除锁定成功:', {
      affected_members: result.affectedRows
    });

    return res.json({
      code: 0,
      msg: `成功解除 ${result.affectedRows} 个用户的刷新锁定`
    });

  } catch (err) {
    if (conn) await conn.rollback();
    logger.error('[Unlock Refresh] 解除锁定失败:', {
      error: err.message,
      stack: err.stack
    });
    return res.json({ code: -1, msg: '处理失败: ' + err.message });
  } finally {
    if (conn) await conn.end();
  }
});

// 添加批量退货处理API
app.post('/api/batch_refund', requireAuth, async (req, res) => {
  const { code, type } = req.body;
  let conn;

  try {
    if (!code || !/^[A-Z0-9]{16}$/.test(code)) {
      return res.json({ code: 1, msg: '无效的激活码格式' });
    }

    conn = await mysql.createConnection(dbConfig);
    await conn.beginTransaction();

    if (type === 'quota') {
      // 处理额度激活码退货
      const [quotaInfo] = await conn.execute(
        'SELECT * FROM quota_activation_codes WHERE code = ?',
        [code]
      );

      if (quotaInfo.length === 0) {
        return res.json({ code: 2, msg: '额度激活码不存在' });
      }

      const activationCode = quotaInfo[0];

      // 计算已用天数
      const usedDays = activationCode.used ? 
        Math.floor((new Date() - new Date(activationCode.used_at)) / (1000 * 60 * 60 * 24)) : 0;

      // 计算有效天数
      const validDays = activationCode.expire_days;

      if (!activationCode.used) {
        // 如果激活码未使用，直接删除并生成新的
        await conn.execute(
          'DELETE FROM quota_activation_codes WHERE code = ?',
          [code]
        );

        // 生成新的激活码
        const newCode = crypto.randomBytes(8).toString('hex').toUpperCase();
        await conn.execute(`
          INSERT INTO quota_activation_codes (
            code, 
            quota,
            expire_days,
            seller_id,
            created_at
          ) VALUES (?, ?, ?, ?, NOW())
        `, [newCode, activationCode.quota, activationCode.expire_days, activationCode.seller_id]);

        await conn.commit();
        return res.json({
          code: 0,
          msg: '未使用的额度激活码已删除，新激活码已生成',
          data: { 
            new_code: newCode, 
            is_used: false,
            valid_days: validDays,
            used_days: usedDays
          }
        });
      }

      // 查找对应的额度会员记录
      const [quotaMembers] = await conn.execute(
        'SELECT *, remaining_quota, total_quota FROM quota_members WHERE BIOS_UUID = ?',
        [activationCode.used_by]
      );

      if (quotaMembers.length === 0) {
        await conn.rollback();
        return res.json({ code: 3, msg: '未找到对应的额度会员记录' });
      }

      const member = quotaMembers[0];
      const usedQuota = member.total_quota - member.remaining_quota;

      // 扣除额度
      await conn.execute(`
        UPDATE quota_members 
        SET remaining_quota = remaining_quota - ?,
            total_quota = total_quota - ?
        WHERE id = ?
      `, [activationCode.quota, activationCode.quota, member.id]);

      // 删除激活码
      await conn.execute(
        'DELETE FROM quota_activation_codes WHERE code = ?',
        [code]
      );

      // 生成新的激活码
      const newCode = crypto.randomBytes(8).toString('hex').toUpperCase();
      await conn.execute(`
        INSERT INTO quota_activation_codes (
          code, 
          quota,
          expire_days,
          seller_id,
          created_at
        ) VALUES (?, ?, ?, ?, NOW())
      `, [newCode, activationCode.quota, activationCode.expire_days, activationCode.seller_id]);

      await conn.commit();

      return res.json({
        code: 0,
        msg: `成功处理：扣除${activationCode.quota}额度，新激活码已生成`,
        data: { 
          new_code: newCode, 
          is_used: true,
          valid_days: validDays,
          used_days: usedDays,
          used_quota: usedQuota
        }
      });

    } else {
      // 处理普通激活码退货
      const [codeInfo] = await conn.execute(
        'SELECT * FROM activation_codes WHERE code = ?',
        [code]
      );

      if (codeInfo.length === 0) {
        return res.json({ code: 2, msg: '激活码不存在' });
      }

      const activationCode = codeInfo[0];

      // 计算已用天数
      const usedDays = activationCode.used ? 
        Math.floor((new Date() - new Date(activationCode.used_at)) / (1000 * 60 * 60 * 24)) : 0;

      // 计算有效天数
      const validDays = activationCode.days;

      if (!activationCode.used) {
        // 如果激活码未使用，直接删除并生成新的
        await conn.execute(
          'DELETE FROM activation_codes WHERE code = ?',
          [code]
        );

        // 生成新的激活码
        const newCode = crypto.randomBytes(8).toString('hex').toUpperCase();
        await conn.execute(`
          INSERT INTO activation_codes (
            code, 
            days,
            seller_id,
            created_at
          ) VALUES (?, ?, ?, NOW())
        `, [newCode, activationCode.days, activationCode.seller_id]);

        await conn.commit();
        return res.json({
          code: 0,
          msg: '未使用的激活码已删除，新激活码已生成',
          data: { 
            new_code: newCode, 
            is_used: false,
            valid_days: validDays,
            used_days: usedDays
          }
        });
      }

      // 查找对应的会员记录
      const [members] = await conn.execute(
        'SELECT * FROM members WHERE device_id = ? OR BIOS_UUID = ?',
        [activationCode.used_by, activationCode.used_by]
      );

      if (members.length === 0) {
        await conn.rollback();
        return res.json({ code: 3, msg: '未找到对应的会员记录' });
      }

      // 删除会员记录
      await conn.execute(
        'DELETE FROM members WHERE id = ?',
        [members[0].id]
      );

      // 删除激活码
      await conn.execute(
        'DELETE FROM activation_codes WHERE code = ?',
        [code]
      );

      // 生成新的激活码
      const newCode = crypto.randomBytes(8).toString('hex').toUpperCase();
      await conn.execute(`
        INSERT INTO activation_codes (
          code, 
          days,
          seller_id,
          created_at
        ) VALUES (?, ?, ?, NOW())
      `, [newCode, activationCode.days, activationCode.seller_id]);

      await conn.commit();

      return res.json({
        code: 0,
        msg: '退货处理成功，会员记录已删除，新激活码已生成',
        data: { 
          new_code: newCode, 
          is_used: true,
          valid_days: validDays,
          used_days: usedDays,
          deleted_member: members[0]
        }
      });
    }

  } catch (err) {
    if (conn) await conn.rollback();
    logger.error('[Batch Refund] 处理失败:', {
      error: err.message,
      stack: err.stack,
      code,
      type
    });
    return res.json({ code: -1, msg: '处理失败: ' + err.message });
  } finally {
    if (conn) await conn.end();
  }
});

// 管理页面路由
app.get('/', requireAuth, async (req, res) => {
  try {
    const template = await loadHtmlTemplate('admin');

    // 获取账号统计数据
    const conn = await mysql.createConnection(dbConfig);
    const [accountStats] = await conn.execute(
      'SELECT COUNT(*) as total_accounts, SUM(CASE WHEN used = 0 THEN 1 ELSE 0 END) as unused_accounts FROM accounts'
    );

    // 获取来源统计数据
    const [sourceStats] = await conn.execute(`
      SELECT 
        source_from as source,
        COUNT(*) as count,
        SUM(CASE WHEN used = 0 THEN 1 ELSE 0 END) as unused_count,
        SUM(CASE WHEN DATE(created_at) = CURDATE() THEN 1 ELSE 0 END) as today_count,
        SUM(CASE WHEN created_at >= DATE_SUB(NOW(), INTERVAL 10 MINUTE) THEN 1 ELSE 0 END) as recent_count
      FROM accounts 
      GROUP BY source_from
    `);

    // 获取监控记录
    const [monitorLogs] = await conn.execute(
      'SELECT * FROM monitor_logs ORDER BY check_time DESC LIMIT 10'
    );

    await conn.end();

    // 替换模板中的变量
    res.send(template
      .replace('${accountStats[0].total_accounts}', accountStats[0].total_accounts)
      .replace('${accountStats[0].unused_accounts}', accountStats[0].unused_accounts)
      .replace('${sourceStats.map', sourceStats.map)
      .replace('${monitorLogs.map', monitorLogs.map)
    );
  } catch (err) {
    logger.error('加载管理页面失败:', err);
    res.status(500).send('服务器错误');
  }
});

// 将原来的根路由 '/' 改为 '/s'
app.get('/s', requireAuth, async (req, res) => {
  res.send("hello");
  return;
});

// 添加检查账号剩余次数的接口
app.post('/api/check_account_quota', async (req, res) => {  // 移除 requireAuth
  let conn;
  try {
    const { email } = req.body;
    const clientIP = req.ip.replace(/^::ffff:/, '');

    if (!email) {
      return res.json({
        code: 1,
        msg: '邮箱不能为空'
      });
    }

    conn = await mysql.createConnection(dbConfig);

    // 检查IP访问频率
    const [ipRequests] = await conn.execute(`
      SELECT COUNT(*) as count
      FROM access_logs 
      WHERE ip = ? 
      AND api = '/api/check_account_quota'
      AND created_at > DATE_SUB(NOW(), INTERVAL 1 HOUR)
    `, [clientIP]);

    if (ipRequests[0].count > 60) { // 每小时最多60次
      logger.warn('[Check Quota] IP访问过于频繁:', {
        ip: clientIP,
        count: ipRequests[0].count
      });
      return res.json({
        code: 4,
        msg: '请求过于频繁,请稍后再试'
      });
    }

    // 查询账号token
    const [accounts] = await conn.execute(
      'SELECT id, email, access_token FROM cursor_accounts WHERE email = ?',
      [email]
    );

    if (accounts.length === 0) {
      return res.json({
        code: 2,
        msg: '未找到该邮箱对应的账号'
      });
    }

    const account = accounts[0];

    try {
      // 调用userinfo接口检查配额
      const response = await fetch('http://101.200.57.128:4000/userinfo', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          token: account.access_token
        })
      });

      if (!response.ok) {
        throw new Error(`API请求失败: ${response.status}`);
      }

      const data = await response.json();

      // 修正数据解析
      const premiumUsage = data.usage?.premium || {
        requests: 0,
        requests_total: 0,
        tokens: 0,
        max_requests: 0
      };
      const trialDays = data.stripe?.days_remaining_on_trial || 0;

      // 记录检查日志
      await conn.execute(`
        UPDATE cursor_accounts 
        SET 
          requests = ?,
          max_requests = ?,
          check_time = NOW()
        WHERE id = ?
      `, [
        premiumUsage.requests || 0,
        premiumUsage.max_requests || 0,
        account.id
      ]);

      logger.info('[Check Quota] 检查账号配额成功:', {
        email,
        account_id: account.id,
        requests: premiumUsage.requests,
        requests_total: premiumUsage.requests_total,
        tokens: premiumUsage.tokens,
        max_requests: premiumUsage.max_requests,
        trial_days: trialDays,
        client_ip: clientIP
      });

      return res.json({
        code: 0,
        data: {
          email: account.email,
          requests: premiumUsage.requests,
          requests_total: premiumUsage.requests_total,
          tokens: premiumUsage.tokens,
          max_requests: premiumUsage.max_requests,
          remaining: premiumUsage.max_requests - premiumUsage.requests,
          trial_days: trialDays,
          check_time: new Date().toISOString()
        }
      });

    } catch (err) {
      logger.error('[Check Quota] 调用API失败:', {
        error: err.message,
        email,
        account_id: account.id,
        client_ip: clientIP
      });
      return res.json({
        code: 3,
        msg: '检查配额失败: ' + err.message
      });
    }

  } catch (err) {
    logger.error('[Check Quota] 处理失败:', {
      error: err.message,
      stack: err.stack,
      email: req.body.email,
      client_ip: req.ip.replace(/^::ffff:/, '')
    });
    return res.json({ code: -1, msg: '服务器错误' });
  } finally {
    if (conn) await conn.end();
  }
});

// 添加通过邮箱获取账号信息的 API
app.post('/api/account_by_email', async (req, res) => {
  let conn;
  try {
    const { email } = req.body;  // 从 req.body 获取参数，而不是 req.query

    // 验证参数
    if (!email || email.trim() === '') {
      return res.json({ code: 1, msg: '邮箱不能为空' });
    }

    conn = await mysql.createConnection({
      ...dbConfig,
      connectTimeout: 10000
    });

    // 查询账号信息
    const [accounts] = await conn.execute(
      'SELECT email, access_token, refresh_token FROM cursor_accounts WHERE email = ?',
      [email.trim()]
    );

    if (accounts.length === 0) {
      return res.json({ code: 2, msg: '未找到该账号' });
    }

    return res.json({
      code: 0,
      data: {
        email: accounts[0].email,
        access_token: accounts[0].access_token || '',
        refresh_token: accounts[0].refresh_token || ''
      }
    });

  } catch (err) {
    logger.error('[Account By Email] 处理出错:', err);
    return res.json({ code: -1, msg: '服务器错误' });
  } finally {
    if (conn) {
      try {
        await conn.end();
      } catch (err) {
        logger.error('[Account By Email] 关闭数据库连接失败:', err);
      }
    }
  }
});

// 查询额度会员详情
app.post('/api/quota_member_detail', async (req, res) => {
  let conn;
  try {
    const { bios_uuid } = req.body;

    if (!bios_uuid) {
      return res.json({ code: 1, msg: 'BIOS UUID不能为空' });
    }

    conn = await mysql.createConnection(dbConfig);

    const [quotaMembers] = await conn.execute(`
      SELECT 
        id,
        remaining_quota,
        total_quota,
        activated_at,
        expire_at,
        refresh_count,
        last_refresh_time
      FROM quota_members 
        WHERE BIOS_UUID = ? 
      `, [bios_uuid]);

    if (quotaMembers.length === 0) {
      return res.json({ code: 2, msg: '未找到额度会员信息' });
    }

    return res.json({
      code: 0,
      data: quotaMembers[0]
    });

  } catch (err) {
    logger.error('[Quota Member Detail] 处理出错:', err);
    return res.json({ code: -1, msg: '服务器错误' });
  } finally {
    if (conn) await conn.end();
  }
});

// 查询额度使用记录
app.post('/api/quota_usage_history', async (req, res) => {
  let conn;
  try {
    const { bios_uuid } = req.body; // 移除分页参数

    console.log(`请求参数: bios_uuid=${bios_uuid}`); // 添加调试信息

    if (!bios_uuid) {
      return res.json({ code: 1, msg: 'BIOS UUID不能为空' });
    }

    conn = await mysql.createConnection(dbConfig);

    // 查询总记录数
    const [total] = await conn.execute(`
      SELECT COUNT(*) as total 
      FROM quota_usage_history quh
      JOIN quota_members qm ON qm.id = quh.member_id
      WHERE qm.BIOS_UUID = ?
    `, [bios_uuid]);

    // 打印总记录数查询的 SQL 语句
    console.log(`执行查询总记录数: SELECT COUNT(*) as total FROM quota_usage_history quh JOIN quota_members qm ON qm.id = quh.member_id WHERE qm.BIOS_UUID = '${bios_uuid}'`);

    // 查询所有数据
    const [records] = await conn.execute(`
      SELECT 
        quh.*,
        ca.email,
        ca.access_token,
        ca.refresh_token
      FROM quota_usage_history quh
      JOIN quota_members qm ON qm.id = quh.member_id
      JOIN cursor_accounts ca ON ca.id = quh.account_id
      WHERE qm.BIOS_UUID = ?
      ORDER BY quh.used_at DESC
    `, [bios_uuid]);

    // 打印查询所有数据的 SQL 语句
    console.log(`执行查询所有数据: SELECT quh.*, ca.email, ca.access_token, ca.refresh_token FROM quota_usage_history quh JOIN quota_members qm ON qm.id = quh.member_id JOIN cursor_accounts ca ON ca.id = quh.account_id WHERE qm.BIOS_UUID = '${bios_uuid}' ORDER BY quh.used_at DESC`);

    return res.json({
      code: 0,
      data: {
        total: total[0].total,
        records: records.map(record => ({
          id: record.id,
          email: record.email,
          used_at: record.used_at,
          type: record.type,
          quota_used: record.quota_used,
          ip: record.ip
        }))
      }
    });

  } catch (err) {
    logger.error('[Quota Usage History] 处理出错:', err);
    return res.json({ code: -1, msg: '服务器错误' });
  } finally {
    if (conn) await conn.end();
  }
});

// 查询额度激活记录
app.post('/api/quota_activation_history', async (req, res) => {
  let conn;
  try {
    const { bios_uuid, page = 1, page_size = 20 } = req.body;

    if (!bios_uuid) {
      return res.json({ code: 1, msg: 'BIOS UUID不能为空' });
    }

    conn = await mysql.createConnection(dbConfig);

    const [records] = await conn.execute(`
      SELECT 
        qac.code,
        qac.quota,
        qac.used_at,
        qac.expire_days
      FROM quota_activation_codes qac
      WHERE qac.used_by = ?
      ORDER BY qac.used_at DESC
      LIMIT ? OFFSET ?
    `, [bios_uuid, page_size, (page - 1) * page_size]);

    return res.json({
      code: 0,
      data: {
        records,
        page,
        page_size
      }
    });

  } catch (err) {
    logger.error('[Quota Activation History] 处理出错:', err);
    return res.json({ code: -1, msg: '服务器错误' });
  } finally {
    if (conn) await conn.end();
  }
});

// 生成额度激活码
app.post('/api/generate_quota_codes', async (req, res) => {
  let conn;
  try {
    const apiKey = req.headers['x-api-key'];

    // 验证密钥
    if (!apiKey || apiKey !== (process.env.API_KEY || 'cursor-98999899')) {
      logger.warn('[Generate Quota Codes] 无效的密钥:', {
        provided_key: apiKey,
        ip: req.ip
      });
      return res.json({ code: 403, msg: '无效的密钥' });
    }

    const { quota, expire_days, count = 1, seller_id } = req.body;

    // 验证参数
    if (!quota || !expire_days || !seller_id) {
      return res.json({ code: 1, msg: '额度、有效期和渠道号不能为空' });
    }

    conn = await mysql.createConnection(dbConfig);

    // 先检查表是否有 seller_id 字段,如果没有则添加
    try {
      await conn.execute(`
        ALTER TABLE quota_activation_codes 
        ADD COLUMN IF NOT EXISTS seller_id VARCHAR(50) DEFAULT NULL,
        ADD INDEX idx_seller_id (seller_id)
      `);
    } catch (err) {
      logger.warn('[Generate Quota Codes] 添加 seller_id 字段失败(可能已存在):', err);
    }

    const codes = [];
    for (let i = 0; i < count; i++) {
      // 生成16位大写的激活码
      const code = crypto.randomBytes(8).toString('hex').toUpperCase();
      
      await conn.execute(`
        INSERT INTO quota_activation_codes (
          code,
          quota,
          expire_days,
          seller_id,
          created_at
        ) VALUES (?, ?, ?, ?, NOW())
      `, [code, quota, expire_days, seller_id]);

      codes.push(code);
    }

    // 记录生成日志
    logger.info('[Generate Quota Codes] 生成成功:', {
      count,
      quota,
      expire_days,
      seller_id,
      codes: codes.length
    });

    return res.json({
      code: 0,
      data: {
        codes,
        quota,
        expire_days,
        seller_id,
        count: codes.length
      }
    });

  } catch (err) {
    logger.error('[Generate Quota Codes] 处理出错:', {
      error: err.message,
      stack: err.stack,
      request: {
        quota: req.body.quota,
        expire_days: req.body.expire_days,
        count: req.body.count,
        seller_id: req.body.seller_id
      }
    });
    return res.json({ code: -1, msg: '服务器错误' });
  } finally {
    if (conn) {
      try {
        await conn.end();
      } catch (err) {
        logger.error('[Generate Quota Codes] 关闭数据库连接失败:', err);
      }
    }
  }
});

// 查询额度激活码列表
app.post('/api/list_quota_codes', async (req, res) => {
  let conn;
  try {
    const { page = 1, page_size = 20, used = null } = req.body;

    conn = await mysql.createConnection(dbConfig);

    let whereClause = '';
    const params = [];

    if (used !== null) {
      whereClause = 'WHERE used = ?';
      params.push(used);
    }

    // 查询总记录数
    const [total] = await conn.execute(`
      SELECT COUNT(*) as total 
      FROM quota_activation_codes 
      ${whereClause}
    `, params);

    // 查询分页数据
    const [records] = await conn.execute(`
      SELECT * 
      FROM quota_activation_codes 
      ${whereClause}
      ORDER BY created_at DESC
      LIMIT ? OFFSET ?
    `, [...params, page_size, (page - 1) * page_size]);

    return res.json({
      code: 0,
      data: {
        total: total[0].total,
        records,
        page,
        page_size
      }
    });

  } catch (err) {
    logger.error('[List Quota Codes] 处理出错:', err);
    return res.json({ code: -1, msg: '服务器错误' });
  } finally {
    if (conn) await conn.end();
  }
});

// 查询额度会员列表
app.post('/api/list_quota_members', async (req, res) => {
  let conn;
  try {
    const { page = 1, page_size = 20, status = 'all' } = req.body;

    conn = await mysql.createConnection(dbConfig);

    let whereClause = '';
    if (status === 'active') {
      whereClause = 'WHERE expire_at > NOW() AND remaining_quota >= 0';
    } else if (status === 'expired') {
      whereClause = 'WHERE expire_at <= NOW()';
    }

    // 查询总记录数
    const [total] = await conn.execute(`
      SELECT COUNT(*) as total 
      FROM quota_members 
      ${whereClause}
    `);

    // 查询分页数据
    const [records] = await conn.execute(`
      SELECT * 
      FROM quota_members 
      ${whereClause}
      ORDER BY created_at DESC
      LIMIT ? OFFSET ?
    `, [page_size, (page - 1) * page_size]);

    return res.json({
      code: 0,
      data: {
        total: total[0].total,
        records,
        page,
        page_size
      }
    });

  } catch (err) {
    logger.error('[List Quota Members] 处理出错:', err);
    return res.json({ code: -1, msg: '服务器错误' });
  } finally {
    if (conn) await conn.end();
  }
});

// 手动调整会员额度
app.post('/api/adjust_quota', async (req, res) => {
  let conn;
  try {
    const { bios_uuid, adjust_amount, reason } = req.body;

    if (!bios_uuid || !adjust_amount) {
      return res.json({ code: 1, msg: '参数不完整' });
    }

    conn = await mysql.createConnection(dbConfig);

    // 更新额度
    await conn.execute(`
      UPDATE quota_members 
      SET remaining_quota = remaining_quota + ?,
          total_quota = total_quota + ?
      WHERE BIOS_UUID = ?
    `, [adjust_amount, adjust_amount, bios_uuid]);

    // 记录调整历史
    await conn.execute(`
      INSERT INTO quota_adjustment_history (
        bios_uuid,
        adjust_amount,
        reason,
        created_at
      ) VALUES (?, ?, ?, NOW())
    `, [bios_uuid, adjust_amount, reason || '手动调整']);

    return res.json({ code: 0, msg: '调整成功' });

  } catch (err) {
    logger.error('[Adjust Quota] 处理出错:', err);
    return res.json({ code: -1, msg: '服务器错误' });
  } finally {
    if (conn) await conn.end();
  }
});

// 查询额度调整历史
app.post('/api/quota_adjustment_history', async (req, res) => {
  let conn;
  try {
    const { bios_uuid, page = 1, page_size = 20 } = req.body;

    if (!bios_uuid) {
      return res.json({ code: 1, msg: 'BIOS UUID不能为空' });
    }

    conn = await mysql.createConnection(dbConfig);

    // 查询总记录数
    const [total] = await conn.execute(`
      SELECT COUNT(*) as total 
      FROM quota_adjustment_history 
      WHERE bios_uuid = ?
    `, [bios_uuid]);

    // 查询分页数据
    const [records] = await conn.execute(`
      SELECT * 
      FROM quota_adjustment_history 
      WHERE bios_uuid = ?
      ORDER BY created_at DESC
      LIMIT ? OFFSET ?
    `, [bios_uuid, page_size, (page - 1) * page_size]);

    return res.json({
      code: 0,
      data: {
        total: total[0].total,
        records,
        page,
        page_size
      }
    });

  } catch (err) {
    logger.error('[Quota Adjustment History] 处理出错:', err);
    return res.json({ code: -1, msg: '服务器错误' });
  } finally {
    if (conn) await conn.end();
  }
});

// 查询额度会员锁定的账号
app.post('/api/quota_member_locked_accounts', async (req, res) => {
  let conn;
  try {
    const { bios_uuid } = req.body;

    if (!bios_uuid) {
      return res.json({ code: 1, msg: 'BIOS UUID不能为空' });
    }

    conn = await mysql.createConnection(dbConfig);

    // 查询会员信息和锁定的账号
    const [accounts] = await conn.execute(`
      SELECT 
        ca.id,
        ca.email,
        ca.access_token,
        ca.refresh_token,
        ca.used_at,
        ca.need_verify,
        qma.locked_at,
        qma.expire_at,
        CASE 
          WHEN qma.expire_at <= NOW() THEN 'expired'
          WHEN ca.need_verify = 1 THEN 'need_verify'
          ELSE 'active'
        END as status
      FROM quota_members qm
      JOIN quota_member_accounts qma ON qma.member_id = qm.id
      JOIN cursor_accounts ca ON ca.id = qma.account_id
      WHERE qm.BIOS_UUID = ?
      ORDER BY qma.locked_at DESC
    `, [bios_uuid]);

    // 查询会员信息
    const [member] = await conn.execute(`
      SELECT 
        remaining_quota,
        total_quota,
        locked_accounts_count,
        expire_at
      FROM quota_members
      WHERE BIOS_UUID = ?
    `, [bios_uuid]);

    if (member.length === 0) {
      return res.json({ code: 2, msg: '未找到额度会员信息' });
    }

    return res.json({
      code: 0,
      data: {
        member: {
          remaining_quota: member[0].remaining_quota,
          total_quota: member[0].total_quota,
          locked_accounts_count: member[0].locked_accounts_count,
          expire_at: member[0].expire_at
        },
        accounts: accounts.map(acc => ({
          id: acc.id,
          email: acc.email,
          access_token: acc.access_token,
          refresh_token: acc.refresh_token,
          used_at: acc.used_at,
          locked_at: acc.locked_at,
          expire_at: acc.expire_at,
          status: acc.status
        }))
      }
    });

  } catch (err) {
    logger.error('[Quota Member Locked Accounts] 处理出错:', {
      error: err.message,
      stack: err.stack,
      request: { bios_uuid }
    });
    return res.json({ code: -1, msg: '服务器错误' });
  } finally {
    if (conn) await conn.end();
  }
});

// 添加采集统计页面路由
app.get('/catch', requireAuth, async (req, res) => {
  let conn;
  try {
    conn = await mysql.createConnection(dbConfig);

    // 按来源统计数据
    const [sourceStats] = await conn.execute(`
      SELECT 
        source_from,
        COUNT(*) as total_count,
        SUM(CASE 
          WHEN created_at >= DATE_SUB(NOW(), INTERVAL 10 MINUTE) 
          THEN 1 ELSE 0 
        END) as last_10min_count,
        SUM(CASE 
          WHEN created_at >= DATE_SUB(NOW(), INTERVAL 1 HOUR) 
          THEN 1 ELSE 0 
        END) as last_1hour_count,
        SUM(CASE 
          WHEN DATE(created_at) = CURDATE() 
          THEN 1 ELSE 0 
        END) as today_count
      FROM cursor_accounts
      WHERE source_from IS NOT NULL
      GROUP BY source_from
      ORDER BY total_count DESC
    `);

    const template = await loadHtmlTemplate('catch');

    // 生成统计卡片HTML
    const statsHtml = sourceStats.map(stat => `
      <div class="bg-white rounded-lg shadow-md p-6 mb-4">
        <h3 class="text-xl font-bold mb-4">${stat.source_from || '未知来源'}</h3>
        <div class="grid grid-cols-3 gap-4">
          <div class="text-center">
            <p class="text-gray-600">最近10分钟</p>
            <p class="text-2xl font-bold text-blue-600">${stat.last_10min_count}</p>
          </div>
          <div class="text-center">
            <p class="text-gray-600">最近1小时</p>
            <p class="text-2xl font-bold text-green-600">${stat.last_1hour_count}</p>
          </div>
          <div class="text-center">
            <p class="text-gray-600">今日总数</p>
            <p class="text-2xl font-bold text-purple-600">${stat.today_count}</p>
          </div>
        </div>
        <div class="mt-4 text-center">
          <p class="text-gray-600">总采集数量</p>
          <p class="text-3xl font-bold text-gray-800">${stat.total_count}</p>
        </div>
      </div>
    `).join('');

    // 替换模板中的变量
    res.send(template.replace('${statsContent}', statsHtml));

  } catch (err) {
    logger.error('加载采集统计页面失败:', err);
    res.status(500).send('服务器错误');
  } finally {
    if (conn) {
      await conn.end();
    }
  }
});

app.post('/api/check_member_batch', async (req, res) => {
  let conn;
  try {
    const { device_ids } = req.body;

    // 验证参数
    if (!Array.isArray(device_ids) || device_ids.length === 0) {
      return res.json({
        code: 1,
        msg: '请提供有效的设备ID数组'
      });
    }

    conn = await mysql.createConnection(dbConfig);

    // 构建并记录device_id查询SQL
    const deviceSQL = mysql.format(`
      SELECT DISTINCT device_id
      FROM members 
      WHERE device_id IN (?) AND expire_at > NOW()
    `, [device_ids]);

    logger.info('[Check Member Batch] Device SQL:', deviceSQL);
    const [deviceMembers] = await conn.execute(deviceSQL);

    // 构建并记录bios_uuid查询SQL
    const biosSQL = mysql.format(`
      SELECT DISTINCT bios_uuid
      FROM members 
      WHERE bios_uuid IN (?) AND expire_at > NOW()
    `, [device_ids]);

    logger.info('[Check Member Batch] BIOS SQL:', biosSQL);
    const [biosMembers] = await conn.execute(biosSQL);

    // 合并结果并去重
    const validIds = [...new Set([
      ...deviceMembers.map(m => m.device_id),
      ...biosMembers.map(m => m.bios_uuid).filter(b => b) // 过滤掉空值
    ])];

    logger.info('[Check Member Batch] 批量查询结果:', {
      input_count: device_ids.length,
      valid_count: validIds.length
    });

    return res.json({
      code: 0,
      data: {
        valid_ids: validIds
      }
    });

  } catch (err) {
    logger.error('[Check Member Batch] 处理出错:', err);
    res.status(500).json({ code: 1, msg: '服务器错误' });
  } finally {
    if (conn) {
      try {
        await conn.end();
      } catch (err) {
        logger.error('[Check Member Batch] 关闭数据库连接出错:', err);
      }
    }
  }
});

app.post('/api/create_member_from_activation', async (req, res) => {
  let conn;
  try {
    const { unique_bios_uuid, activation_code, old_id } = req.body;
    let newExpireAt; // 在这里定义变量

    // 验证参数
    if (!unique_bios_uuid || !activation_code || !old_id) {
      return res.json({
        code: 1,
        msg: 'unique_bios_uuid、激活码和设备标识(old_id)是必填项'
      });
    }

    conn = await mysql.createConnection(dbConfig);

    // 先检查激活码是否存在
    const [codeExists] = await conn.execute(`
      SELECT * FROM activation_codes 
      WHERE code = ?
    `, [activation_code]);

    if (codeExists.length === 0) {
      return res.json({
        code: 2,
        msg: '无效的激活码4'
      });
    }

    // 查询激活码记录，检查是否与原old_id匹配
    const [activationCodes] = await conn.execute(`
      SELECT * FROM activation_codes 
      WHERE code = ? 
      AND used_by = ?
      AND updated = 0
    `, [activation_code, old_id]);

    if (activationCodes.length === 0) {
      return res.json({
        code: 2,
        msg: '未找到匹配的激活码记录或激活码已被使用'
      });
    }

    const activationCodeRecord = activationCodes[0];

    // 计算新的到期时间（移到这里）
    newExpireAt = new Date(activationCodeRecord.used_at.getTime() + activationCodeRecord.days * 24 * 60 * 60 * 1000);
    logger.info('[seven] 计算新的到期时间:', {
      newExpireAt
    });
    // 查找原会员记录以获取有效期信息
    const [members] = await conn.execute(`
      SELECT * FROM members 
      WHERE (device_id = ? AND device_id != '') 
      OR (BIOS_UUID = ? AND BIOS_UUID != '')
    `, [old_id, old_id]);

    // 如果没有找到原会员记录，则检查 unique_bios_uuid 是否存在
    const [existingNewMembers] = await conn.execute(`
            SELECT * FROM members 
            WHERE BIOS_UUID = ?
          `, [unique_bios_uuid]);

    if (existingNewMembers.length === 0) {
        // 如果没有找到原会员记录，则创建新会员
        await conn.execute(`
        INSERT INTO members (
          BIOS_UUID,
          activated_at,
          expire_at,
          created_at,
          old_id
        ) VALUES (
          ?,
          ?,
          ?,
          NOW(),
          ? 
        )
      `, [
          unique_bios_uuid,
          activationCodeRecord.used_at,
          newExpireAt,
          old_id  // 传入 old_id
        ]);
      } else {
        const memberRecord = members[0];

        // 检查 memberRecord 是否有效
        if (!memberRecord) {
          logger.warn('[Create Member From Activation] 未找到会员记录:', {
            unique_bios_uuid,
            old_id,
            activation_code
          });
          return res.json({
            code: 2,
            msg: '未找到会员记录'
          });
        }

        // 判断是否需要更新expire_at
        if (newExpireAt > memberRecord.expire_at) {
          await conn.execute(`
          UPDATE members 
          SET expire_at = ?,
              bios_uuid = ?
          WHERE id = ?
        `, [newExpireAt, unique_bios_uuid, memberRecord.id]);

          logger.info('[Create Member From Activation] 更新会员到期时间:', {
            unique_bios_uuid,
            old_id,
            activation_code,
            new_expire_at: newExpireAt
          });
        } else {
          logger.info('[Create Member From Activation] 不需要更新会员到期时间:', {
            unique_bios_uuid,
            old_id,
            activation_code,
            current_expire_at: memberRecord.expire_at,
            new_expire_at: newExpireAt
          });
        }
      }

      // 更新激活码记录
      const updateSql = `
        UPDATE activation_codes 
        SET updated = 1,
            old_id = ?,
            update_by = ?
        WHERE code = ?
      `;
      logger.info('[SEVEN--][Create Member From Activation] 执行 SQL:', { sql: updateSql, params: [old_id, unique_bios_uuid, activation_code] });
      await conn.execute(updateSql, [old_id, unique_bios_uuid, activation_code]);  // 传入 old_id

      logger.info('[Create Member From Activation] 创建或更新成功:', {
        unique_bios_uuid,
        old_id,
        activation_code,
        activated_at: activationCodeRecord.used_at,
        expire_at: newExpireAt
      });

      return res.json({
        code: 0,
        msg: '会员处理成功',
        data: {
          activated_at: activationCodeRecord.used_at,
          expire_at: newExpireAt
        }
      });

    } catch (err) {
      logger.error('[Create Member From Activation] 处理出错:', {
        error: err.message,
        stack: err.stack,
        request: {
          unique_bios_uuid: req.body.unique_bios_uuid,
          old_id: req.body.old_id,
          activation_code: req.body.activation_code
        }
      });
      res.status(500).json({ code: -1, msg: '服务器错误' });
    } finally {
      if (conn) {
        try {
          await conn.end();
        } catch (err) {
          logger.error('[Create Member From Activation] 关闭数据库连接出错:', err);
        }
      }
    }
  });

app.post('/api/check_device_recharge', async (req, res) => {
  let conn;
  try {
    const { id } = req.body;

    // 验证参数
    if (!id) {
      return res.json({ code: 1, msg: '设备ID是必填项' });
    }

    conn = await mysql.createConnection(dbConfig);

    // 查询充值次数超过2次的used_by列表
    const [rechargeDevices] = await conn.execute(`
      SELECT used_by 
      FROM activation_codes 
      GROUP BY used_by 
      HAVING COUNT(*) > 1
    `);

    // 提取设备ID列表
    const deviceIds = rechargeDevices.map(device => device.used_by);

    // 检查传入的ID是否在列表中
    const isExist = deviceIds.includes(id);

    return res.json({
      code: 0,
      isExist: isExist
    });

  } catch (err) {
    logger.error('[Check Device Recharge] 处理出错:', {
      error: err.message,
      stack: err.stack,
      request: {
        id: req.body.id
      }
    });
    res.status(500).json({ code: -1, msg: '服务器错误' });
  } finally {
    if (conn) {
      try {
        await conn.end();
      } catch (err) {
        logger.error('[Check Device Recharge] 关闭数据库连接出错:', err);
      }
    }
  }
});

// 添加检查激活码是否已使用的接口
app.post('/api/check_activation_code', async (req, res) => {
  const { activation_code } = req.body;

  // 参数验证
  if (!activation_code) {
    return res.json({ code: 1, msg: '激活码不能为空' });
  }

  let conn; // 在这里定义 conn
  try {
    conn = await mysql.createConnection(dbConfig);
    
    // 查询激活码信息，包括 used_at 和 days
    const [codes] = await conn.execute(
      'SELECT *, DATE_FORMAT(used_at, "%Y-%m-%d %H:%i:%s") as used_time FROM activation_codes WHERE code = ?',
      [activation_code]
    );

    // 检查 quota_activation_codes 表
    const [quotaCodes] = await conn.execute(
      'SELECT *, DATE_FORMAT(used_at, "%Y-%m-%d %H:%i:%s") as used_time FROM quota_activation_codes WHERE code = ?',
      [activation_code]
    );

    // 如果在 activation_codes 表中未找到激活码，检查 quota_activation_codes 表
    if (codes.length === 0 && quotaCodes.length === 0) {
      return res.json({ code: 3, msg: '无效的激活码' });
    }

    // 如果在 activation_codes 表中找到激活码
    if (codes.length > 0) {
      const code = codes[0];
      // 返回激活码信息，包括 used_at 和 days
      return res.json({
        code: 0,
        msg: '激活码有效',
        data: {
          used: code.used,
          used_time: code.used_time,
          days: code.days
        }
      });
    }

    // 如果在 quota_activation_codes 表中找到激活码
    if (quotaCodes.length > 0) {
      const quotaCode = quotaCodes[0];
      // 返回激活码信息，包括 used_at 和 days
      return res.json({
        code: 0,
        msg: '额度激活码有效',
        data: {
          used: quotaCode.used,
          used_time: quotaCode.used_time,
          quota: quotaCode.quota
        }
      });
    }

  } catch (err) {
    logger.error('检查激活码出错:', {
      error: err.message,
      stack: err.stack,
      request: {
        activation_code
      }
    });
    return res.json({ code: -1, msg: '服务器错误' });
  } finally {
    if (conn) {
      try {
        await conn.end(); // 确保关闭连接
      } catch (err) {
        logger.error('关闭数据库连接出错:', err);
      }
    }
  }
});