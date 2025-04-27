// jest.setup.js
// 在 Node.js 环境下提供全局 crypto 对象
// import { webcrypto } from 'node:crypto'; // 改为 require
const { webcrypto } = require('node:crypto');

global.crypto = webcrypto; 