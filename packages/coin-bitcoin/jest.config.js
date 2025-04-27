/** @type {import('ts-jest').JestConfigWithTsJest} */
module.exports = {
  // preset: 'ts-jest', // 移除 preset
  testEnvironment: 'node',
  transform: { // 添加 transform
    '^.+\.tsx?$': ['ts-jest', {
      tsconfig: 'tsconfig.json',
      useESM: false, // 确保 ts-jest 输出 CJS
    }],
  },
  transformIgnorePatterns: [
    // 现在所有有问题的依赖都通过 moduleNameMapper 解决
    // 可以恢复默认忽略 node_modules
    '/node_modules/',
  ],
  moduleNameMapper: {
    // '^(\.{1,2}/.*)\.js$': '$1',
    // 添加 @juanelas/base64 的映射
    '^@juanelas/base64$': '<rootDir>/../../../../node_modules/.pnpm/@juanelas+base64@1.1.5/node_modules/@juanelas/base64/dist/cjs/index.node.js',
    // 添加 @okxweb3/crypto-lib 的映射
    '^@okxweb3/crypto-lib$': '<rootDir>/../../../../node_modules/.pnpm/@okxweb3+crypto-lib@1.0.11/node_modules/@okxweb3/crypto-lib/dist/index.js',
    // 恢复 bigint-conversion 的映射，明确指向 CJS 版本
    '^bigint-conversion$': '<rootDir>/../../../../node_modules/.pnpm/bigint-conversion@2.4.3/node_modules/bigint-conversion/dist/cjs/index.node.js',
    // 添加 bigint-crypto-utils 的映射
    '^bigint-crypto-utils$': '<rootDir>/../../../../node_modules/.pnpm/bigint-crypto-utils@3.3.0/node_modules/bigint-crypto-utils/dist/index.node.cjs',
    // 如果还有其他 ESM 包导致问题，也需要在这里添加映射
    // '^another-esm-pkg$': '<rootDir>/node_modules/another-esm-pkg/dist/cjs/index.js',
  },
  setupFilesAfterEnv: ['<rootDir>/jest.setup.js'], // 添加 setup 文件
};