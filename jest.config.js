module.exports = {
  testEnvironment: 'node',
  testMatch: ['**/tests/**/*.test.js'],
  collectCoverageFrom: ['src/utils/**/*.js', 'src/routes/**/*.js'],
  // Routes open Redis/DNS handles; keep the runner from hanging on a stray socket.
  testTimeout: 15000,
  clearMocks: true,
};
