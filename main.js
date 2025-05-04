const axios = require('axios');
const fs = require('fs');
const path = require('path');
const moment = require('moment');
const readline = require('readline');
const { clear } = require('console');
const { HttpsProxyAgent } = require('https-proxy-agent');
const { SocksProxyAgent } = require('socks-proxy-agent');
const https = require('https');

const API_BASE_URL = 'https://prod.interlinklabs.ai/api/v1';
const TOKEN_FILE_PATH = path.join(__dirname, 'token.txt');
const PROXIES_FILE_PATH = path.join(__dirname, 'proxy.txt');
const CLAIM_INTERVAL_MS = 4 * 60 * 60 * 1000; 

const colors = {
  green: '\x1b[32m',
  yellow: '\x1b[33m',
  red: '\x1b[31m',
  white: '\x1b[37m',
  gray: '\x1b[90m',
  cyan: '\x1b[36m',
  reset: '\x1b[0m',
  bold: '\x1b[1m'
};

const logger = {
  info: (msg) => console.log(`${colors.green}[✓] ${msg}${colors.reset}`),
  warn: (msg) => console.log(`${colors.yellow}[⚠] ${msg}${colors.reset}`),
  error: (msg) => console.log(`${colors.red}[✗] ${msg}${colors.reset}`),
  success: (msg) => console.log(`${colors.green}[✅] ${msg}${colors.reset}`),
  loading: (msg) => console.log(`${colors.cyan}[⟳] ${msg}${colors.reset}`),
  step: (msg) => console.log(`${colors.white}[➤] ${msg}${colors.reset}`),
  banner: () => {
    console.log(`${colors.cyan}${colors.bold}`);
    console.log(`---------------------------------------------`);
    console.log(`    Interlink Bot - Airdrop Script FA    `);
    console.log(`---------------------------------------------${colors.reset}`);
    console.log();
  }
};

const rl = readline.createInterface({
  input: process.stdin,
  output: process.stdout
});

function promptInput(question) {
  return new Promise((resolve) => {
    rl.question(`${colors.white}${question}${colors.reset}`, (answer) => {
      resolve(answer.trim());
    });
  });
}

function readToken() {
  try {
    return fs.readFileSync(TOKEN_FILE_PATH, 'utf8').trim();
  } catch (error) {
    logger.warn(`Token file not found or invalid. Will attempt login.`);
    return null;
  }
}

function saveToken(token) {
  try {
    fs.writeFileSync(TOKEN_FILE_PATH, token);
    logger.info(`Token saved to ${TOKEN_FILE_PATH}`);
  } catch (error) {
    logger.error(`Error saving token: ${error.message}`);
  }
}

function readProxies() {
  try {
    if (!fs.existsSync(PROXIES_FILE_PATH)) {
      logger.warn(`Proxies file not found. Running without proxies.`);
      return [];
    }
    const content = fs.readFileSync(PROXIES_FILE_PATH, 'utf8');
    return content.split('\n')
      .map(line => line.trim())
      .filter(line => line && !line.startsWith('#'))
      .map(line => {
        if (!line.match(/^(http|socks[45]):\/\//)) {
          return `http://${line}`;
        }
        return line;
      });
  } catch (error) {
    logger.error(`Error reading proxies file: ${error.message}`);
    return [];
  }
}

function getRandomProxy(proxies, failedProxies = new Set()) {
  const availableProxies = proxies.filter(p => !failedProxies.has(p));
  if (!availableProxies.length) return null;
  return availableProxies[Math.floor(Math.random() * availableProxies.length)];
}

function createProxyAgent(proxyUrl) {
  if (!proxyUrl) return null;
  try {
    if (proxyUrl.startsWith('socks')) {
      return new SocksProxyAgent(proxyUrl);
    } else {
      return new HttpsProxyAgent(proxyUrl);
    }
  } catch (error) {
    logger.error(`Failed to create proxy agent for ${proxyUrl}: ${error.message}`);
    return null;
  }
}

function createApiClient(token = null, proxy = null) {
  const config = {
    baseURL: API_BASE_URL,
    headers: {
      'User-Agent': 'okhttp/4.12.0',
      'Accept-Encoding': 'gzip',
      'Content-Type': 'application/json'
    },
    timeout: 30000,
    httpsAgent: new https.Agent({
      rejectUnauthorized: false,
      minVersion: 'TLSv1.2',
      maxVersion: 'TLSv1.3'
    })
  };
  if (token) {
    config.headers['Authorization'] = `Bearer ${token}`;
  }
  if (proxy) {
    const proxyAgent = createProxyAgent(proxy);
    if (proxyAgent) {
      config.httpsAgent = proxyAgent;
      config.proxy = false;
      logger.info(`Using proxy: ${proxy}`);
    } else {
      logger.warn(`Failed to set up proxy ${proxy}. Proceeding without proxy.`);
    }
  }
  return axios.create(config);
}

async function sendOtp(apiClient, loginId, passcode, email) {
  try {
    const payload = {
      loginId: loginId,
      passcode: passcode,
      email: email
    };
    const response = await apiClient.post('/auth/send-otp-email-verify-login', payload);
    if (response.data.statusCode === 200) {
      logger.success(response.data.message);
      logger.info(`If OTP doesn't arrive, stop the bot (Ctrl+C) and restart.`);
    } else {
      logger.error(`Failed to send OTP: ${JSON.stringify(response.data)}`);
    }
  } catch (error) {
    logger.error(`Error sending OTP: ${error.response?.data?.message || error.message}`);
    if (error.response?.data) {
      logger.error(`Response details: ${JSON.stringify(error.response.data)}`);
    }
  }
}

async function verifyOtp(apiClient, loginId, otp) {
  try {
    const payload = {
      loginId: loginId,
      otp: otp
    };
    const response = await apiClient.post('/auth/check-otp-email-verify-login', payload);
    if (response.data.statusCode === 200) {
      logger.success(response.data.message);
      const token = response.data.data.jwtToken;
      saveToken(token);
      return token;
    } else {
      logger.error(`Failed to verify OTP: ${JSON.stringify(response.data)}`);
      return null;
    }
  } catch (error) {
    logger.error(`Error verifying OTP: ${error.response?.data?.message || error.message}`);
    if (error.response?.data) {
      logger.error(`Response details: ${JSON.stringify(error.response.data)}`);
    }
    return null;
  }
}

async function login(proxies) {
  const loginId = await promptInput('Enter your login ID (or email): ');
  const passcode = await promptInput('Enter your passcode: ');
  const email = await promptInput('Enter your email: ');
  
  let apiClient;
  let proxy = getRandomProxy(proxies);

  if (proxy) {
    logger.step(`Attempting to send OTP with proxy: ${proxy}`);
    apiClient = createApiClient(null, proxy);
    await sendOtp(apiClient, loginId, passcode, email);
  }

  if (!proxy || !apiClient) {
    logger.step(`Attempting to send OTP without proxy...`);
    apiClient = createApiClient(null);
    await sendOtp(apiClient, loginId, passcode, email);
  }
  
  const otp = await promptInput('Enter OTP: ');
  const token = await verifyOtp(apiClient, loginId, otp);
  
  return token;
}

function formatTimeRemaining(milliseconds) {
  try {
    if (milliseconds <= 0) return '00:00:00';
    const seconds = Math.floor((milliseconds / 1000) % 60);
    const minutes = Math.floor((milliseconds / (1000 * 60)) % 60);
    const hours = Math.floor((milliseconds / (1000 * 60 * 60)) % 24);
    return [hours, minutes, seconds]
      .map(val => val.toString().padStart(2, '0'))
      .join(':');
  } catch (error) {
    logger.error(`Error formatting time: ${error.message}`);
    return '00:00:00';
  }
}

async function getCurrentUser(apiClient) {
  try {
    const response = await apiClient.get('/auth/current-user');
    return response.data.data;
  } catch (error) {
    if (error.response?.status === 401) {
      throw new Error('Token expired');
    }
    logger.error(`Error getting user information: ${error.response?.data?.message || error.message}`);
    return null;
  }
}

async function getTokenBalance(apiClient) {
  try {
    const response = await apiClient.get('/token/get-token');
    return response.data.data;
  } catch (error) {
    if (error.response?.status === 401) {
      throw new Error('Token expired');
    }
    logger.error(`Error getting token balance: ${error.response?.data?.message || error.message}`);
    return null;
  }
}

async function checkIsClaimable(apiClient) {
  try {
    const response = await apiClient.get('/token/check-is-claimable');
    return response.data.data;
  } catch (error) {
    if (error.response?.status === 401) {
      throw new Error('Token expired');
    }
    logger.error(`Error checking if airdrop is claimable: ${error.message}`);
    return { isClaimable: false, nextFrame: Date.now() + 1000 * 60 * 5 };
  }
}

async function claimAirdrop(apiClient) {
  try {
    const response = await apiClient.post('/token/claim-airdrop');
    logger.success(`Airdrop claimed successfully!`);
    return response.data;
  } catch (error) {
    if (error.response?.status === 401) {
      throw new Error('Token expired');
    }
    logger.error(`Error claiming airdrop: ${error.response?.data?.message || error.message}`);
    return null;
  }
}

function displayUserInfo(userInfo, tokenInfo) {
  if (!userInfo || !tokenInfo) return;
  console.log('\n' + '='.repeat(50));
  console.log(`${colors.yellow}${colors.bold}👤 USER INFORMATION${colors.reset}`);
  console.log(`${colors.yellow}Username:${colors.reset} ${userInfo.username}`);
  console.log(`${colors.yellow}Email:${colors.reset} ${userInfo.email}`);
  console.log(`${colors.yellow}Wallet:${colors.reset} ${userInfo.connectedAccounts.wallet.address}`);
  console.log(`${colors.yellow}User ID:${colors.reset} ${userInfo.loginId}`);
  console.log(`${colors.yellow}Referral ID:${colors.reset} ${tokenInfo.userReferralId}`);
  console.log('\n' + '='.repeat(50));
  console.log(`${colors.yellow}${colors.bold}💰 TOKEN BALANCE${colors.reset}`);
  console.log(`${colors.yellow}Gold Tokens:${colors.reset} ${tokenInfo.interlinkGoldTokenAmount}`);
  console.log(`${colors.yellow}Silver Tokens:${colors.reset} ${tokenInfo.interlinkSilverTokenAmount}`);
  console.log(`${colors.yellow}Diamond Tokens:${colors.reset} ${tokenInfo.interlinkDiamondTokenAmount}`);
  console.log(`${colors.yellow}Interlink Tokens:${colors.reset} ${tokenInfo.interlinkTokenAmount}`);
  console.log(`${colors.yellow}Last Claim:${colors.reset} ${moment(tokenInfo.lastClaimTime).format('YYYY-MM-DD HH:mm:ss')}`);
  console.log('='.repeat(50) + '\n');
}

async function tryConnect(token, proxies) {
  let apiClient;
  let userInfo = null;
  let tokenInfo = null;
  const failedProxies = new Set();

  logger.step(`Attempting connection without proxy...`);
  apiClient = createApiClient(token);
  
  logger.loading(`Retrieving user information...`);
  userInfo = await getCurrentUser(apiClient);

  if (!userInfo && proxies.length > 0) {
    let attempts = 0;
    const maxAttempts = Math.min(proxies.length, 5);
    
    while (!userInfo && attempts < maxAttempts) {
      const proxy = getRandomProxy(proxies, failedProxies);
      if (!proxy) {
        logger.warn(`No more proxies available.`);
        break;
      }
      
      logger.step(`Trying with proxy ${attempts + 1}/${maxAttempts}: ${proxy}`);
      apiClient = createApiClient(token, proxy);
      
      logger.loading(`Retrieving user information...`);
      userInfo = await getCurrentUser(apiClient);
      
      if (!userInfo) {
        logger.warn(`Proxy ${proxy} failed. Marking as failed and trying next...`);
        failedProxies.add(proxy);
      }
      attempts++;
    }
  }
  
  if (userInfo) {
    logger.loading(`Retrieving token balance...`);
    tokenInfo = await getTokenBalance(apiClient);
  }
  
  return { apiClient, userInfo, tokenInfo };
}

async function runBot() {
  try {
    clear();
    logger.banner();

    const proxies = readProxies();
    let token = readToken();

    if (!token) {
      logger.step(`No token found. Initiating login...`);
      token = await login(proxies);
      if (!token) {
        logger.error(`Login failed. Exiting.`);
        process.exit(1);
      }
    }

    let { apiClient, userInfo, tokenInfo: initialTokenInfo } = await tryConnect(token, proxies);
    
    if (!userInfo || !initialTokenInfo) {
      logger.error(`Failed to retrieve necessary information. Attempting login...`);
      token = await login(proxies);
      if (!token) {
        logger.error(`Login failed. Exiting.`);
        process.exit(1);
      }
      const result = await tryConnect(token, proxies);
      apiClient = result.apiClient;
      userInfo = result.userInfo;
      initialTokenInfo = result.tokenInfo;
      if (!userInfo || !initialTokenInfo) {
        logger.error(`Failed to retrieve necessary information after login. Check your credentials and proxies.`);
        process.exit(1);
      }
    }

    let tokenInfo = initialTokenInfo;
    const failedProxies = new Set();

    logger.success(`Connected as ${userInfo.username}`);
    logger.info(`Started at: ${moment().format('YYYY-MM-DD HH:mm:ss')}`);
    
    displayUserInfo(userInfo, tokenInfo);

    async function attemptClaim() {
      let currentApiClient = apiClient;
      let usedProxy = null;
      let claimCheck = null;

      try {
        logger.step(`Checking if airdrop is claimable without proxy...`);
        claimCheck = await checkIsClaimable(currentApiClient);
      } catch (error) {
        if (error.message === 'Token expired') {
          logger.warn(`Token expired. Initiating re-login...`);
          token = await login(proxies);
          if (!token) {
            logger.error(`Re-login failed. Using default retry time.`);
            return { isClaimable: false, nextFrame: Date.now() + 1000 * 60 * 5 };
          }
          currentApiClient = createApiClient(token);
          apiClient = currentApiClient; 
          claimCheck = await checkIsClaimable(currentApiClient);
        } else {
          logger.error(`Claim check failed without proxy: ${error.message}`);
        }
      }

      if (!claimCheck && proxies.length > 0) {
        let attempts = 0;
        const maxAttempts = Math.min(proxies.length, 3);
        
        while (!claimCheck && attempts < maxAttempts) {
          usedProxy = getRandomProxy(proxies, failedProxies);
          if (!usedProxy) {
            logger.warn(`No more proxies available.`);
            break;
          }
          
          logger.step(`Checking if airdrop is claimable with proxy ${usedProxy}...`);
          currentApiClient = createApiClient(token, usedProxy);
          
          try {
            claimCheck = await checkIsClaimable(currentApiClient);
          } catch (error) {
            if (error.message === 'Token expired') {
              logger.warn(`Token expired. Initiating re-login...`);
              token = await login(proxies);
              if (!token) {
                logger.error(`Re-login failed. Using default retry time.`);
                return { isClaimable: false, nextFrame: Date.now() + 1000 * 60 * 5 };
              }
              currentApiClient = createApiClient(token, usedProxy);
              apiClient = createApiClient(token); 
              claimCheck = await checkIsClaimable(currentApiClient);
            } else {
              logger.error(`Claim check failed with proxy ${usedProxy}: ${error.message}`);
              failedProxies.add(usedProxy);
            }
          }
          attempts++;
        }
      }

      if (!claimCheck) {
        logger.warn(`All attempts failed. Using default retry time.`);
        return { isClaimable: false, nextFrame: Date.now() + 1000 * 60 * 5 };
      }
      
      if (claimCheck.isClaimable) {
        logger.loading(`Airdrop is claimable! Attempting to claim...`);
        try {
          await claimAirdrop(currentApiClient);
          logger.loading(`Updating token information...`);
          const newTokenInfo = await getTokenBalance(currentApiClient);
          if (newTokenInfo) {
            tokenInfo = newTokenInfo;
            displayUserInfo(userInfo, tokenInfo);
          }
        } catch (error) {
          if (error.message === 'Token expired') {
            logger.warn(`Token expired during claim. Initiating re-login...`);
            token = await login(proxies);
            if (!token) {
              logger.error(`Re-login failed. Using default retry time.`);
              return { isClaimable: false, nextFrame: Date.now() + 1000 * 60 * 5 };
            }
            currentApiClient = createApiClient(token, usedProxy);
            apiClient = createApiClient(token); 
            await claimAirdrop(currentApiClient);
            const newTokenInfo = await getTokenBalance(currentApiClient);
            if (newTokenInfo) {
              tokenInfo = newTokenInfo;
              displayUserInfo(userInfo, tokenInfo);
            }
          } else {
            logger.error(`Claim failed: ${error.message}`);
          }
        }
      }
      
      return claimCheck.nextFrame;
    }

    logger.step(`Checking if airdrop is claimable...`);
    let nextClaimTime = await attemptClaim();

    const updateCountdown = () => {
      const now = Date.now();
      const timeRemaining = Math.max(0, nextClaimTime - now);
      
      process.stdout.write(`\r${colors.white}⏱️ Next claim in: ${colors.bold}${formatTimeRemaining(timeRemaining)}${colors.reset}     `);
      
      if (timeRemaining <= 0) {
        process.stdout.write('\n');
        logger.step(`Claim time reached!`);
        
        attemptClaim().then(newNextFrame => {
          nextClaimTime = newNextFrame;
        });
      }
    };

    setInterval(updateCountdown, 1000);

    const scheduleNextCheck = () => {
      const now = Date.now();
      const timeUntilNextCheck = Math.max(1000, nextClaimTime - now);
      
      setTimeout(async () => {
        logger.step(`Scheduled claim time reached.`);
        nextClaimTime = await attemptClaim();
        scheduleNextCheck();
      }, timeUntilNextCheck);
    };

    scheduleNextCheck();
    
    logger.success(`Bot is running! Airdrop claims will be attempted automatically.\n`);
    
  } catch (error) {
    logger.error(`Unexpected error: ${error.message}`);
    process.exit(1);
  }
}

runBot().finally(() => rl.close());
