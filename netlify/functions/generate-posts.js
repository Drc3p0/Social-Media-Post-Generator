// In-memory rate limiting storage (for demo - use Redis/DB for production)
const rateLimits = new Map();
const contentHistory = new Map();

// Rate limiting configuration
const REQUESTS_PER_WINDOW = 5;
const WINDOW_MINUTES = 5;
const DAILY_LIMIT = 20;
const MIN_POST_LENGTH = 10;
const MAX_POST_LENGTH = 2000;
const COOLDOWN_SECONDS = 30;

// Clean up old entries periodically
function cleanupRateLimits() {
  const now = Date.now();
  const windowStart = now - (WINDOW_MINUTES * 60 * 1000);
  const dayStart = now - (24 * 60 * 60 * 1000);
  
  for (const [ip, data] of rateLimits.entries()) {
    // Clean old requests
    data.requests = data.requests.filter(time => time > windowStart);
    data.dailyRequests = data.dailyRequests.filter(time => time > dayStart);
    
    // Remove empty entries
    if (data.requests.length === 0 && data.dailyRequests.length === 0) {
      rateLimits.delete(ip);
    }
  }
}

// Check for suspicious content patterns
function isSpamContent(content) {
  // Check for repeated characters (more than 10 in a row)
  if (/(.)\1{10,}/.test(content)) return true;
  
  // Check for excessive uppercase (more than 70%)
  const upperCount = (content.match(/[A-Z]/g) || []).length;
  if (upperCount / content.length > 0.7) return true;
  
  // Check for common spam patterns
  const spamPatterns = [
    /(.{1,20})\1{5,}/i, // Repeated phrases
    /^[^a-zA-Z0-9\s]{50,}$/, // Too many special characters
    /test{5,}/i, // Testing patterns
  ];
  
  return spamPatterns.some(pattern => pattern.test(content));
}

// Check content similarity with recent submissions
function isDuplicateContent(ip, content) {
  const normalizedContent = content.toLowerCase().replace(/\s+/g, ' ').trim();
  
  if (!contentHistory.has(ip)) {
    contentHistory.set(ip, []);
  }
  
  const userHistory = contentHistory.get(ip);
  const now = Date.now();
  const hourAgo = now - (60 * 60 * 1000);
  
  // Clean old history
  const recentHistory = userHistory.filter(entry => entry.time > hourAgo);
  contentHistory.set(ip, recentHistory);
  
  // Check for duplicates (90% similarity)
  for (const entry of recentHistory) {
    const similarity = calculateSimilarity(normalizedContent, entry.content);
    if (similarity > 0.9) return true;
  }
  
  // Add current content to history
  recentHistory.push({ content: normalizedContent, time: now });
  
  return false;
}

// Simple similarity calculation
function calculateSimilarity(str1, str2) {
  const longer = str1.length > str2.length ? str1 : str2;
  const shorter = str1.length > str2.length ? str2 : str1;
  
  if (longer.length === 0) return 1.0;
  
  const editDistance = levenshteinDistance(longer, shorter);
  return (longer.length - editDistance) / longer.length;
}

// Levenshtein distance calculation
function levenshteinDistance(str1, str2) {
  const matrix = [];
  
  for (let i = 0; i <= str2.length; i++) {
    matrix[i] = [i];
  }
  
  for (let j = 0; j <= str1.length; j++) {
    matrix[0][j] = j;
  }
  
  for (let i = 1; i <= str2.length; i++) {
    for (let j = 1; j <= str1.length; j++) {
      if (str2.charAt(i - 1) === str1.charAt(j - 1)) {
        matrix[i][j] = matrix[i - 1][j - 1];
      } else {
        matrix[i][j] = Math.min(
          matrix[i - 1][j - 1] + 1,
          matrix[i][j - 1] + 1,
          matrix[i - 1][j] + 1
        );
      }
    }
  }
  
  return matrix[str2.length][str1.length];
}

exports.handler = async (event, context) => {
  // Clean up old rate limit entries
  cleanupRateLimits();
  
  // Only allow POST requests
  if (event.httpMethod !== 'POST') {
    return {
      statusCode: 405,
      body: JSON.stringify({ error: 'Method not allowed' })
    };
  }

  // Get client IP
  const clientIP = event.headers['client-ip'] || 
                  event.headers['x-forwarded-for']?.split(',')[0] || 
                  event.headers['x-real-ip'] || 
                  'unknown';

  // Validate referrer (only allow requests from your domain)
  const referrer = event.headers.referer || event.headers.origin;
  const allowedDomains = [
    'https://social-post-generator.netlify.app',
    'http://localhost:3000', // For development
    'http://127.0.0.1:3000'  // For development
  ];
  
  if (referrer && !allowedDomains.some(domain => referrer.startsWith(domain))) {
    return {
      statusCode: 403,
      body: JSON.stringify({ error: 'Invalid referrer' })
    };
  }

  // Check User-Agent for obvious bots
  const userAgent = event.headers['user-agent'] || '';
  const botPatterns = ['curl', 'wget', 'python', 'bot', 'crawler', 'spider'];
  if (botPatterns.some(pattern => userAgent.toLowerCase().includes(pattern))) {
    return {
      statusCode: 403,
      body: JSON.stringify({ error: 'Automated requests not allowed' })
    };
  }

  try {
    const { prompt } = JSON.parse(event.body);
    
    if (!prompt) {
      return {
        statusCode: 400,
        body: JSON.stringify({ error: 'Prompt is required' })
      };
    }

    // Input validation
    if (typeof prompt !== 'string') {
      return {
        statusCode: 400,
        body: JSON.stringify({ error: 'Invalid prompt format' })
      };
    }

    if (prompt.length < MIN_POST_LENGTH) {
      return {
        statusCode: 400,
        body: JSON.stringify({ error: `Prompt too short. Minimum ${MIN_POST_LENGTH} characters.` })
      };
    }

    if (prompt.length > MAX_POST_LENGTH) {
      return {
        statusCode: 400,
        body: JSON.stringify({ error: `Prompt too long. Maximum ${MAX_POST_LENGTH} characters.` })
      };
    }

    // Extract original post from prompt for content analysis
    const originalPostMatch = prompt.match(/Original post: "(.*?)"/);
    const originalPost = originalPostMatch ? originalPostMatch[1] : prompt;

    // Check for spam content
    if (isSpamContent(originalPost)) {
      return {
        statusCode: 400,
        body: JSON.stringify({ error: 'Content appears to be spam' })
      };
    }

    // Check for duplicate content
    if (isDuplicateContent(clientIP, originalPost)) {
      return {
        statusCode: 429,
        body: JSON.stringify({ error: 'Similar content submitted recently. Please wait before trying again.' })
      };
    }

    // Rate limiting logic
    const now = Date.now();
    const windowStart = now - (WINDOW_MINUTES * 60 * 1000);
    const dayStart = now - (24 * 60 * 60 * 1000);
    
    if (!rateLimits.has(clientIP)) {
      rateLimits.set(clientIP, {
        requests: [],
        dailyRequests: [],
        lastRequest: 0
      });
    }
    
    const userLimits = rateLimits.get(clientIP);
    
    // Check cooldown period
    if (now - userLimits.lastRequest < COOLDOWN_SECONDS * 1000) {
      const remainingSeconds = Math.ceil((COOLDOWN_SECONDS * 1000 - (now - userLimits.lastRequest)) / 1000);
      return {
        statusCode: 429,
        headers: {
          "Content-Type": "application/json",
          "Access-Control-Allow-Origin": "*"
        },
        body: JSON.stringify({ 
          error: `Please wait ${remainingSeconds} seconds before making another request`,
          retryAfter: remainingSeconds
        })
      };
    }
    
    // Clean old requests
    userLimits.requests = userLimits.requests.filter(time => time > windowStart);
    userLimits.dailyRequests = userLimits.dailyRequests.filter(time => time > dayStart);
    
    // Check rate limits
    if (userLimits.requests.length >= REQUESTS_PER_WINDOW) {
      return {
        statusCode: 429,
        headers: {
          "Content-Type": "application/json",
          "Access-Control-Allow-Origin": "*"
        },
        body: JSON.stringify({ 
          error: `Rate limit exceeded. Maximum ${REQUESTS_PER_WINDOW} requests per ${WINDOW_MINUTES} minutes.`,
          retryAfter: Math.ceil((WINDOW_MINUTES * 60))
        })
      };
    }
    
    if (userLimits.dailyRequests.length >= DAILY_LIMIT) {
      return {
        statusCode: 429,
        headers: {
          "Content-Type": "application/json",
          "Access-Control-Allow-Origin": "*"
        },
        body: JSON.stringify({ 
          error: `Daily limit exceeded. Maximum ${DAILY_LIMIT} requests per day.`,
          retryAfter: Math.ceil((24 * 60 * 60))
        })
      };
    }

    // Record the request
    userLimits.requests.push(now);
    userLimits.dailyRequests.push(now);
    userLimits.lastRequest = now;

    // Call Claude API with the secret key (stored as environment variable)
    const response = await fetch("https://api.anthropic.com/v1/messages", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "x-api-key": process.env.CLAUDE_API_KEY,
        "anthropic-version": "2023-06-01"
      },
      body: JSON.stringify({
        model: "claude-sonnet-4-20250514",
        max_tokens: 2000,
        messages: [
          { role: "user", content: prompt }
        ]
      })
    });

    if (!response.ok) {
      // Don't decrement counters on API failures
      userLimits.requests.pop();
      userLimits.dailyRequests.pop();
      throw new Error(`Claude API error: ${response.status}`);
    }

    const data = await response.json();
    
    return {
      statusCode: 200,
      headers: {
        "Content-Type": "application/json",
        "Access-Control-Allow-Origin": "*",
        "Access-Control-Allow-Headers": "Content-Type",
        "Access-Control-Allow-Methods": "POST, OPTIONS"
      },
      body: JSON.stringify({
        success: true,
        content: data.content[0].text,
        rateLimitRemaining: REQUESTS_PER_WINDOW - userLimits.requests.length,
        dailyRemaining: DAILY_LIMIT - userLimits.dailyRequests.length
      })
    };

  } catch (error) {
    console.error('Error:', error);
    return {
      statusCode: 500,
      headers: {
        "Content-Type": "application/json",
        "Access-Control-Allow-Origin": "*"
      },
      body: JSON.stringify({
        success: false,
        error: 'Failed to process request'
      })
    };
  }
};
