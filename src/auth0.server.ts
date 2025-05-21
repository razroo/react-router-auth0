import axios from 'axios';
import dotenv from 'dotenv';
import type { TokenInfo, User } from './types/User';
import { commitSession, getSession } from './sessions.server';
import { environment } from '~/config/environment';

// Load environment variables
dotenv.config();

// Destructure and validate required Auth0 configuration
if (!environment.auth0.domain) throw new Error('Missing Auth0 domain.');
if (!environment.auth0.clientId) throw new Error('Missing Auth0 client id.');
if (!environment.auth0.clientSecret) throw new Error('Missing Auth0 client secret.');
if (!environment.auth0.callbackURL) throw new Error('Missing Auth0 callback url.');
if (!environment.auth0.audience) throw new Error('Missing Auth0 audience.');

// Object containing Auth0 configuration values
const auth0Config = {
  clientId: environment.auth0.clientId,
  clientSecret: environment.auth0.clientSecret,
  domain: environment.auth0.domain,
  callbackUrl: environment.auth0.callbackURL,
  audience: environment.auth0.audience,
};

// Centralized logging function to control verbosity
function log(message: string, level: 'info' | 'error' | 'debug' = 'info') {
  switch (level) {
    case 'error':
      console.error(`[Auth0] [ERROR] ${message}`);
      break;
    case 'info':
      console.log(`[Auth0] [INFO] ${message}`);
      break;
    case 'debug':
      console.log(`[Auth0] [DEBUG] ${message}`);
      break;
  }
}

// Type for the Session object from getSession
type SessionObject = Awaited<ReturnType<typeof getSession>>;

export class Auth0Service {
  // Singleton instance
  private static instance: Auth0Service;
  // Axios instance for Auth0 API communication
  private auth0Api;
  // Base URL for Auth0 endpoints
  private auth0Url: string;
  // In-memory cache for tokens and user information
  private tokenCache: Map<string, TokenInfo>;
  // Cache time for user information (24 hours)
  private readonly USER_INFO_CACHE_TIME = 24 * 60 * 60 * 1000;
  // Near-expiration time buffer (5 minutes)
  private readonly TOKEN_EXPIRATION_BUFFER = 5 * 60 * 1000;
  // Rate limiting tracking
  private rateLimitFailures = 0;
  private readonly MAX_RATE_LIMIT_FAILURES = 3;

  /**
   * Private constructor to enforce singleton pattern
   * Initializes axios client and token cache
   */
  private constructor() {
    log('Service instance created', 'debug');
    this.auth0Url = `https://${auth0Config.domain}`;
    this.auth0Api = axios.create({
      baseURL: this.auth0Url,
      headers: {
        'Content-Type': 'application/json',
      },
    });
    this.tokenCache = new Map();
  }

  /**
   * Returns the singleton instance of Auth0Service
   * Creates it if it doesn't exist yet
   */
  static getInstance(): Auth0Service {
    if (!Auth0Service.instance) {
      Auth0Service.instance = new Auth0Service();
    }
    return Auth0Service.instance;
  }

  /**
   * Checks if cached user info has expired
   * @param timestamp - When the user info was cached
   * @returns true if expired, false otherwise
   */
  private isUserInfoExpired(timestamp?: number): boolean {
    if (!timestamp) return true;
    return Date.now() >= timestamp + this.USER_INFO_CACHE_TIME;
  }

  /**
   * Generates the URL for Auth0 login page
   * @param state - CSRF protection state parameter
   * @returns Full URL for Auth0 authorization endpoint
   */
  getLoginUrl(state: string): string {
    const params = new URLSearchParams({
      response_type: 'code',
      client_id: auth0Config.clientId,
      redirect_uri: auth0Config.callbackUrl,
      scope: 'openid profile email offline_access',
      state,
      audience: auth0Config.audience,
    });
    const loginUrl = `${this.auth0Url}/authorize?${params.toString()}`;
    log(`Generated login URL with state: ${state.substring(0, 8)}...`, 'debug');
    return loginUrl;
  }

  /**
   * Generates the URL for logging out of Auth0
   * @returns Full URL for Auth0 logout endpoint
   */
  getLogoutUrl(): string {
    const baseUrl = new URL(auth0Config.callbackUrl).origin;
    const returnTo = `${baseUrl}/auth/login`;
    const params = new URLSearchParams({
      client_id: auth0Config.clientId,
      returnTo: returnTo,
    });
    return `${this.auth0Url}/v2/logout?${params.toString()}`;
  }

  /**
   * Checks if a token is expired or about to expire
   * @param expiresAt - Token expiration timestamp
   * @returns true if token is expired or will expire soon
   */
  private isTokenExpired(expiresAt: number): boolean {
    const now = Date.now();
    const timeLeft = expiresAt - now;
    const expired = now >= expiresAt - this.TOKEN_EXPIRATION_BUFFER;

    if (expired) {
      log(`Token expired or will expire soon (${Math.round(timeLeft / 1000)}s remaining)`, 'debug');
    }
    return expired;
  }

  /**
   * Handles API errors and provides consistent error messages
   * @param error - The caught error
   * @param context - Additional context about the error
   * @throws Formatted error with context
   */
  private handleApiError(error: any, context: string): never {
    const errorMessage = error.response?.data?.error_description || error.message;
    const status = error.response?.status;

    log(`${context}: ${errorMessage}`, 'error');

    // Check for rate limiting (HTTP 429)
    if (status === 429) {
      this.rateLimitFailures++;
      log(`Rate limit hit. Failure count: ${this.rateLimitFailures}/${this.MAX_RATE_LIMIT_FAILURES}`, 'error');

      if (this.rateLimitFailures >= this.MAX_RATE_LIMIT_FAILURES) {
        throw new Error('RATE_LIMIT_EXCEEDED');
      }
    }

    throw new Error(`${context}: ${errorMessage}`);
  }

  /**
   * Exchanges an authorization code for access and refresh tokens
   * Also fetches user information
   * @param code - Authorization code from Auth0 redirect
   * @returns Object containing tokens, user info, and expiration
   */
  async exchangeCodeForToken(code: string): Promise<{
    accessToken: string;
    userInfo: User;
    refreshToken: string;
    expiresAt: number;
  }> {
    try {
      log(`Exchanging authorization code for token...`, 'debug');
      // Request tokens from Auth0
      const { data } = await this.auth0Api.post('/oauth/token', {
        grant_type: 'authorization_code',
        client_id: auth0Config.clientId,
        client_secret: auth0Config.clientSecret,
        code,
        redirect_uri: auth0Config.callbackUrl,
      });

      // Calculate when the token will expire
      const expiresAt = Date.now() + data.expires_in * 1000;
      log(`Token exchange successful, expires in ${data.expires_in}s`, 'debug');

      // Fetch user info using the access token
      const userInfo = await this.fetchUserInfo(data.access_token);
      log(`Retrieved user info for ${userInfo.email || userInfo.sub}`, 'debug');

      // Cache the token information
      const tokenInfo: TokenInfo = {
        accessToken: data.access_token,
        refreshToken: data.refresh_token,
        expiresAt,
        userInfo,
        userInfoTimestamp: Date.now(),
      };

      this.tokenCache.set(data.access_token, tokenInfo);
      return {
        accessToken: data.access_token,
        refreshToken: data.refresh_token,
        expiresAt,
        userInfo,
      };
    } catch (error: any) {
      this.handleApiError(error, 'Failed to exchange code for token');
    }
  }

  /**
   * Gets a new access token using a refresh token
   * @param refreshToken - The refresh token to use
   * @returns New token information including user details
   */
  private async refreshToken(refreshToken: string): Promise<TokenInfo> {
    try {
      log(`Refreshing token...`, 'debug');
      // Request a new access token using the refresh token
      // Use Auth0's built-in token rotation by not specifying token_type_hint
      const { data } = await this.auth0Api.post('/oauth/token', {
        grant_type: 'refresh_token',
        client_id: auth0Config.clientId,
        client_secret: auth0Config.clientSecret,
        refresh_token: refreshToken,
      });

      // With Auth0's built-in token rotation, a new refresh token is automatically issued
      // and the old one is invalidated, so no manual revocation is needed

      // Calculate expiration time
      const expiresAt = Date.now() + data.expires_in * 1000;
      log(`Token refresh successful, expires in ${data.expires_in}s`, 'debug');

      // Get user info with the new token
      const userInfo = await this.fetchUserInfo(data.access_token);

      // Create token info object
      const tokenInfo: TokenInfo = {
        accessToken: data.access_token,
        // Use the new refresh token provided by Auth0
        refreshToken: data.refresh_token || refreshToken,
        expiresAt,
        userInfo,
        userInfoTimestamp: Date.now(),
      };

      // Cache the new token info
      this.tokenCache.set(data.access_token, tokenInfo);
      return tokenInfo;
    } catch (error: any) {
      this.handleApiError(error, 'Failed to refresh token');
    }
  }

  /**
   * Fetches user information from Auth0
   * @param accessToken - Token to use for authentication
   * @returns User information object
   */
  private async fetchUserInfo(accessToken: string): Promise<User> {
    try {
      log(`Fetching user info...`, 'debug');
      // Call Auth0 userinfo endpoint
      const { data } = await this.auth0Api.get('/userinfo', {
        headers: { Authorization: `Bearer ${accessToken}` },
      });
      log(`User info retrieved for ${data.email || data.sub}`, 'debug');
      return data;
    } catch (error: any) {
      this.handleApiError(error, 'Failed to fetch user info');
    }
  }

  /**
   * Updates the session with token information
   * @param session - The session to update
   * @param tokenInfo - Token information to store in session
   * @returns Promise that resolves when session is committed
   */
  private async updateSession(session: SessionObject, tokenInfo: Partial<TokenInfo>): Promise<void> {
    if (tokenInfo.accessToken) {
      session.set('accessToken', tokenInfo.accessToken);
    }

    if (tokenInfo.refreshToken) {
      session.set('refreshToken', tokenInfo.refreshToken);
    }

    if (tokenInfo.userInfo) {
      session.set('user', tokenInfo.userInfo);
    }

    await commitSession(session);
    log(`Session updated with token info`, 'debug');
  }

  /**
   * Gets user information, using cache when possible
   * Will refresh tokens if necessary
   * @param accessToken - The access token
   * @param request - Optional request object for session handling
   * @returns User information
   */
  async getUserInfo(accessToken: string, request?: Request): Promise<User> {
    try {
      log(`Getting user info for token: ${accessToken.substring(0, 10)}...`, 'debug');
      // First strategy: Check in-memory cache for token information
      const cachedToken = this.tokenCache.get(accessToken);
      let sessionTokenInfo: Partial<TokenInfo> = {};
      let session: SessionObject | undefined;

      // Second strategy: If request is provided, try to get token info from session
      if (request) {
        session = await getSession(request.headers.get('Cookie'));
        const sessionUser = session.get('user');
        const sessionAccessToken = session.get('accessToken');
        const sessionRefreshToken = session.get('refreshToken');

        if (sessionUser && (sessionAccessToken || sessionRefreshToken)) {
          log(`Found user info in session for: ${sessionUser.email || sessionUser.sub}`, 'debug');
          sessionTokenInfo = {
            userInfo: sessionUser as User,
            accessToken: sessionAccessToken as string,
            refreshToken: sessionRefreshToken as string,
          };
        }
      }

      // Merge session info with cached info, prioritizing cache for freshness
      const tokenInfo = {
        ...(sessionTokenInfo || {}),
        ...(cachedToken || {}),
      };

      // If no token information is found, throw error
      if (!tokenInfo.accessToken && !tokenInfo.refreshToken && !tokenInfo.userInfo) {
        log(`No token or user info found in cache or session`, 'debug');
        throw new Error('No token information found');
      }

      // Check if token or user info is expired
      const isTokenExpired = tokenInfo.expiresAt ? this.isTokenExpired(tokenInfo.expiresAt) : true;
      const isUserInfoExpired = tokenInfo.userInfoTimestamp ? this.isUserInfoExpired(tokenInfo.userInfoTimestamp) : true;
      const cachedUserInfo = tokenInfo.userInfo;
      const tokenAccessToken = tokenInfo.accessToken;
      const tokenRefreshToken = tokenInfo.refreshToken;

      // Return cached user info if it's still valid
      if (!isTokenExpired && !isUserInfoExpired && cachedUserInfo) {
        log(`Using cached user info for: ${cachedUserInfo.email || cachedUserInfo.sub}`, 'debug');
        return cachedUserInfo;
      }

      // If we have a refresh token, use it to get new tokens
      if (tokenRefreshToken) {
        log(`Need to refresh token (expired=${isTokenExpired}, userInfoExpired=${isUserInfoExpired})`, 'debug');
        const newTokenInfo = await this.refreshToken(tokenRefreshToken);

        // Update session if available
        if (session && newTokenInfo) {
          await this.updateSession(session, {
            accessToken: newTokenInfo.accessToken,
            refreshToken: newTokenInfo.refreshToken,
            userInfo: newTokenInfo.userInfo
          });
        }

        if (!newTokenInfo.userInfo) {
          throw new Error('Failed to get user info after token refresh');
        }

        return newTokenInfo.userInfo;
      }

      // Fetch user info directly if no refresh token is available but we have an access token
      if (tokenAccessToken) {
        log(`No refresh token available, fetching user info directly with access token`, 'debug');
        const userInfo = await this.fetchUserInfo(tokenAccessToken);
        const updatedTokenInfo = {
          ...tokenInfo,
          accessToken: tokenAccessToken,
          userInfo,
          userInfoTimestamp: Date.now(),
        };

        // Update cache
        this.tokenCache.set(tokenAccessToken, updatedTokenInfo as TokenInfo);

        // Update session
        if (session) {
          await this.updateSession(session, { userInfo });
        }

        return userInfo;
      }

      throw new Error('No refresh token or access token available');
    } catch (error: any) {
      this.handleApiError(error, 'Failed to get user info');
    }
  }

  /**
   * Cleans the session by removing auth-related data
   * @param session - The session to clean
   * @returns Promise that resolves when session is committed
   */
  private async cleanSession(session: SessionObject): Promise<void> {
    session.unset('accessToken');
    session.unset('refreshToken');
    session.unset('user');
    await commitSession(session);
    log('Session cleaned', 'debug');
  }

  /**
   * Verifies if a session is valid
   * @param request - The request object containing session cookie
   * @returns true if session is valid, false otherwise
   */
  async verifySession(request: Request): Promise<boolean> {
    try {
      log(`Verifying session...`, 'debug');
      // Get session from request
      const session = await getSession(request.headers.get('Cookie'));
      const accessToken = session.get('accessToken') as string | undefined;
      const refreshToken = session.get('refreshToken') as string | undefined;
      const user = session.get('user');

      // If no access token and no refresh token, session is invalid
      if (!accessToken && !refreshToken) {
        log(`No tokens in session`, 'debug');
        await this.cleanSession(session);
        return false;
      }

      // First try to use access token
      if (accessToken) {
        try {
          log(`Verifying access token...`, 'debug');
          // Ensure token is in cache for future use if we have user info
          if (user && !this.tokenCache.has(accessToken)) {
            log(`Adding token to cache from session`, 'debug');
            this.tokenCache.set(accessToken, {
              accessToken,
              refreshToken: refreshToken || '',
              userInfo: user as User,
              expiresAt: Date.now() + 3600 * 1000, // Assume 1 hour validity
              userInfoTimestamp: Date.now(),
            });
          }

          // Try to get user info with access token
          const userInfo = await this.fetchUserInfo(accessToken);
          
          // Update user info in session if different
          if (JSON.stringify(userInfo) !== JSON.stringify(user)) {
            await this.updateSession(session, { userInfo });
          }
          
          // Reset rate limit failures on successful verification
          this.rateLimitFailures = 0;
          return true;
        } catch (error) {
          log(`Access token invalid, will try refresh token if available`, 'debug');
          // Continue to refresh token logic if access token fails
        }
      }

      // If we have a refresh token, try to refresh the session
      if (refreshToken) {
        try {
          log(`Using refresh token to renew session...`, 'debug');
          const newTokenInfo = await this.refreshToken(refreshToken);
          
          await this.updateSession(session, {
            accessToken: newTokenInfo.accessToken,
            refreshToken: newTokenInfo.refreshToken,
            userInfo: newTokenInfo.userInfo
          });
          
          // Reset rate limit failures on successful refresh
          this.rateLimitFailures = 0;
          return true;
        } catch (error: any) {
          // Check if we hit the rate limit threshold
          if (error.message === 'RATE_LIMIT_EXCEEDED') {
            log('Rate limit exceeded, forcing logout', 'error');
            await this.cleanSession(session);
            return false;
          }

          log('Failed to refresh session with refresh token', 'error');
          await this.cleanSession(session);
          return false;
        }
      }

      // If we reach here, both token verification methods failed
      await this.cleanSession(session);
      return false;
    } catch (error) {
      log('Session verification error', 'error');
      return false;
    }
  }

  /**
   * Gets the access token from the session
   * @param request - The request object containing session cookie
   * @returns The access token
   * @throws Error if no access token is found
   */
  async getAccessToken(request: Request): Promise<string> {
    log(`Getting access token from session...`, 'debug');
    const session = await getSession(request.headers.get('Cookie'));
    const accessToken = session.get('accessToken') as string | undefined;

    if (!accessToken) {
      log(`No access token found in session`, 'error');
      throw new Error('No access token found');
    }

    log(`Access token retrieved from session: ${accessToken.substring(0, 10)}...`, 'debug');
    return accessToken;
  }

  /**
   * Gets the access token from the session and refreshes it if expired
   * @param request - The request object containing session cookie
   * @returns The access token (refreshed if needed)
   * @throws Error if token cannot be retrieved or refreshed
   */
  async getAccessTokenWithRefresh(request: Request): Promise<string> {
    log(`Getting access token with refresh capability...`, 'debug');
    const session = await getSession(request.headers.get('Cookie'));
    const accessToken = session.get('accessToken') as string | undefined;
    const refreshToken = session.get('refreshToken') as string | undefined;
    
    if (!accessToken && !refreshToken) {
      log(`No tokens found in session`, 'error');
      throw new Error('No tokens found');
    }
    
    // First try to use existing access token
    if (accessToken) {
      // Get cached token info if available
      const cachedToken = this.tokenCache.get(accessToken);
      
      // Check if token is cached and still valid
      if (cachedToken && cachedToken.expiresAt && !this.isTokenExpired(cachedToken.expiresAt)) {
        log(`Using cached valid access token: ${accessToken.substring(0, 10)}...`, 'debug');
        return accessToken;
      }

      try {
        // Verify if token is still valid by checking user info
        const userInfo = await this.fetchUserInfo(accessToken);
        if (userInfo) {
          log(`Access token is valid, returning: ${accessToken.substring(0, 10)}...`, 'debug');
          return accessToken;
        }
      } catch (error) {
        log(`Access token invalid, will try refresh token`, 'debug');
        // Continue to refresh token logic
      }
    }

    // If we need to refresh the token
    if (refreshToken) {
      try {
        // Attempt to refresh the token
        const tokenInfo = await this.refreshToken(refreshToken);
        
        // Update session with new tokens
        await this.updateSession(session, {
          accessToken: tokenInfo.accessToken,
          refreshToken: tokenInfo.refreshToken,
          userInfo: tokenInfo.userInfo
        });

        log(`Token successfully refreshed: ${tokenInfo.accessToken.substring(0, 10)}...`, 'debug');
        return tokenInfo.accessToken;
      } catch (refreshError) {
        log(`Failed to refresh access token: ${refreshError}`, 'error');
        // Clean session as refresh failed
        await this.cleanSession(session);
        throw new Error('Failed to refresh access token');
      }
    }

    // This should not be reached if either token is valid
    throw new Error('No valid tokens available');
  }

  /**
   * Gets the access token from the session
   * @param request - The request object containing session cookie
   * @returns The access token or undefined if not found
   */
  async getAccessTokenSilentError(request: Request): Promise<string | undefined> {
    log(`Getting access token from session silently...`, 'debug');
    const session = await getSession(request.headers.get('Cookie'));
    const accessToken = session.get('accessToken') as string | undefined;

    if (accessToken) {
      log(`Access token retrieved from session: ${accessToken.substring(0, 10)}...`, 'debug');
    } else {
      log(`No access token in session`, 'debug');
    }
    
    return accessToken;
  }
}

// Export the singleton instance
export const auth0Service = Auth0Service.getInstance();
