import http from "node:http";
import { resolve4, resolve6, resolveMx } from "node:dns/promises";
import { mkdir, readFile, rename, writeFile } from "node:fs/promises";
import path from "node:path";
import {
  createHash,
  createPublicKey,
  randomBytes,
  randomUUID,
  scrypt as nodeScrypt,
  timingSafeEqual,
  verify as verifySignature
} from "node:crypto";
import { promisify } from "node:util";

const scrypt = promisify(nodeScrypt);

const config = {
  port: Number(process.env.PORT || 8787),
  sakuApiKey: process.env.SAKU_API_KEY || "",
  sakuMarketClientKey: process.env.SAKU_MARKET_CLIENT_KEY || process.env.SAKU_API_KEY || "",
  authDataPath: process.env.AUTH_DATA_PATH || path.join(process.cwd(), "data", "kinra-auth.json"),
  sessionTTLHours: Number(process.env.SESSION_TTL_HOURS || 24 * 90),
  appleBundleID: process.env.APPLE_BUNDLE_ID || "com.jeffreyyang.saku",
  appleServiceID: process.env.APPLE_SERVICE_ID || "",
  googleClientIDs: [
    process.env.GOOGLE_CLIENT_ID,
    process.env.GOOGLE_IOS_CLIENT_ID,
    process.env.GOOGLE_WEB_CLIENT_ID
  ].filter(Boolean),
  psaAuthMode: process.env.PSA_AUTH_MODE || "password",
  psaTokenURL: process.env.PSA_TOKEN_URL || "",
  psaClientID: process.env.PSA_CLIENT_ID || "",
  psaClientSecret: process.env.PSA_CLIENT_SECRET || "",
  psaUsername: process.env.PSA_USERNAME || "",
  psaPassword: process.env.PSA_PASSWORD || "",
  psaScope: process.env.PSA_SCOPE || "",
  psaAccessToken: process.env.PSA_ACCESS_TOKEN || "",
  psaAPIBaseURL: process.env.PSA_API_BASE_URL || "https://api.psacard.com",
  psaCertPathTemplate: process.env.PSA_CERT_PATH_TEMPLATE || "/publicapi/cert/GetByCertNumber/{certNumber}",
  psaCertImagesPathTemplate: process.env.PSA_CERT_IMAGES_PATH_TEMPLATE || "/publicapi/cert/GetImagesByCertNumber/{certNumber}",
  ebayClientID: process.env.EBAY_CLIENT_ID || "",
  ebayClientSecret: process.env.EBAY_CLIENT_SECRET || "",
  ebayMarketplaceID: process.env.EBAY_MARKETPLACE_ID || "EBAY_US",
  ebayOAuthScope: process.env.EBAY_OAUTH_SCOPE || "https://api.ebay.com/oauth/api_scope",
  ebayInsightsOAuthScope: process.env.EBAY_INSIGHTS_OAUTH_SCOPE || "https://api.ebay.com/oauth/api_scope https://api.ebay.com/oauth/api_scope/buy.marketplace.insights",
  ebayBrowseBaseURL: process.env.EBAY_BROWSE_BASE_URL || "https://api.ebay.com/buy/browse/v1",
  ebayInsightsBaseURL: process.env.EBAY_INSIGHTS_BASE_URL || "https://api.ebay.com/buy/marketplace_insights/v1_beta",
  ebayEnableMarketplaceInsights: process.env.EBAY_ENABLE_MARKETPLACE_INSIGHTS === "true",
  tcgplayerPublicKey: process.env.TCGPLAYER_PUBLIC_KEY || "",
  tcgplayerPrivateKey: process.env.TCGPLAYER_PRIVATE_KEY || "",
  tcgplayerAccessToken: process.env.TCGPLAYER_ACCESS_TOKEN || "",
  tcgplayerAPIBaseURL: process.env.TCGPLAYER_API_BASE_URL || "https://api.tcgplayer.com/v1.39.0",
  tcgplayerPricingBaseURL: process.env.TCGPLAYER_PRICING_BASE_URL || "https://api.tcgplayer.com/pricing",
  tcgplayerTokenURL: process.env.TCGPLAYER_TOKEN_URL || "https://api.tcgplayer.com/token",
  gradedCensusRapidAPIKey: process.env.GRADED_CENSUS_RAPIDAPI_KEY || "",
  gradedCensusRapidAPIHost: process.env.GRADED_CENSUS_RAPIDAPI_HOST || "graded-card-census-api.p.rapidapi.com",
  gradedCensusAPIBaseURL: process.env.GRADED_CENSUS_API_BASE_URL || "https://graded-card-census-api.p.rapidapi.com",
  pokemonTCGAPIBaseURL: process.env.POKEMON_TCG_API_BASE_URL || "https://api.pokemontcg.io/v2",
  yugiohAPIBaseURL: process.env.YUGIOH_API_BASE_URL || "https://db.ygoprodeck.com/api/v7",
  scryfallAPIBaseURL: process.env.SCRYFALL_API_BASE_URL || "https://api.scryfall.com",
  includeRawPSAResponse: process.env.INCLUDE_RAW_PSA_RESPONSE === "true"
};

let tokenCache = {
  accessToken: "",
  expiresAt: 0
};

let ebayTokenCache = {
  accessToken: "",
  scope: "",
  expiresAt: 0
};

let tcgplayerTokenCache = {
  accessToken: "",
  expiresAt: 0
};

const gradedCensusCache = new Map();
const emailDomainCache = new Map();
const gradedCensusCacheTTL = 6 * 60 * 60 * 1000;
const marketQuoteCache = new Map();
const marketQuoteCacheTTL = 30 * 60 * 1000;
let authStore;
let appleJWKCache = {
  keys: [],
  expiresAt: 0
};
let googleJWKCache = {
  keys: [],
  expiresAt: 0
};

export async function handleKinraRequest(request, response) {
  try {
    setBaseHeaders(response);

    if (request.method === "OPTIONS") {
      response.writeHead(204);
      response.end();
      return;
    }

    const url = new URL(request.url || "/", `http://${request.headers.host || "localhost"}`);

    if (request.method === "GET" && url.pathname === "/health") {
      sendJSON(response, 200, {
        ok: true,
        service: "kinra-backend",
        authConfigured: true,
        psaConfigured: isPSAConfigured(),
        marketConfigured: isMarketConfigured(),
        providers: {
          auth: true,
          google: isGoogleConfigured(),
          psa: isPSAConfigured(),
          ebayBrowse: isEbayConfigured(),
          ebayMarketplaceInsights: isEbayInsightsConfigured(),
          tcgplayer: isTCGPlayerConfigured(),
          gradedCensus: isGradedCensusConfigured()
        }
      });
      return;
    }

    if (request.method === "GET" && url.pathname === "/auth/email-domain") {
      const email = normalizedEmail(url.searchParams.get("email") || "");
      const formatReason = emailValidationReason(email);
      const domain = emailDomainFrom(email);
      const recognized = formatReason === "valid" && await isEmailDomainRecognized(domain);
      sendJSON(response, 200, {
        recognized,
        domain,
        reason: formatReason !== "valid" ? formatReason : recognized ? "recognized" : "unrecognized_domain"
      });
      return;
    }

    const usernameMatch = url.pathname.match(/^\/auth\/usernames\/([^/]+)$/);
    if (request.method === "GET" && usernameMatch) {
      const username = decodeURIComponent(usernameMatch[1]);
      const available = await authStore.isUsernameAvailable(username);
      sendJSON(response, 200, {
        available,
        reason: available ? "available" : usernameAvailabilityReason(username) === "available" ? "taken" : usernameAvailabilityReason(username)
      });
      return;
    }

    if (url.pathname === "/auth/register" && request.method === "POST") {
      const payload = await readJSONBody(request);
      const account = await authStore.register(payload);
      sendJSON(response, 201, account);
      return;
    }

    if (url.pathname === "/auth/login" && request.method === "POST") {
      const payload = await readJSONBody(request);
      const account = await authStore.login(payload);
      sendJSON(response, 200, account);
      return;
    }

    if (url.pathname === "/auth/federated" && request.method === "POST") {
      const payload = await readJSONBody(request);
      const account = await authStore.federatedSignIn(payload);
      sendJSON(response, 200, account);
      return;
    }

    if (url.pathname === "/auth/me" && request.method === "GET") {
      const session = await authStore.accountForBearerToken(authorizationBearerToken(request));
      if (!session) {
        sendJSON(response, 401, { error: "unauthorized" });
        return;
      }
      sendJSON(response, 200, session);
      return;
    }

    if (url.pathname === "/market/quote" && (request.method === "POST" || request.method === "GET")) {
      if (!isMarketAuthorized(request)) {
        sendJSON(response, 401, { error: "unauthorized" });
        return;
      }

      const quoteRequest = request.method === "POST"
        ? normalizeMarketQuoteRequest(await readJSONBody(request))
        : normalizeMarketQuoteRequest(Object.fromEntries(url.searchParams.entries()));

      if (!quoteRequest.name) {
        sendJSON(response, 400, { error: "missing_card_name" });
        return;
      }

      const quote = await buildMarketQuote(quoteRequest);
      if (!quote) {
        sendJSON(response, 404, {
          error: "market_data_unavailable",
          message: "No configured market source returned verified pricing data for this card.",
          asOf: new Date().toISOString()
        });
        return;
      }

      sendJSON(response, 200, { quote });
      return;
    }

    const tcgplayerPricingPath = matchedTCGPlayerPricingPath(url.pathname);
    if (request.method === "GET" && tcgplayerPricingPath) {
      if (!isMarketAuthorized(request)) {
        sendJSON(response, 401, { error: "unauthorized" });
        return;
      }

      if (!isTCGPlayerConfigured()) {
        sendJSON(response, 503, { error: "tcgplayer_not_configured" });
        return;
      }

      const upstream = await fetchTCGPlayerPricing(tcgplayerPricingPath, url.searchParams);
      sendJSON(response, upstream.status, upstream.payload);
      return;
    }

    const certMatch = url.pathname.match(/^\/psa\/certs\/([A-Za-z0-9-]+)$/);
    if (request.method === "GET" && certMatch) {
      if (!isAuthorized(request)) {
        sendJSON(response, 401, { error: "unauthorized" });
        return;
      }

      const certNumber = normalizeCertNumber(certMatch[1]);
      if (!certNumber) {
        sendJSON(response, 400, { error: "invalid_cert_number" });
        return;
      }

      const cert = await lookupPSACert(certNumber);
      sendJSON(response, 200, cert);
      return;
    }

    sendJSON(response, 404, { error: "not_found" });
  } catch (error) {
    const statusCode = Number(error?.statusCode || 500);
    sendJSON(response, statusCode, {
      error: error?.code || "internal_error",
      message: error instanceof Error ? error.message : "Unknown error"
    });
  }
}

function setBaseHeaders(response) {
  response.setHeader("content-type", "application/json; charset=utf-8");
  response.setHeader("access-control-allow-origin", "*");
  response.setHeader("access-control-allow-methods", "GET, POST, OPTIONS");
  response.setHeader("access-control-allow-headers", "authorization, content-type, x-saku-api-key, x-saku-client-key");
  response.setHeader("cache-control", "no-store");
}

function sendJSON(response, statusCode, payload) {
  response.writeHead(statusCode);
  response.end(JSON.stringify(payload));
}

function sendAuthError(message, statusCode = 400, error = "auth_error") {
  const authError = new Error(message);
  authError.statusCode = statusCode;
  authError.code = error;
  throw authError;
}

class KinraAuthStore {
  constructor(filePath) {
    this.filePath = filePath;
    this.loaded = false;
    this.writeQueue = Promise.resolve();
    this.data = {
      users: [],
      sessions: []
    };
  }

  async register(payload = {}) {
    await this.load();
    const name = cleanText(payload.name);
    const username = cleanText(payload.username);
    const email = normalizedEmail(payload.email);
    const phone = normalizedPhone(payload.phone);
    const password = String(payload.password || "");

    validateName(name);
    validateUsernameOrThrow(username);
    validateEmail(email);
    await validateEmailDomainOrThrow(email);
    validatePhone(phone);
    validatePassword(password);

    if (!await this.isUsernameAvailable(username)) {
      sendAuthError("That username is already taken.", 409, "username_unavailable");
    }
    if (this.findUserByEmail(email)) {
      sendAuthError("That email is already registered.", 409, "email_unavailable");
    }

    const now = new Date().toISOString();
    const passwordRecord = await hashPassword(password);
    const user = {
      id: randomUUID(),
      name,
      username,
      usernameNormalized: normalizedUsername(username),
      email,
      emailNormalized: email,
      phone,
      passwordHash: passwordRecord.hash,
      passwordSalt: passwordRecord.salt,
      providerIDs: {},
      createdAt: now,
      updatedAt: now
    };

    this.data.users.push(user);
    const sessionToken = this.createSession(user.id);
    await this.save();
    return accountResponse(user, sessionToken);
  }

  async login(payload = {}) {
    await this.load();
    const email = normalizedEmail(payload.email);
    const password = String(payload.password || "");
    validateEmail(email);
    if (!password) {
      sendAuthError("Enter your password.", 400, "missing_password");
    }

    const user = this.findUserByEmail(email);
    if (!user || !user.passwordHash || !user.passwordSalt) {
      sendAuthError("Email or password is incorrect.", 401, "invalid_credentials");
    }

    const isValid = await verifyPassword(password, user.passwordSalt, user.passwordHash);
    if (!isValid) {
      sendAuthError("Email or password is incorrect.", 401, "invalid_credentials");
    }

    const sessionToken = this.createSession(user.id);
    await this.save();
    return accountResponse(user, sessionToken);
  }

  async federatedSignIn(payload = {}) {
    await this.load();
    const provider = cleanText(payload.provider).toLowerCase();
    let claims;
    if (provider === "apple") {
      claims = await verifyAppleIdentityToken(payload.idToken);
    } else if (provider === "google") {
      claims = await verifyGoogleIdentityToken(payload.idToken);
    } else {
      sendAuthError("That sign-in provider is not supported.", 501, "provider_not_configured");
    }

    const providerKey = `${provider}:${claims.sub}`;
    const email = normalizedEmail(
      payload.email
        || claims.email
        || (provider === "apple" ? `${claims.sub}@privaterelay.appleid.com` : "")
    );
    if (!email) {
      sendAuthError("That sign-in provider did not return an email.", 401, "missing_provider_email");
    }
    const fallbackName = email.split("@")[0] || "Kinra Collector";
    const name = cleanText(payload.name || claims.name) || fallbackName;

    let user = this.data.users.find((candidate) => candidate.providerIDs?.[provider] === providerKey)
      || this.findUserByEmail(email);

    if (!user) {
      const username = await this.uniqueUsernameFromBase(fallbackName);
      const now = new Date().toISOString();
      user = {
        id: randomUUID(),
        name,
        username,
        usernameNormalized: normalizedUsername(username),
        email,
        emailNormalized: email,
        phone: "",
        passwordHash: "",
        passwordSalt: "",
        providerIDs: { [provider]: providerKey },
        createdAt: now,
        updatedAt: now
      };
      this.data.users.push(user);
    } else {
      user.providerIDs = { ...(user.providerIDs || {}), [provider]: providerKey };
      if (!user.name && name) user.name = name;
      user.updatedAt = new Date().toISOString();
    }

    const sessionToken = this.createSession(user.id);
    await this.save();
    return accountResponse(user, sessionToken);
  }

  async accountForBearerToken(token) {
    await this.load();
    const rawToken = cleanText(token);
    if (!rawToken) {
      return null;
    }

    const tokenHash = sha256(rawToken);
    const now = Date.now();
    const session = this.data.sessions.find((candidate) => {
      return candidate.tokenHash === tokenHash && Date.parse(candidate.expiresAt) > now;
    });
    if (!session) {
      return null;
    }

    const user = this.data.users.find((candidate) => candidate.id === session.userID);
    return user ? accountResponse(user, "") : null;
  }

  async isUsernameAvailable(username) {
    await this.load();
    const normalized = normalizedUsername(username);
    return usernameAvailabilityReason(username) === "available"
      && !this.data.users.some((user) => user.usernameNormalized === normalized);
  }

  findUserByEmail(email) {
    const normalized = normalizedEmail(email);
    return this.data.users.find((user) => user.emailNormalized === normalized);
  }

  async uniqueUsernameFromBase(value) {
    const base = normalizedUsername(value).replace(/[^a-z0-9]/g, "").slice(0, 18) || "collector";
    for (let index = 0; index < 1000; index += 1) {
      const suffix = index === 0 ? "" : String(index + 1);
      const candidate = `${base}${suffix}`.slice(0, 24);
      if (await this.isUsernameAvailable(candidate)) {
        return candidate;
      }
    }
    return `collector${randomBytes(4).toString("hex")}`;
  }

  createSession(userID) {
    const rawToken = `kinra_${base64URL(randomBytes(32))}`;
    const now = Date.now();
    this.data.sessions = this.data.sessions.filter((session) => Date.parse(session.expiresAt) > now);
    this.data.sessions.push({
      id: randomUUID(),
      userID,
      tokenHash: sha256(rawToken),
      createdAt: new Date(now).toISOString(),
      expiresAt: new Date(now + config.sessionTTLHours * 60 * 60 * 1000).toISOString()
    });
    return rawToken;
  }

  async load() {
    if (this.loaded) {
      return;
    }

    try {
      const raw = await readFile(this.filePath, "utf8");
      const parsed = JSON.parse(raw);
      this.data = {
        users: Array.isArray(parsed.users) ? parsed.users : [],
        sessions: Array.isArray(parsed.sessions) ? parsed.sessions : []
      };
    } catch (error) {
      if (error?.code !== "ENOENT") {
        throw error;
      }
      this.data = { users: [], sessions: [] };
    }
    this.loaded = true;
  }

  async save() {
    const payload = JSON.stringify(this.data, null, 2);
    this.writeQueue = this.writeQueue.then(async () => {
      await mkdir(path.dirname(this.filePath), { recursive: true });
      const tempPath = `${this.filePath}.${process.pid}.${Date.now()}.tmp`;
      await writeFile(tempPath, payload, { mode: 0o600 });
      await rename(tempPath, this.filePath);
    });
    await this.writeQueue;
  }
}

function accountResponse(user, sessionToken) {
  return {
    userID: user.id,
    name: user.name,
    username: user.username,
    email: user.email,
    phone: user.phone,
    sessionToken
  };
}

function cleanText(value) {
  return String(value || "").trim().replace(/\s+/g, " ");
}

function normalizedUsername(value) {
  return String(value || "").trim().toLowerCase();
}

function normalizedEmail(value) {
  return String(value || "").trim().toLowerCase();
}

function normalizedPhone(value) {
  const raw = String(value || "").trim();
  const leadingPlus = raw.startsWith("+") ? "+" : "";
  return `${leadingPlus}${raw.replace(/[^\d]/g, "")}`;
}

function usernameAvailabilityReason(username) {
  const value = String(username || "").trim();
  const normalized = normalizedUsername(value);
  const reserved = new Set(["admin", "kinra", "saku", "support", "pokemon", "tcg", "psa", "collector", "library"]);

  if (value.length < 3) return "too_short";
  if (value.length > 24) return "too_long";
  if (/\s/.test(value)) return "no_spaces";
  if (!/^[A-Za-z0-9]+$/.test(value)) return "letters_and_numbers_only";
  if (reserved.has(normalized)) return "reserved";
  return "available";
}

function validateUsernameOrThrow(username) {
  const reason = usernameAvailabilityReason(username);
  if (reason === "available") {
    return;
  }
  const messages = {
    too_short: "Username must be at least 3 characters.",
    too_long: "Username must be 24 characters or fewer.",
    no_spaces: "Username cannot contain spaces.",
    letters_and_numbers_only: "Username can only use letters and numbers.",
    reserved: "That username is reserved."
  };
  sendAuthError(messages[reason] || "Choose a different username.", 400, reason);
}

function validateName(name) {
  if (name.length < 1) {
    sendAuthError("Enter your name.", 400, "missing_name");
  }
  if (name.length > 80) {
    sendAuthError("Name must be 80 characters or fewer.", 400, "name_too_long");
  }
}

function validateEmail(email) {
  if (emailValidationReason(email) !== "valid") {
    sendAuthError("Enter a valid email.", 400, "invalid_email");
  }
}

function emailValidationReason(email) {
  const value = normalizedEmail(email);
  if (!value || value.length > 254) return "invalid_email";
  if (/\s/.test(value)) return "invalid_email";
  if ((value.match(/@/g) || []).length !== 1) return "invalid_email";

  const [local, domain] = value.split("@");
  if (!local || local.length > 64 || local.startsWith(".") || local.endsWith(".") || local.includes("..")) {
    return "invalid_email";
  }
  if (!/^[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+$/.test(local)) {
    return "invalid_email";
  }

  const labels = domain.split(".");
  if (labels.length < 2 || labels.some((label) => !label || label.length > 63)) {
    return "invalid_domain";
  }
  if (labels.some((label) => label.startsWith("-") || label.endsWith("-") || !/^[A-Za-z0-9-]+$/.test(label))) {
    return "invalid_domain";
  }
  const tld = labels.at(-1) || "";
  if (tld.length < 2 || !/^[A-Za-z]+$/.test(tld)) {
    return "invalid_domain";
  }
  return "valid";
}

function emailDomainFrom(email) {
  const parts = normalizedEmail(email).split("@");
  return parts.length === 2 ? parts[1] : "";
}

async function validateEmailDomainOrThrow(email) {
  const domain = emailDomainFrom(email);
  if (!await isEmailDomainRecognized(domain)) {
    sendAuthError("Kinra does not recognize this email domain.", 400, "unrecognized_email_domain");
  }
}

async function isEmailDomainRecognized(domain) {
  const normalized = String(domain || "").trim().toLowerCase();
  if (!normalized) return false;

  const cached = emailDomainCache.get(normalized);
  if (cached && cached.expiresAt > Date.now()) {
    return cached.recognized;
  }

  const recognized = await hasEmailDNSRecord(normalized);
  emailDomainCache.set(normalized, {
    recognized,
    expiresAt: Date.now() + 12 * 60 * 60 * 1000
  });
  return recognized;
}

async function hasEmailDNSRecord(domain) {
  try {
    const mxRecords = await withTimeout(resolveMx(domain), 2500);
    if (Array.isArray(mxRecords) && mxRecords.length > 0) {
      return true;
    }
  } catch {
    // Continue to address-record fallback.
  }

  try {
    const records = await withTimeout(Promise.any([resolve4(domain), resolve6(domain)]), 2500);
    return Array.isArray(records) && records.length > 0;
  } catch {
    return false;
  }
}

function withTimeout(promise, timeoutMs) {
  return Promise.race([
    promise,
    new Promise((_, reject) => {
      setTimeout(() => reject(new Error("dns_timeout")), timeoutMs);
    })
  ]);
}

function validatePhone(phone) {
  const digits = phone.replace(/[^\d]/g, "");
  if (digits.length < 7 || digits.length > 15) {
    sendAuthError("Enter a valid phone number.", 400, "invalid_phone");
  }
}

function validatePassword(password) {
  if (password.length < 8) {
    sendAuthError("Password must be at least 8 characters.", 400, "weak_password");
  }
  if (password.length > 256) {
    sendAuthError("Password is too long.", 400, "password_too_long");
  }
}

async function hashPassword(password) {
  const salt = base64URL(randomBytes(24));
  const hash = await scrypt(password, salt, 64);
  return {
    salt,
    hash: Buffer.from(hash).toString("base64")
  };
}

async function verifyPassword(password, salt, expectedHash) {
  const hash = await scrypt(password, salt, 64);
  const expected = Buffer.from(expectedHash, "base64");
  if (hash.length !== expected.length) {
    return false;
  }
  return timingSafeEqual(hash, expected);
}

function sha256(value) {
  return createHash("sha256").update(value).digest("hex");
}

function base64URL(value) {
  return Buffer.from(value)
    .toString("base64")
    .replaceAll("+", "-")
    .replaceAll("/", "_")
    .replaceAll("=", "");
}

function base64URLDecode(value) {
  const normalized = String(value || "").replaceAll("-", "+").replaceAll("_", "/");
  const padded = normalized.padEnd(Math.ceil(normalized.length / 4) * 4, "=");
  return Buffer.from(padded, "base64");
}

function authorizationBearerToken(request) {
  const header = request.headers.authorization || "";
  const match = String(header).match(/^Bearer\s+(.+)$/i);
  return match ? match[1].trim() : "";
}

async function verifyAppleIdentityToken(idToken) {
  const token = String(idToken || "");
  const parts = token.split(".");
  if (parts.length !== 3) {
    sendAuthError("Apple sign-in token is missing.", 401, "invalid_apple_token");
  }

  const [encodedHeader, encodedPayload, encodedSignature] = parts;
  const header = JSON.parse(base64URLDecode(encodedHeader).toString("utf8"));
  const claims = JSON.parse(base64URLDecode(encodedPayload).toString("utf8"));
  const keys = await appleJWKs();
  const jwk = keys.find((key) => key.kid === header.kid && key.kty === "RSA");
  if (!jwk) {
    sendAuthError("Apple sign-in key was not found.", 401, "invalid_apple_token");
  }

  const publicKey = createPublicKey({ key: jwk, format: "jwk" });
  const isVerified = verifySignature(
    "RSA-SHA256",
    Buffer.from(`${encodedHeader}.${encodedPayload}`),
    publicKey,
    base64URLDecode(encodedSignature)
  );
  if (!isVerified) {
    sendAuthError("Apple sign-in token could not be verified.", 401, "invalid_apple_token");
  }

  const expectedAudiences = [config.appleBundleID, config.appleServiceID].filter(Boolean);
  if (claims.iss !== "https://appleid.apple.com" || !expectedAudiences.includes(claims.aud)) {
    sendAuthError("Apple sign-in token is for a different app.", 401, "invalid_apple_token");
  }
  if (!claims.sub || Number(claims.exp || 0) * 1000 <= Date.now()) {
    sendAuthError("Apple sign-in token has expired.", 401, "invalid_apple_token");
  }

  return claims;
}

async function appleJWKs() {
  const now = Date.now();
  if (appleJWKCache.keys.length && appleJWKCache.expiresAt > now) {
    return appleJWKCache.keys;
  }

  const response = await fetch("https://appleid.apple.com/auth/keys", {
    headers: { accept: "application/json" }
  });
  if (!response.ok) {
    sendAuthError("Apple sign-in keys are temporarily unavailable.", 503, "apple_keys_unavailable");
  }
  const payload = await response.json();
  appleJWKCache = {
    keys: Array.isArray(payload.keys) ? payload.keys : [],
    expiresAt: now + 6 * 60 * 60 * 1000
  };
  return appleJWKCache.keys;
}

async function verifyGoogleIdentityToken(idToken) {
  if (!isGoogleConfigured()) {
    sendAuthError("Google sign-in is not configured yet.", 501, "provider_not_configured");
  }

  const token = String(idToken || "");
  const parts = token.split(".");
  if (parts.length !== 3) {
    sendAuthError("Google sign-in token is missing.", 401, "invalid_google_token");
  }

  const [encodedHeader, encodedPayload, encodedSignature] = parts;
  const header = JSON.parse(base64URLDecode(encodedHeader).toString("utf8"));
  const claims = JSON.parse(base64URLDecode(encodedPayload).toString("utf8"));
  const keys = await googleJWKs();
  const jwk = keys.find((key) => key.kid === header.kid && key.kty === "RSA");
  if (!jwk) {
    sendAuthError("Google sign-in key was not found.", 401, "invalid_google_token");
  }

  const publicKey = createPublicKey({ key: jwk, format: "jwk" });
  const isVerified = verifySignature(
    "RSA-SHA256",
    Buffer.from(`${encodedHeader}.${encodedPayload}`),
    publicKey,
    base64URLDecode(encodedSignature)
  );
  if (!isVerified) {
    sendAuthError("Google sign-in token could not be verified.", 401, "invalid_google_token");
  }

  const validIssuer = claims.iss === "https://accounts.google.com" || claims.iss === "accounts.google.com";
  if (!validIssuer || !config.googleClientIDs.includes(claims.aud)) {
    sendAuthError("Google sign-in token is for a different app.", 401, "invalid_google_token");
  }
  if (!claims.sub || Number(claims.exp || 0) * 1000 <= Date.now()) {
    sendAuthError("Google sign-in token has expired.", 401, "invalid_google_token");
  }

  return claims;
}

async function googleJWKs() {
  const now = Date.now();
  if (googleJWKCache.keys.length && googleJWKCache.expiresAt > now) {
    return googleJWKCache.keys;
  }

  const response = await fetch("https://www.googleapis.com/oauth2/v3/certs", {
    headers: { accept: "application/json" }
  });
  if (!response.ok) {
    sendAuthError("Google sign-in keys are temporarily unavailable.", 503, "google_keys_unavailable");
  }
  const payload = await response.json();
  googleJWKCache = {
    keys: Array.isArray(payload.keys) ? payload.keys : [],
    expiresAt: now + 6 * 60 * 60 * 1000
  };
  return googleJWKCache.keys;
}

authStore = new KinraAuthStore(config.authDataPath);

function isAuthorized(request) {
  if (!config.sakuApiKey) {
    return true;
  }
  return request.headers["x-saku-api-key"] === config.sakuApiKey;
}

function isMarketAuthorized(request) {
  if (!config.sakuMarketClientKey) {
    return true;
  }
  return request.headers["x-saku-client-key"] === config.sakuMarketClientKey
    || request.headers["x-saku-api-key"] === config.sakuMarketClientKey;
}

function isPSAConfigured() {
  const hasCredentialPath = config.psaAccessToken || (
    config.psaTokenURL &&
    config.psaUsername &&
    config.psaPassword
  );
  return Boolean(config.psaAPIBaseURL && config.psaCertPathTemplate && hasCredentialPath);
}

function isGoogleConfigured() {
  return config.googleClientIDs.length > 0;
}

function isEbayConfigured() {
  return Boolean(config.ebayClientID && config.ebayClientSecret);
}

function isEbayInsightsConfigured() {
  return Boolean(config.ebayEnableMarketplaceInsights && isEbayConfigured());
}

function isTCGPlayerConfigured() {
  return Boolean(config.tcgplayerAccessToken || (config.tcgplayerPublicKey && config.tcgplayerPrivateKey));
}

function isGradedCensusConfigured() {
  return Boolean(config.gradedCensusRapidAPIKey && config.gradedCensusRapidAPIHost && config.gradedCensusAPIBaseURL);
}

function isMarketConfigured() {
  return isPSAConfigured() || isEbayConfigured() || isTCGPlayerConfigured() || isGradedCensusConfigured();
}

function normalizeCertNumber(value) {
  return String(value || "").replace(/[^0-9]/g, "");
}

async function readJSONBody(request) {
  let raw = "";
  for await (const chunk of request) {
    raw += chunk;
  }
  if (!raw.trim()) {
    return {};
  }
  return JSON.parse(raw);
}

function normalizeMarketQuoteRequest(input = {}) {
  const get = (...keys) => {
    for (const key of keys) {
      const value = input[key];
      if (value !== undefined && value !== null && String(value).trim()) {
        return String(value).trim();
      }
    }
    return "";
  };

  return {
    game: get("game"),
    name: get("name", "cardName", "card_name", "q"),
    setName: get("setName", "set_name", "set"),
    number: get("number", "cardNumber", "card_number"),
    rarity: get("rarity"),
    variant: get("variant"),
    language: get("language"),
    conditionGrade: get("conditionGrade", "condition_grade", "condition", "grade"),
    gradingCompany: get("gradingCompany", "grading_company"),
    certificationNumber: normalizeCertNumber(get("certificationNumber", "certification_number", "cert", "psaCertNumber")),
    itemKind: get("itemKind", "item_kind"),
    imageURL: get("imageURL", "image_url"),
    backImageURL: get("backImageURL", "back_image_url"),
    ownedQuantity: Number(input.ownedQuantity ?? input.owned_quantity ?? 0) || null,
    collectionName: get("collectionName", "collection_name")
  };
}

async function buildMarketQuote(request) {
  const cacheKey = marketQuoteCacheKey(request);
  const cached = marketQuoteCache.get(cacheKey);
  if (cached && Date.now() - cached.storedAt < marketQuoteCacheTTL) {
    return cached.quote;
  }

  const includeCardOnlyProviders = isIndividualCardRequest(request);
  const tasks = [
    publicAvailablePricingProvider(request),
    ebayActiveListingsProvider(request),
    ebaySoldCompsProvider(request),
    tcgplayerPricingProvider(request)
  ];

  if (includeCardOnlyProviders) {
    tasks.push(gradedCardCensusPopulationProvider(request));
    tasks.push(psaVerificationProvider(request));
  }

  const settled = await Promise.allSettled(tasks);
  for (const result of settled) {
    if (result.status === "rejected") {
      console.warn("Market provider failed:", result.reason instanceof Error ? result.reason.message : result.reason);
    }
  }
  const providerResults = settled
    .filter((result) => result.status === "fulfilled" && result.value)
    .map((result) => result.value);

  const sources = providerResults.flatMap((result) => result.sources || []);
  const comps = providerResults.flatMap((result) => result.comps || []);
  const activeListings = providerResults.flatMap((result) => result.activeListings || []);
  const pricingRows = providerResults.flatMap((result) => result.pricingRows || []);
  const verification = providerResults.find((result) => result.verification)?.verification || null;

  const includedComps = comps.filter((comp) => comp.isIncluded && Number.isFinite(comp.price) && comp.price > 0);
  const activePrices = activeListings.map((listing) => listing.price).filter((price) => Number.isFinite(price) && price > 0);
  const selectedPricingRows = preferredPricingRows(pricingRows, request);
  const selectedPricingValues = selectedPricingRows.map(pricingRowValue).filter((price) => Number.isFinite(price) && price > 0);
  const sourcePrices = sources.map((source) => source.valueUSD).filter((price) => Number.isFinite(price) && price > 0);
  const quotePrices = includedComps.length
    ? includedComps.map((comp) => comp.price)
    : selectedPricingValues.length
      ? selectedPricingValues
      : sourcePrices.length
        ? sourcePrices
        : activePrices;

  if (!quotePrices.length) {
    return null;
  }

  const lastVerifiedSale = latestComp(includedComps);
  const blendedValueUSD = roundCurrency(median(quotePrices));
  const selectedLowValues = selectedPricingRows.map((row) => Number(row.low)).filter((price) => Number.isFinite(price) && price > 0);
  const selectedHighValues = selectedPricingRows.map((row) => Number(row.high)).filter((price) => Number.isFinite(price) && price > 0);
  const estimatedLowUSD = selectedLowValues.length && !includedComps.length
    ? roundCurrency(Math.min(...selectedLowValues))
    : roundCurrency(Math.min(...quotePrices));
  const estimatedHighUSD = selectedHighValues.length && !includedComps.length
    ? roundCurrency(Math.max(...selectedHighValues))
    : roundCurrency(Math.max(...quotePrices));
  const activeListingFloorUSD = activePrices.length ? roundCurrency(Math.min(...activePrices)) : null;
  const medianActiveListingUSD = activePrices.length ? roundCurrency(median(activePrices)) : null;
  const verifiedCompCount90Day = includedComps.length;
  const activeListingCount = activeListings.length;
  const sellerCount = new Set(activeListings.map((listing) => listing.seller).filter(Boolean)).size;
  const liquidityScore = liquidityScoreFor({ verifiedCompCount90Day, activeListingCount, sellerCount });

  const rawGradedRows = pricingRows;
  const conditionRows = conditionPricingRows(pricingRows);

  const quote = {
    blendedValueUSD,
    sources,
    asOf: new Date().toISOString(),
    estimatedLowUSD,
    estimatedHighUSD,
    lastVerifiedSaleUSD: lastVerifiedSale?.price ?? null,
    thirtyDayChangeUSD: thirtyDayChangeFromComps(includedComps, blendedValueUSD),
    activeListingFloorUSD,
    medianActiveListingUSD,
    activeListingCount,
    verifiedCompCount90Day,
    liquidityScore,
    sellerCount,
    psaCertificationNumber: verification?.certNumber ?? null,
    psaGrade: verification?.grade ?? null,
    psaPopulationTotal: verification?.population ?? null,
    psaPopulationCurrentGrade: verification?.populationCurrentGrade ?? null,
    psaPopulationHigher: verification?.populationHigher ?? null,
    psaPopulationLastUpdated: verification ? new Date().toISOString() : null,
    psaPopulationSource: verification?.source ?? (verification ? "PSA" : null),
    comps: includedComps.slice(0, 12),
    listingBands: priceBands(activePrices),
    conditionBands: conditionBandsFromComps(includedComps),
    saleFormatBands: saleFormatBandsFromComps(includedComps),
    rawGradedRows,
    conditionRows
  };
  marketQuoteCache.set(cacheKey, { quote, storedAt: Date.now() });
  return quote;
}

async function ebayActiveListingsProvider(request) {
  if (!isEbayConfigured()) {
    return null;
  }

  const token = await getEbayAccessToken(config.ebayOAuthScope);
  const url = new URL("item_summary/search", ensureTrailingSlash(config.ebayBrowseBaseURL));
  url.searchParams.set("q", marketSearchQuery(request));
  url.searchParams.set("limit", "50");
  url.searchParams.set("fieldgroups", "EXTENDED");

  const upstreamResponse = await fetch(url, {
    headers: {
      accept: "application/json",
      authorization: `Bearer ${token}`,
      "x-ebay-c-marketplace-id": config.ebayMarketplaceID
    }
  });

  if (!upstreamResponse.ok) {
    return null;
  }

  const payload = await upstreamResponse.json();
  const activeListings = (payload.itemSummaries || [])
    .map((item) => ({
      title: item.title || "",
      price: numberFromPrice(item.price),
      seller: item.seller?.username || item.seller?.sellerAccountType || "",
      format: Array.isArray(item.buyingOptions) && item.buyingOptions.includes("AUCTION") ? "Auction" : "Fixed price",
      url: item.itemWebUrl || "",
      source: "eBay"
    }))
    .filter((listing) => listing.price > 0 && isComparableListing(request, listing.title));

  if (!activeListings.length) {
    return null;
  }

  const activePrices = activeListings.map((listing) => listing.price);
  return {
    sources: [
      {
        name: "eBay",
        basis: "Active listing median",
        valueUSD: roundCurrency(median(activePrices)),
        observedAt: new Date().toISOString()
      },
      {
        name: "eBay",
        basis: "Active listing floor",
        valueUSD: roundCurrency(Math.min(...activePrices)),
        observedAt: new Date().toISOString()
      }
    ],
    activeListings
  };
}

async function ebaySoldCompsProvider(request) {
  if (!isEbayInsightsConfigured()) {
    return null;
  }

  const token = await getEbayAccessToken(config.ebayInsightsOAuthScope);
  const url = new URL("item_sales/search", ensureTrailingSlash(config.ebayInsightsBaseURL));
  url.searchParams.set("q", marketSearchQuery(request));
  url.searchParams.set("limit", "50");

  const upstreamResponse = await fetch(url, {
    headers: {
      accept: "application/json",
      authorization: `Bearer ${token}`,
      "x-ebay-c-marketplace-id": config.ebayMarketplaceID
    }
  });

  if (!upstreamResponse.ok) {
    return null;
  }

  const payload = await upstreamResponse.json();
  const records = payload.itemSales || payload.itemSummaries || [];
  const comps = records
    .map((item) => ({
      date: item.itemEndDate || item.saleDate || item.lastSoldDate || new Date().toISOString(),
      price: numberFromPrice(item.price || item.soldPrice),
      source: "eBay",
      format: Array.isArray(item.buyingOptions) && item.buyingOptions.includes("AUCTION") ? "Auction" : "Fixed price",
      conditionGrade: request.conditionGrade || item.condition || "Comparable",
      isIncluded: isComparableListing(request, item.title || "")
    }))
    .filter((comp) => comp.price > 0)
    .sort((left, right) => Date.parse(right.date) - Date.parse(left.date));

  if (!comps.length) {
    return null;
  }

  const included = comps.filter((comp) => comp.isIncluded);
  return {
    sources: included.length ? [{
      name: "eBay",
      basis: "Verified sold comps median",
      valueUSD: roundCurrency(median(included.map((comp) => comp.price))),
      observedAt: new Date().toISOString()
    }] : [],
    comps
  };
}

async function tcgplayerPricingProvider(request) {
  if (!isTCGPlayerConfigured()) {
    return null;
  }

  const token = await getTCGPlayerAccessToken();
  const products = await searchTCGPlayerProducts(request, token);
  const product = bestTCGPlayerProduct(request, products);
  if (!product?.productId) {
    return null;
  }

  const upstream = await fetchTCGPlayerPricing(`product/${encodeURIComponent(product.productId)}`);
  if (upstream.status < 200 || upstream.status >= 300) {
    return null;
  }

  const pricingRows = tcgplayerPricingRows(upstream.payload);

  if (!pricingRows.length) {
    return null;
  }

  const sourceValue = median(pricingRows.flatMap((row) => [row.low, row.high]).filter((price) => price > 0));
  return {
    sources: [{
      name: "TCGplayer",
      basis: "Marketplace pricing",
      valueUSD: roundCurrency(sourceValue),
      observedAt: new Date().toISOString()
    }],
    pricingRows
  };
}

function matchedTCGPlayerPricingPath(pathname) {
  const match = pathname.match(/^\/tcgplayer\/pricing\/(?:(buy)\/)?(marketprices|group|product|sku)\/([^/]+)$/);
  if (!match) {
    return "";
  }

  const [, buyPrefix, resource, ids] = match;
  return [buyPrefix, resource, encodeURIComponent(ids)].filter(Boolean).join("/");
}

async function fetchTCGPlayerPricing(path, searchParams = new URLSearchParams()) {
  const token = await getTCGPlayerAccessToken();
  const url = new URL(path, ensureTrailingSlash(config.tcgplayerPricingBaseURL));
  for (const [key, value] of searchParams.entries()) {
    url.searchParams.append(key, value);
  }

  const upstreamResponse = await fetch(url, {
    headers: {
      accept: "application/json",
      authorization: `bearer ${token}`
    }
  });

  const rawText = await upstreamResponse.text();
  return {
    status: upstreamResponse.status,
    payload: parseMaybeJSON(rawText)
  };
}

function tcgplayerPricingRows(payload) {
  const rows = Array.isArray(payload?.results)
    ? payload.results
    : Array.isArray(payload)
      ? payload
      : [];

  return rows
    .map((row) => {
      const low = Number(row.lowPrice ?? row.lowPriceWithShipping ?? row.marketPrice ?? row.midPrice);
      const market = Number(row.marketPrice ?? row.midPrice ?? row.lowPriceWithShipping ?? row.lowPrice);
      const high = Number(row.highPrice ?? row.directLowPrice ?? row.marketPrice ?? row.midPrice);
      if (![low, market, high].some(Number.isFinite)) {
        return null;
      }
      return {
        label: String(row.subTypeName || row.printing || row.condition || row.productConditionId || row.skuId || "Market"),
        low: roundCurrency(Number.isFinite(low) ? low : market),
        market: roundCurrency(Number.isFinite(market) ? market : Number.isFinite(low) ? low : high),
        high: roundCurrency(Number.isFinite(high) ? high : market),
        comps: 0,
        confidence: "Medium",
        liquidity: "Medium"
      };
    })
    .filter(Boolean);
}

async function gradedCardCensusPopulationProvider(request) {
  if (!isGradedCensusConfigured()) {
    return null;
  }

  let result = null;
  if (request.certificationNumber) {
    const payload = await fetchGradedCensus("/psa/pop", { certNumber: request.certificationNumber });
    result = firstCensusResult(payload);
  }

  if (!result && request.setName) {
    const payload = await fetchGradedCensus("/psa/set", { setName: request.setName });
    result = bestCensusSetMatch(request, censusResults(payload));
  }

  const verification = normalizeGradedCensusResult(request, result);
  if (!verification) {
    return null;
  }

  return {
    sources: [],
    verification
  };
}

async function fetchGradedCensus(pathname, params) {
  const url = new URL(pathname, ensureTrailingSlash(config.gradedCensusAPIBaseURL));
  for (const [key, value] of Object.entries(params)) {
    if (value !== undefined && value !== null && String(value).trim()) {
      url.searchParams.set(key, String(value).trim());
    }
  }

  const cacheKey = url.toString();
  const cached = gradedCensusCache.get(cacheKey);
  if (cached && Date.now() - cached.storedAt < gradedCensusCacheTTL) {
    return cached.payload;
  }

  const upstreamResponse = await fetch(url, {
    headers: {
      accept: "application/json",
      "x-rapidapi-host": config.gradedCensusRapidAPIHost,
      "x-rapidapi-key": config.gradedCensusRapidAPIKey
    }
  });

  if (!upstreamResponse.ok) {
    return null;
  }

  const payload = await upstreamResponse.json();
  gradedCensusCache.set(cacheKey, { payload, storedAt: Date.now() });
  return payload;
}

function firstCensusResult(payload) {
  return censusResults(payload)[0] || null;
}

function censusResults(payload) {
  if (!payload) {
    return [];
  }
  if (Array.isArray(payload)) {
    return payload;
  }
  if (Array.isArray(payload.results)) {
    return payload.results;
  }
  if (Array.isArray(payload.data)) {
    return payload.data;
  }
  return [payload];
}

function bestCensusSetMatch(request, results) {
  if (!Array.isArray(results) || !results.length) {
    return null;
  }

  const requestNumber = normalizedCardNumber(request.number);
  const requestNameTokens = importantTokens(request.name);
  const requestSetTokens = importantTokens(request.setName);

  const scored = results
    .map((result) => {
      const cardNumber = normalizedCardNumber(result.cardNumber || result.number || "");
      const subject = normalizedSearchText(result.subject || result.description || result.name || "");
      const setName = normalizedSearchText(result.setName || result.brand || "");
      let score = 0;

      if (requestNumber && cardNumber && requestNumber === cardNumber) score += 60;
      if (requestNameTokens.length && requestNameTokens.every((token) => subject.includes(token))) score += 30;
      if (requestSetTokens.length && requestSetTokens.some((token) => setName.includes(token))) score += 15;
      if (result.psaPop || result.totalPopulation) score += 5;

      return { result, score };
    })
    .sort((left, right) => right.score - left.score);

  return scored[0]?.score > 0 ? scored[0].result : null;
}

function normalizeGradedCensusResult(request, result) {
  if (!result) {
    return null;
  }

  const psaPop = result.psaPop || result.psaDnaPop || {};
  const total = firstFiniteNumber([
    result.totalPopulation,
    result.population,
    psaPop.total
  ]);
  if (!Number.isFinite(total) || total <= 0) {
    return null;
  }

  const gradeNumber = numericGradeFromText(request.conditionGrade || result.cardGrade || result.gradeDescription || "");
  const populationCurrentGrade = gradeNumber ? gradePopulation(psaPop, gradeNumber) : null;
  const populationHigher = gradeNumber ? populationAboveGrade(psaPop, gradeNumber) : firstFiniteNumber([result.populationHigher]);
  const label = [
    result.year,
    result.brand,
    result.subject || result.description || request.name,
    result.variety
  ]
    .filter(Boolean)
    .join(" ")
    .replace(/\s+/g, " ")
    .trim();

  return {
    certNumber: result.certNumber || request.certificationNumber || null,
    issuer: "PSA",
    label: label || request.name,
    grade: result.cardGrade || result.gradeDescription || request.conditionGrade || "PSA",
    year: result.year || null,
    brand: result.brand || result.setName || request.setName || null,
    category: result.category || null,
    cardNumber: result.cardNumber || request.number || null,
    subject: result.subject || request.name || null,
    variety: result.variety || request.rarity || null,
    population: total,
    populationCurrentGrade,
    populationHigher,
    status: "verified",
    source: "Graded Card Census API",
    scrapedAt: result.scrapedAt || null
  };
}

async function psaVerificationProvider(request) {
  if (!request.certificationNumber || !isPSAConfigured()) {
    return null;
  }

  const cert = await lookupPSACert(request.certificationNumber);
  if (cert.status !== "verified") {
    return null;
  }

  return {
    sources: [],
    verification: cert
  };
}

async function publicAvailablePricingProvider(request) {
  const game = normalizedSearchText(request.game);
  if (game.includes("pokemon")) {
    return pokemonTCGPricingProvider(request);
  }
  if (game.includes("yugioh") || game.includes("yu gi oh")) {
    return yugiohPublicPricingProvider(request);
  }
  if (game.includes("magic") || game.includes("mtg")) {
    return scryfallPricingProvider(request);
  }
  return null;
}

async function pokemonTCGPricingProvider(request) {
  const url = new URL("cards", ensureTrailingSlash(config.pokemonTCGAPIBaseURL));
  const printedNumber = normalizedCardNumber(request.number);
  const queryParts = [`name:"${escapedQueryValue(request.name)}"`];
  if (request.setName) {
    queryParts.push(`set.name:"${escapedQueryValue(request.setName)}"`);
  }
  if (printedNumber) {
    queryParts.push(`number:${escapedQueryValue(printedNumber)}`);
  }
  url.searchParams.set("q", queryParts.join(" "));
  url.searchParams.set("pageSize", "20");
  url.searchParams.set("select", "id,name,number,set,tcgplayer");

  const upstreamResponse = await fetch(url, {
    headers: {
      accept: "application/json",
      "user-agent": "Kinra/0.1 market-data"
    }
  });

  if (!upstreamResponse.ok) {
    return null;
  }

  const payload = await upstreamResponse.json();
  const card = bestRemoteCardMatch(request, payload.data || [], false);
  if (!card?.tcgplayer?.prices) {
    return null;
  }

  const rows = Object.entries(card.tcgplayer.prices)
    .map(([label, price]) => publicPriceRow(formatPriceLabel(label), price))
    .filter(Boolean);
  if (!rows.length) {
    return null;
  }

  return publicPricingResult("Pokémon TCG API", rows, card.tcgplayer.updatedAt);
}

async function yugiohPublicPricingProvider(request) {
  const url = new URL("cardinfo.php", ensureTrailingSlash(config.yugiohAPIBaseURL));
  url.searchParams.set("fname", request.name);

  const upstreamResponse = await fetch(url, {
    headers: {
      accept: "application/json",
      "user-agent": "Kinra/0.1 market-data"
    }
  });

  if (!upstreamResponse.ok) {
    return null;
  }

  const payload = await upstreamResponse.json();
  const card = bestRemoteCardMatch(request, payload.data || []);
  const price = card?.card_prices?.[0];
  if (!price) {
    return null;
  }

  const rows = [
    publicPriceRow("TCGplayer", { market: price.tcgplayer_price }),
    publicPriceRow("eBay", { market: price.ebay_price }),
    publicPriceRow("Cardmarket", { market: price.cardmarket_price }),
    publicPriceRow("Amazon", { market: price.amazon_price })
  ].filter(Boolean);

  if (!rows.length) {
    return null;
  }

  return publicPricingResult("YGOPRODeck", rows);
}

async function scryfallPricingProvider(request) {
  const url = new URL("cards/search", ensureTrailingSlash(config.scryfallAPIBaseURL));
  url.searchParams.set("q", scryfallQuery(request));
  url.searchParams.set("unique", "prints");
  url.searchParams.set("order", "released");
  url.searchParams.set("dir", "desc");
  url.searchParams.set("include_extras", "false");

  const upstreamResponse = await fetch(url, {
    headers: {
      accept: "application/json",
      "user-agent": "Kinra/0.1 market-data"
    }
  });

  if (!upstreamResponse.ok) {
    return null;
  }

  const payload = await upstreamResponse.json();
  const card = bestRemoteCardMatch(request, payload.data || []);
  if (!card?.prices) {
    return null;
  }

  const rows = [
    publicPriceRow("USD", { market: card.prices.usd }),
    publicPriceRow("USD foil", { market: card.prices.usd_foil }),
    publicPriceRow("USD etched", { market: card.prices.usd_etched })
  ].filter(Boolean);

  if (!rows.length) {
    return null;
  }

  return publicPricingResult("Scryfall", rows);
}

function publicPricingResult(sourceName, rows, observedAt = new Date().toISOString()) {
  const sources = rows.map((row) => ({
    name: sourceName,
    basis: `${row.label} market price`,
    valueUSD: roundCurrency(pricingRowValue(row)),
    observedAt
  }));

  return {
    sources,
    pricingRows: rows
  };
}

function publicPriceRow(label, price) {
  const low = priceNumber(price?.low ?? price?.lowPrice ?? price?.market ?? price?.mid ?? price?.averageSellPrice ?? price?.trendPrice);
  const market = priceNumber(price?.market ?? price?.marketPrice ?? price?.mid ?? price?.averageSellPrice ?? price?.trendPrice ?? price?.low);
  const high = priceNumber(price?.high ?? price?.highPrice ?? price?.market ?? price?.mid ?? price?.averageSellPrice ?? price?.trendPrice);
  if (![low, market, high].some(Number.isFinite)) {
    return null;
  }

  return {
    label,
    low: roundCurrency(Number.isFinite(low) ? low : market),
    market: roundCurrency(Number.isFinite(market) ? market : Number.isFinite(low) ? low : high),
    high: roundCurrency(Number.isFinite(high) ? high : market),
    comps: 0,
    confidence: "Medium",
    liquidity: "Medium"
  };
}

function scryfallQuery(request) {
  const terms = [`!"${escapedQueryValue(request.name)}"`];
  const printedNumber = request.number.split("/")[0]?.replace(/^#/, "").trim();
  if (printedNumber) {
    terms.push(`cn:${escapedQueryValue(printedNumber)}`);
  }
  return terms.join(" ");
}

function priceNumber(value) {
  if (value === undefined || value === null || value === "") {
    return Number.NaN;
  }
  return Number(String(value).replace(/[$,]/g, ""));
}

function escapedQueryValue(value) {
  return String(value || "")
    .replace(/\\/g, "\\\\")
    .replace(/"/g, '\\"')
    .trim();
}

function formatPriceLabel(label) {
  return String(label || "Market")
    .replace(/([a-z])([A-Z])/g, "$1 $2")
    .replace(/^./, (character) => character.toUpperCase());
}

function bestRemoteCardMatch(request, cards, allowFallback = true) {
  if (!Array.isArray(cards) || !cards.length) {
    return null;
  }
  return cards.find((card) => remoteCardMatches(request, card)) || (allowFallback ? cards[0] : null);
}

function remoteCardMatches(request, card) {
  const name = card.name || card.cleanName || "";
  const setName = card.set?.name || card.set_name || card.setName || "";
  const number = card.number || card.collector_number || card.collectorNumber || "";
  const requestNumber = request.number.split("/")[0]?.replace(/^#/, "").trim();

  const hasName = importantTokens(request.name).every((token) => normalizedSearchText(name).includes(token));
  const hasSet = !request.setName || importantTokens(request.setName).some((token) => normalizedSearchText(setName).includes(token));
  const hasNumber = !requestNumber || normalizedSearchText(number).includes(normalizedSearchText(requestNumber));
  return hasName && hasSet && hasNumber;
}

async function getEbayAccessToken(scope) {
  const now = Date.now();
  if (ebayTokenCache.accessToken && ebayTokenCache.scope === scope && ebayTokenCache.expiresAt - 60_000 > now) {
    return ebayTokenCache.accessToken;
  }

  const body = new URLSearchParams();
  body.set("grant_type", "client_credentials");
  body.set("scope", scope);

  const tokenResponse = await fetch("https://api.ebay.com/identity/v1/oauth2/token", {
    method: "POST",
    headers: {
      accept: "application/json",
      "content-type": "application/x-www-form-urlencoded",
      authorization: `Basic ${Buffer.from(`${config.ebayClientID}:${config.ebayClientSecret}`).toString("base64")}`
    },
    body
  });

  const payload = parseMaybeJSON(await tokenResponse.text());
  if (!tokenResponse.ok || !payload?.access_token) {
    throw new Error(`eBay auth failed with HTTP ${tokenResponse.status}`);
  }

  ebayTokenCache = {
    accessToken: payload.access_token,
    scope,
    expiresAt: now + Number(payload.expires_in || 7200) * 1000
  };
  return ebayTokenCache.accessToken;
}

async function getTCGPlayerAccessToken() {
  if (config.tcgplayerAccessToken) {
    return config.tcgplayerAccessToken;
  }

  const now = Date.now();
  if (tcgplayerTokenCache.accessToken && tcgplayerTokenCache.expiresAt - 60_000 > now) {
    return tcgplayerTokenCache.accessToken;
  }

  const body = new URLSearchParams();
  body.set("grant_type", "client_credentials");
  body.set("client_id", config.tcgplayerPublicKey);
  body.set("client_secret", config.tcgplayerPrivateKey);

  const tokenResponse = await fetch(config.tcgplayerTokenURL, {
    method: "POST",
    headers: {
      accept: "application/json",
      "content-type": "application/x-www-form-urlencoded"
    },
    body
  });

  const payload = parseMaybeJSON(await tokenResponse.text());
  if (!tokenResponse.ok || !payload?.access_token) {
    throw new Error(`TCGplayer auth failed with HTTP ${tokenResponse.status}`);
  }

  tcgplayerTokenCache = {
    accessToken: payload.access_token,
    expiresAt: now + Number(payload.expires_in || 1209600) * 1000
  };
  return tcgplayerTokenCache.accessToken;
}

async function searchTCGPlayerProducts(request, token) {
  const categoryID = tcgplayerCategoryID(request.game);
  const queries = [
    [request.name, request.setName, normalizedCardNumber(request.number)].filter(Boolean).join(" "),
    request.name
  ].filter(Boolean);

  for (const query of [...new Set(queries)]) {
    const products = await searchTCGPlayerProductsByName(query, categoryID, token);
    if (products.length) {
      return products;
    }
  }

  return [];
}

async function searchTCGPlayerProductsByName(productName, categoryID, token) {
  const url = new URL("catalog/products", ensureTrailingSlash(config.tcgplayerAPIBaseURL));
  url.searchParams.set("productName", productName);
  url.searchParams.set("limit", "25");
  if (categoryID) {
    url.searchParams.set("categoryId", categoryID);
  }

  const upstreamResponse = await fetch(url, {
    headers: {
      accept: "application/json",
      authorization: `bearer ${token}`
    }
  });

  if (!upstreamResponse.ok) {
    return [];
  }

  const payload = await upstreamResponse.json();
  return Array.isArray(payload.results) ? payload.results : [];
}

function bestTCGPlayerProduct(request, products) {
  if (!Array.isArray(products) || !products.length) {
    return null;
  }

  const requestNumber = normalizedCardNumber(request.number);
  const nameTokens = importantTokens(request.name);
  const setTokens = importantTokens(request.setName);
  const variantTokens = importantTokens([request.rarity, request.variant].filter(Boolean).join(" "));

  const scored = products
    .map((product) => {
      const haystack = normalizedSearchText(JSON.stringify(product));
      let score = 0;
      if (nameTokens.length && nameTokens.every((token) => haystack.includes(token))) score += 45;
      if (setTokens.length && setTokens.some((token) => haystack.includes(token))) score += 35;
      if (requestNumber && haystack.includes(requestNumber)) score += 50;
      if (variantTokens.length && variantTokens.some((token) => haystack.includes(token))) score += 15;
      return { product, score };
    })
    .sort((left, right) => right.score - left.score);

  return scored[0]?.score > 0 ? scored[0].product : products[0];
}

function tcgplayerCategoryID(game) {
  const normalized = normalizedSearchText(game);
  if (normalized.includes("pokemon")) return "3";
  if (normalized.includes("magic")) return "1";
  if (normalized.includes("yugioh")) return "2";
  if (normalized.includes("lorcana")) return "71";
  return "";
}

function marketSearchQuery(request) {
  const gradeText = normalizedSearchText([request.conditionGrade, request.gradingCompany].filter(Boolean).join(" "));
  const isGraded = gradeText.includes("psa") || gradeText.includes("bgs") || gradeText.includes("cgc") || gradeText.includes("sgc");
  const significantRarity = premiumPokemonRarity(normalizedSearchText([request.rarity, request.variant].filter(Boolean).join(" ")))
    ? [request.rarity, request.variant].filter(Boolean).join(" ")
    : "";
  return [
    request.game,
    request.name,
    request.setName,
    request.number,
    significantRarity,
    isGraded ? request.conditionGrade : "",
    isGraded ? request.gradingCompany : "",
    request.certificationNumber ? `PSA ${request.certificationNumber}` : ""
  ]
    .filter(Boolean)
    .join(" ")
    .replace(/\s+/g, " ")
    .trim();
}

function isComparableListing(request, title) {
  const haystack = normalizedSearchText(title);
  if (!haystack) {
    return false;
  }
  const nameTokens = importantTokens(request.name);
  const setTokens = importantTokens(request.setName);
  const numberTokens = importantTokens(request.number);
  const gradeTokens = importantTokens(request.conditionGrade).filter((token) => /^(psa|bgs|cgc|sgc|[0-9]{1,2})$/.test(token));

  const hasName = nameTokens.length === 0 || nameTokens.every((token) => haystack.includes(token));
  const hasSet = setTokens.length === 0 || setTokens.some((token) => haystack.includes(token));
  const hasNumber = numberTokens.length === 0 || numberTokens.some((token) => haystack.includes(token));
  const hasGrade = gradeTokens.length === 0 || gradeTokens.every((token) => haystack.includes(token));
  return hasName && hasSet && hasNumber && hasGrade;
}

function normalizedSearchText(value) {
  return String(value || "")
    .toLowerCase()
    .normalize("NFKD")
    .replace(/\p{Mark}/gu, "")
    .replace(/[^\p{Letter}\p{Number}]+/gu, " ")
    .replace(/\s+/g, " ")
    .trim();
}

function importantTokens(value) {
  const ignored = new Set(["the", "and", "card", "cards", "tcg", "trading", "japanese", "english", "near", "mint", "raw"]);
  return normalizedSearchText(value)
    .split(" ")
    .filter((token) => token.length > 1 && !ignored.has(token));
}

function normalizedCardNumber(value) {
  return String(value || "")
    .split("/")[0]
    .replace(/^#/, "")
    .replace(/^0+(?=\d)/, "")
    .trim()
    .toLowerCase();
}

function numericGradeFromText(value) {
  const match = String(value || "").match(/\b(10|[1-9])(?:\.0)?\b/);
  return match ? Number(match[1]) : null;
}

function firstFiniteNumber(values) {
  for (const value of values) {
    const number = Number(value);
    if (Number.isFinite(number)) {
      return number;
    }
  }
  return null;
}

function gradePopulation(psaPop, gradeNumber) {
  return firstFiniteNumber([
    psaPop?.[`grade${gradeNumber}`],
    psaPop?.[`grade_${gradeNumber}`],
    psaPop?.[`psa${gradeNumber}`],
    psaPop?.[`PSA${gradeNumber}`]
  ]);
}

function populationAboveGrade(psaPop, gradeNumber) {
  if (!psaPop || gradeNumber >= 10) {
    return 0;
  }

  let total = 0;
  for (let grade = gradeNumber + 1; grade <= 10; grade += 1) {
    total += gradePopulation(psaPop, grade) || 0;
  }
  return total;
}

function numberFromPrice(value) {
  if (typeof value === "number") {
    return value;
  }
  if (typeof value === "string") {
    return Number(value.replace(/[$,]/g, "")) || 0;
  }
  return Number(value?.value ?? value?.convertedFromValue ?? 0) || 0;
}

function median(values) {
  const sorted = values.filter((value) => Number.isFinite(value)).sort((left, right) => left - right);
  if (!sorted.length) {
    return 0;
  }
  const midpoint = Math.floor(sorted.length / 2);
  return sorted.length % 2 ? sorted[midpoint] : (sorted[midpoint - 1] + sorted[midpoint]) / 2;
}

function latestComp(comps) {
  return [...comps].sort((left, right) => Date.parse(right.date) - Date.parse(left.date))[0] || null;
}

function roundCurrency(value) {
  return Math.round(Number(value || 0) * 100) / 100;
}

function liquidityScoreFor({ verifiedCompCount90Day, activeListingCount, sellerCount }) {
  return Math.max(0, Math.min(100, verifiedCompCount90Day * 7 + activeListingCount * 2 + sellerCount * 3));
}

function thirtyDayChangeFromComps(comps, currentValue) {
  const now = Date.now();
  const older = comps
    .filter((comp) => now - Date.parse(comp.date) >= 30 * 24 * 60 * 60 * 1000)
    .map((comp) => comp.price);
  if (!older.length) {
    return 0;
  }
  return roundCurrency(currentValue - median(older));
}

function priceBands(prices) {
  if (!prices.length) {
    return [];
  }
  const min = Math.min(...prices);
  const max = Math.max(...prices);
  if (min === max) {
    return [{ label: `$${roundCurrency(min).toFixed(2)}`, count: prices.length }];
  }
  const step = (max - min) / 4;
  return [0, 1, 2, 3].map((index) => {
    const low = min + step * index;
    const high = index === 3 ? max : min + step * (index + 1);
    return {
      label: index === 3
        ? `$${roundCurrency(low).toFixed(2)}+`
        : `$${roundCurrency(low).toFixed(2)}-$${roundCurrency(high).toFixed(2)}`,
      count: prices.filter((price) => index === 3 ? price >= low : price >= low && price < high).length
    };
  });
}

function conditionBandsFromComps(comps) {
  const counts = new Map();
  for (const comp of comps) {
    const key = comp.conditionGrade || "Comparable";
    counts.set(key, (counts.get(key) || 0) + 1);
  }
  return [...counts.entries()].map(([label, count]) => ({ label, count }));
}

function saleFormatBandsFromComps(comps) {
  const counts = new Map();
  for (const comp of comps) {
    const key = comp.format || "Fixed price";
    counts.set(key, (counts.get(key) || 0) + 1);
  }
  return [...counts.entries()].map(([label, count]) => ({ label, count }));
}

function conditionPricingRows(pricingRows) {
  return pricingRows.filter((row) => {
    const label = normalizedSearchText(row.label);
    return label.includes("damaged")
      || label.includes("played")
      || label.includes("near mint")
      || label.includes("mint")
      || label.includes("psa")
      || label.includes("bgs")
      || label.includes("cgc")
      || label.includes("sgc");
  });
}

function marketQuoteCacheKey(request) {
  return [
    request.game,
    request.name,
    request.setName,
    request.number,
    request.rarity,
    request.variant,
    request.conditionGrade,
    request.gradingCompany,
    request.certificationNumber,
    request.itemKind,
    request.language
  ]
    .filter(Boolean)
    .map((value) => normalizedSearchText(value))
    .join("|");
}

function isIndividualCardRequest(request) {
  return !isSealedMarketRequest(request) && normalizedSearchText(request.itemKind || "card").includes("card");
}

function isSealedMarketRequest(request) {
  const text = [
    request.name,
    request.setName,
    request.number,
    request.rarity,
    request.variant,
    request.itemKind
  ]
    .filter(Boolean)
    .join(" ");
  const normalized = normalizedSearchText(text);
  return [
    "sealed",
    "elite trainer box",
    "etb",
    "booster box",
    "booster bundle",
    "booster pack",
    "pack",
    "tin",
    "collection box",
    "trainer box"
  ].some((token) => normalized.includes(normalizedSearchText(token)));
}

function preferredPricingRows(rows, request) {
  if (!Array.isArray(rows) || !rows.length) {
    return [];
  }

  const scored = rows
    .map((row) => ({ row, score: pricingRowScore(row, request) }))
    .sort((left, right) => {
      if (left.score !== right.score) return right.score - left.score;
      return pricingRowValue(right.row) - pricingRowValue(left.row);
    });

  const bestScore = scored[0]?.score ?? 0;
  if (bestScore <= 0) {
    return scored.slice(0, 1).map((entry) => entry.row);
  }
  return scored.filter((entry) => entry.score === bestScore).map((entry) => entry.row);
}

function pricingRowScore(row, request) {
  const label = normalizedSearchText(row.label);
  const preference = normalizedSearchText([
    request.rarity,
    request.variant,
    request.conditionGrade,
    request.gradingCompany
  ].filter(Boolean).join(" "));
  let score = 0;

  if (label.includes("near mint") || label === "nm") score += preference.includes("near mint") || preference.includes("nm") ? 40 : 0;
  if (label.includes("lightly played") || label === "lp") score += preference.includes("lightly played") || preference.includes("lp") ? 35 : 0;
  if (label.includes("moderately played") || label === "mp") score += preference.includes("moderately played") || preference.includes("mp") ? 35 : 0;
  if (label.includes("heavily played") || label === "hp") score += preference.includes("heavily played") || preference.includes("hp") ? 35 : 0;
  if (label.includes("damaged") || label === "dmg") score += preference.includes("damaged") || preference.includes("dmg") ? 35 : 0;

  if (label.includes("reverse")) score += preference.includes("reverse") ? 80 : -15;
  if (label.includes("holo")) score += preference.includes("holo") || preference.includes("foil") || premiumPokemonRarity(preference) ? 70 : 10;
  if (label.includes("normal")) score += preference.includes("normal") ? 45 : premiumPokemonRarity(preference) ? -25 : 12;
  if (label.includes("1st") || label.includes("first")) score += preference.includes("first") ? 45 : -20;
  if (label.includes("psa")) score += preference.includes("psa") ? 80 : -40;

  return score;
}

function premiumPokemonRarity(preference) {
  return [
    "alternate art",
    "special illustration",
    "illustration rare",
    "secret",
    "hyper rare",
    "ultra rare",
    "rare holo",
    "sir",
    "ir"
  ].some((token) => preference.includes(token));
}

function pricingRowValue(row) {
  const market = Number(row.market);
  if (Number.isFinite(market) && market > 0) {
    return market;
  }
  return median([row.low, row.high].map(Number).filter((price) => Number.isFinite(price) && price > 0));
}

async function lookupPSACert(certNumber) {
  if (!isPSAConfigured()) {
    return {
      certNumber,
      issuer: "PSA",
      label: "PSA cert saved",
      grade: "Pending API configuration",
      psaUrl: `https://www.psacard.com/cert/${certNumber}`,
      status: "not_configured"
    };
  }

  const token = await getPSAAccessToken();
  const psaURL = buildPSACertURL(certNumber);
  const upstreamResponse = await fetch(psaURL, {
    headers: {
      accept: "application/json",
      authorization: `bearer ${token}`
    }
  });

  const rawText = await upstreamResponse.text();
  const raw = parseMaybeJSON(rawText);

  if (!upstreamResponse.ok) {
    return {
      certNumber,
      issuer: "PSA",
      label: "PSA lookup failed",
      grade: `HTTP ${upstreamResponse.status}`,
      psaUrl: `https://www.psacard.com/cert/${certNumber}`,
      status: "upstream_error",
      upstreamStatus: upstreamResponse.status,
      raw: config.includeRawPSAResponse ? raw : undefined
    };
  }

  const images = await lookupPSACertImages(certNumber, token);
  return normalizePSACertResponse(certNumber, raw, images);
}

async function lookupPSACertImages(certNumber, token) {
  const psaURL = buildPSACertImagesURL(certNumber);
  const upstreamResponse = await fetch(psaURL, {
    headers: {
      accept: "application/json",
      authorization: `bearer ${token}`
    }
  });

  if (!upstreamResponse.ok) {
    return [];
  }

  const rawText = await upstreamResponse.text();
  const raw = parseMaybeJSON(rawText);
  return normalizePSAImageURLs(raw);
}

async function getPSAAccessToken() {
  if (config.psaAccessToken) {
    return config.psaAccessToken;
  }

  const now = Date.now();
  if (tokenCache.accessToken && tokenCache.expiresAt - 60_000 > now) {
    return tokenCache.accessToken;
  }

  if (!config.psaTokenURL) {
    throw new Error("Missing PSA_TOKEN_URL");
  }

  const body = new URLSearchParams();
  body.set("grant_type", config.psaAuthMode);
  body.set("username", config.psaUsername);
  body.set("password", config.psaPassword);
  if (config.psaClientID) body.set("client_id", config.psaClientID);
  if (config.psaClientSecret) body.set("client_secret", config.psaClientSecret);
  if (config.psaScope) body.set("scope", config.psaScope);

  const tokenResponse = await fetch(config.psaTokenURL, {
    method: "POST",
    headers: {
      accept: "application/json",
      "content-type": "application/x-www-form-urlencoded"
    },
    body
  });

  const rawText = await tokenResponse.text();
  const payload = parseMaybeJSON(rawText);
  if (!tokenResponse.ok || !payload?.access_token) {
    throw new Error(`PSA auth failed with HTTP ${tokenResponse.status}`);
  }

  tokenCache = {
    accessToken: payload.access_token,
    expiresAt: now + Number(payload.expires_in || 3600) * 1000
  };
  return tokenCache.accessToken;
}

function buildPSACertURL(certNumber) {
  const path = config.psaCertPathTemplate.replaceAll("{certNumber}", encodeURIComponent(certNumber));
  return new URL(path, ensureTrailingSlash(config.psaAPIBaseURL)).toString();
}

function buildPSACertImagesURL(certNumber) {
  const path = config.psaCertImagesPathTemplate.replaceAll("{certNumber}", encodeURIComponent(certNumber));
  return new URL(path, ensureTrailingSlash(config.psaAPIBaseURL)).toString();
}

function ensureTrailingSlash(value) {
  return value.endsWith("/") ? value : `${value}/`;
}

function parseMaybeJSON(rawText) {
  if (!rawText) {
    return null;
  }

  try {
    return JSON.parse(rawText);
  } catch {
    return { rawText };
  }
}

function normalizePSACertResponse(certNumber, raw, images = []) {
  const record = firstRecord(raw);
  const label = firstString(record, [
    "label",
    "description",
    "certDescription",
    "CertDescription",
    "cardDescription",
    "CardDescription",
    "specDescription",
    "SpecDescription",
    "itemDescription",
    "ItemDescription",
    "subject",
    "Subject",
    "name",
    "Name"
  ]) || "PSA certification";

  const grade = firstString(record, [
    "grade",
    "Grade",
    "gradeDescription",
    "GradeDescription",
    "finalGrade",
    "FinalGrade"
  ]) || "Verified";

  const resolvedCertNumber = firstString(record, [
    "certNumber",
    "CertNumber",
    "cert",
    "Cert"
  ]) || certNumber;

  const year = firstString(record, ["year", "Year"]);
  const brand = firstString(record, ["brand", "Brand", "setName", "SetName"]);
  const category = firstString(record, ["category", "Category"]);
  const cardNumber = firstString(record, ["cardNumber", "CardNumber"]);
  const subject = firstString(record, ["subject", "Subject", "name", "Name"]);
  const variety = firstString(record, ["variety", "Variety"]);
  const population = firstNumber(record, ["totalPopulation", "TotalPopulation"]);
  const populationCurrentGrade = firstNumber(record, [
    "population",
    "Population",
    "gradePopulation",
    "GradePopulation",
    "populationInGrade",
    "PopulationInGrade",
    "currentGradePopulation",
    "CurrentGradePopulation"
  ]);
  const populationHigher = firstNumber(record, ["populationHigher", "PopulationHigher"]);

  return {
    certNumber: resolvedCertNumber,
    issuer: "PSA",
    label,
    grade,
    year,
    brand,
    category,
    cardNumber,
    subject,
    variety,
    population,
    populationCurrentGrade,
    populationHigher,
    imageURL: images[0] || null,
    imageURLs: images,
    psaUrl: `https://www.psacard.com/cert/${resolvedCertNumber}`,
    status: "verified",
    raw: config.includeRawPSAResponse ? raw : undefined
  };
}

function extractImageURLs(value, urls = []) {
  if (!value) {
    return urls;
  }

  if (typeof value === "string") {
    if (isImageURL(value)) {
      urls.push(value);
    }
    return urls;
  }

  if (Array.isArray(value)) {
    for (const item of value) {
      extractImageURLs(item, urls);
    }
    return [...new Set(urls)];
  }

  if (typeof value === "object") {
    for (const entryValue of Object.values(value)) {
      extractImageURLs(entryValue, urls);
    }
  }

  return [...new Set(urls)];
}

function normalizePSAImageURLs(raw) {
  const records = Array.isArray(raw)
    ? raw
    : Array.isArray(raw?.Images)
      ? raw.Images
      : Array.isArray(raw?.images)
        ? raw.images
        : [];

  const imageRecords = records
    .map((record, index) => ({
      index,
      isFront: Boolean(record?.IsFrontImage ?? record?.isFrontImage ?? record?.Front ?? record?.front),
      url: firstString(record, ["ImageURL", "imageURL", "ImageUrl", "imageUrl", "Url", "url"])
    }))
    .filter((record) => isImageURL(record.url))
    .sort((left, right) => Number(right.isFront) - Number(left.isFront) || left.index - right.index)
    .map((record) => record.url);

  return imageRecords.length ? [...new Set(imageRecords)] : extractImageURLs(raw);
}

function isImageURL(value) {
  try {
    const url = new URL(value);
    return /^https?:$/.test(url.protocol) && /\.(avif|gif|jpe?g|png|webp|tif)(\?.*)?$/i.test(url.pathname + url.search);
  } catch {
    return false;
  }
}

function firstRecord(value) {
  if (!value || typeof value !== "object") {
    return {};
  }

  if (Array.isArray(value)) {
    return firstRecord(value[0]);
  }

  for (const key of ["data", "Data", "result", "Result", "psaCert", "PSACert", "cert", "Cert", "certificate", "Certificate"]) {
    if (value[key]) {
      return firstRecord(value[key]);
    }
  }

  return value;
}

function firstString(record, keys) {
  for (const key of keys) {
    const value = record?.[key];
    if (value !== undefined && value !== null && String(value).trim()) {
      return String(value).trim();
    }
  }
  return "";
}

function firstNumber(record, keys) {
  for (const key of keys) {
    const value = record?.[key];
    if (value !== undefined && value !== null && Number.isFinite(Number(value))) {
      return Number(value);
    }
  }
  return null;
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const server = http.createServer(handleKinraRequest);
  server.listen(config.port, "0.0.0.0", () => {
    console.log(`Kinra backend listening on port ${config.port}`);
  });
}
