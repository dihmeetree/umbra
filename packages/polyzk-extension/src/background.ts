// Background service worker - handles API communication and order placement

const API_BASE = "http://localhost:3001";
const WS_URL = "ws://localhost:3001/ws";

// WebSocket connection for live prices
let priceSocket: WebSocket | null = null;
let subscribedTokens: string[] = [];
const priceCache = new Map<string, number>();

function connectPriceSocket() {
  console.log("[PolyZK] Attempting to connect to price WebSocket...");
  if (priceSocket?.readyState === WebSocket.OPEN) {
    console.log("[PolyZK] Already connected");
    return;
  }

  try {
    priceSocket = new WebSocket(WS_URL);
  } catch (e) {
    console.error("[PolyZK] Failed to create WebSocket:", e);
    setTimeout(connectPriceSocket, 3000);
    return;
  }

  priceSocket.onopen = () => {
    console.log("[PolyZK] Connected to price WebSocket");
    // Resubscribe if we had tokens
    if (subscribedTokens.length > 0) {
      priceSocket?.send(JSON.stringify({ type: "subscribe", tokenIds: subscribedTokens }));
    }
  };

  priceSocket.onmessage = (event) => {
    try {
      const data = JSON.parse(event.data);
      console.log("[PolyZK] WS message received:", data);

      // Handle price updates
      if (data.event_type === "price_change" && data.price_changes) {
        console.log("[PolyZK] Price update received:", data.price_changes);
        for (const change of data.price_changes) {
          if (change.asset_id && change.price) {
            priceCache.set(change.asset_id, parseFloat(change.price));
          }
        }
        // Broadcast to popup
        chrome.runtime.sendMessage({ type: "PRICE_UPDATE", prices: Object.fromEntries(priceCache) }).catch(() => {});
      }
    } catch (e) {
      console.log("[PolyZK] WS message parse error:", e);
    }
  };

  priceSocket.onclose = () => {
    console.log("[PolyZK] Price WebSocket disconnected, reconnecting...");
    setTimeout(connectPriceSocket, 3000);
  };

  priceSocket.onerror = (error) => {
    console.error("[PolyZK] Price WebSocket error:", error);
  };
}

function subscribeToTokens(tokenIds: string[]) {
  subscribedTokens = tokenIds;
  if (priceSocket?.readyState === WebSocket.OPEN) {
    priceSocket.send(JSON.stringify({ type: "subscribe", tokenIds }));
  }
}

// Connect on startup
connectPriceSocket();

interface OrderRequest {
  privateKey: string;
  tokenId: string;
  price: number;
  amount: number;
  side: "BUY" | "SELL";
  market: {
    slug: string;
    title: string;
    conditionId?: string;
  };
}

interface ApiKeyCreds {
  key: string;
  secret: string;
  passphrase: string;
}

// Cache for API credentials
const credentialsCache = new Map<string, ApiKeyCreds>();

// Derive API key from private key
async function deriveApiKey(privateKey: string): Promise<{ address: string; credentials: ApiKeyCreds }> {
  const response = await fetch(`${API_BASE}/auth/derive-key`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ privateKey }),
  });

  if (!response.ok) {
    throw new Error("Failed to derive API key");
  }

  return response.json();
}

// Get orderbook to find tick size
async function getOrderbook(tokenId: string): Promise<{ tick_size: string; neg_risk: boolean }> {
  const response = await fetch(`${API_BASE}/orderbook/${tokenId}`);

  if (!response.ok) {
    throw new Error("Failed to get orderbook");
  }

  const data = await response.json();
  return {
    tick_size: data.orderbook?.tick_size || "0.01",
    neg_risk: data.orderbook?.neg_risk || false,
  };
}

// Get quote for a token - calculates execution price by walking the orderbook
interface Quote {
  avgPrice: number;
  bestPrice: number;
  shares: number;
  payout: number;
  toWin: number;
}

async function getQuote(tokenId: string, amount: number, side: "BUY" | "SELL" = "BUY"): Promise<Quote | null> {
  try {
    // Fetch quote and best price in parallel
    const [quoteRes, priceRes] = await Promise.all([
      fetch(`${API_BASE}/quote/${tokenId}?amount=${amount}&side=${side}`),
      fetch(`${API_BASE}/price/${tokenId}?side=${side === "BUY" ? "SELL" : "BUY"}`)
    ]);

    if (!quoteRes.ok) {
      return null;
    }

    const quoteData = await quoteRes.json();
    let bestPrice = 0;

    if (priceRes.ok) {
      const priceData = await priceRes.json();
      // Handle nested structure: {price: {price: "0.05"}}
      let price = priceData.price;
      if (price && typeof price === "object" && price.price) {
        price = price.price;
      }
      bestPrice = price ? parseFloat(price) : 0;
    }

    console.log("[PolyZK] Quote response:", quoteData, "Best price:", bestPrice);
    return {
      avgPrice: quoteData.avgPrice,
      bestPrice,
      shares: quoteData.shares,
      payout: quoteData.payout,
      toWin: quoteData.toWin,
    };
  } catch (e) {
    console.error("[PolyZK] Error fetching quote:", e);
    return null;
  }
}

// Place limit order
async function placeLimitOrder(params: {
  privateKey: string;
  credentials: ApiKeyCreds;
  tokenId: string;
  price: number;
  size: number;
  side: "BUY" | "SELL";
  tickSize: string;
  negRisk: boolean;
}): Promise<any> {
  const response = await fetch(`${API_BASE}/orders/limit`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(params),
  });

  if (!response.ok) {
    const error = await response.json();
    throw new Error(error.error || "Failed to place order");
  }

  return response.json();
}

// Handle order placement
async function handlePlaceOrder(request: OrderRequest): Promise<{ success: boolean; error?: string; data?: any }> {
  try {
    // Get or derive credentials
    let credentials = credentialsCache.get(request.privateKey);
    let address: string;

    if (!credentials) {
      const result = await deriveApiKey(request.privateKey);
      credentials = result.credentials;
      address = result.address;
      credentialsCache.set(request.privateKey, credentials);
    }

    // Get orderbook info
    const orderbook = await getOrderbook(request.tokenId);

    // Calculate size from amount and price
    const size = request.amount / request.price;

    // Place the order
    const result = await placeLimitOrder({
      privateKey: request.privateKey,
      credentials,
      tokenId: request.tokenId,
      price: request.price,
      size,
      side: request.side,
      tickSize: orderbook.tick_size,
      negRisk: orderbook.neg_risk,
    });

    return { success: true, data: result };
  } catch (error) {
    console.error("Order placement failed:", error);
    return { success: false, error: error instanceof Error ? error.message : "Unknown error" };
  }
}

// Listen for messages from popup
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.type === "PLACE_ORDER") {
    handlePlaceOrder(message.data)
      .then(sendResponse)
      .catch((error) => sendResponse({ success: false, error: error.message }));
    return true; // Keep channel open for async response
  }

  if (message.type === "OPEN_TRADE") {
    // Store market data and open popup
    chrome.storage.local.set({ currentMarket: message.data });
    // The popup will read this when it opens
  }

  if (message.type === "SUBSCRIBE_TOKENS") {
    subscribeToTokens(message.tokenIds);
    sendResponse({ success: true });
  }

  if (message.type === "GET_PRICES") {
    sendResponse({ prices: Object.fromEntries(priceCache) });
  }

  if (message.type === "GET_QUOTE") {
    console.log("[PolyZK] GET_QUOTE request for token:", message.tokenId, "amount:", message.amount, "side:", message.side);
    getQuote(message.tokenId, message.amount, message.side)
      .then((quote) => {
        console.log("[PolyZK] Got quote:", quote);
        sendResponse({ quote });
      })
      .catch((err) => {
        console.error("[PolyZK] Error getting quote:", err);
        sendResponse({ quote: null });
      });
    return true;
  }

  if (message.type === "SUBSCRIBE_TOKEN") {
    const tokenId = message.tokenId;
    if (tokenId && !subscribedTokens.includes(tokenId)) {
      subscribedTokens.push(tokenId);
      if (priceSocket?.readyState === WebSocket.OPEN) {
        priceSocket.send(JSON.stringify({ type: "subscribe", tokenIds: [tokenId] }));
      }
    }
    sendResponse({ success: true });
  }

  if (message.type === "UNSUBSCRIBE_TOKEN") {
    const tokenId = message.tokenId;
    subscribedTokens = subscribedTokens.filter((t) => t !== tokenId);
    if (priceSocket?.readyState === WebSocket.OPEN && tokenId) {
      console.log("[PolyZK] Unsubscribing from token:", tokenId);
      priceSocket.send(JSON.stringify({ type: "unsubscribe", tokenIds: [tokenId] }));
    }
    sendResponse({ success: true });
  }
});

// Handle extension icon click - open popup
chrome.action.onClicked.addListener((tab) => {
  // Popup is already set as default, so this won't be called
  // But we can use it for other actions if needed
});

console.log("[PolyZK] Background service worker loaded");

// Re-inject content scripts into existing Polymarket tabs on extension load/reload
async function reinjectContentScripts() {
  try {
    const tabs = await chrome.tabs.query({ url: ["https://polymarket.com/*", "https://*.polymarket.com/*"] });

    for (const tab of tabs) {
      if (tab.id) {
        try {
          // Inject CSS first
          await chrome.scripting.insertCSS({
            target: { tabId: tab.id },
            files: ["content.css"],
          });

          // Then inject JS
          await chrome.scripting.executeScript({
            target: { tabId: tab.id },
            files: ["content.js"],
          });

          console.log("[PolyZK] Re-injected content script into tab:", tab.id, tab.url);
        } catch (e) {
          // Tab might not be accessible, ignore
          console.log("[PolyZK] Could not inject into tab:", tab.id, e);
        }
      }
    }
  } catch (e) {
    console.log("[PolyZK] Error re-injecting content scripts:", e);
  }
}

// Run on startup
reinjectContentScripts();

// Development: Connect to live reload server
if (typeof WebSocket !== "undefined") {
  const connectDevServer = () => {
    try {
      const ws = new WebSocket("ws://localhost:35729");

      ws.onopen = () => {
        console.log("[PolyZK] Connected to dev server");
      };

      ws.onmessage = (event) => {
        const data = JSON.parse(event.data);
        if (data.type === "reload") {
          console.log("[PolyZK] Reloading extension...");
          chrome.runtime.reload();
        }
      };

      ws.onclose = () => {
        // Reconnect after 3 seconds
        setTimeout(connectDevServer, 3000);
      };

      ws.onerror = () => {
        // Dev server not running, ignore
      };
    } catch (e) {
      // Ignore connection errors in production
    }
  };

  connectDevServer();
}
