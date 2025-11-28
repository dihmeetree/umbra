import { Hono } from "hono";
import { cors } from "hono/cors";
import { logger } from "hono/logger";
import { Wallet } from "@ethersproject/wallet";
import {
  ClobClient,
  Chain,
  Side,
  OrderType,
  type ApiKeyCreds,
  type OrderBookSummary,
} from "@polymarket/clob-client";

const app = new Hono();

// Middleware
app.use("*", logger());
app.use(
  "*",
  cors({
    origin: ["http://localhost:5173", "http://localhost:3000", "chrome-extension://*"],
    allowMethods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allowHeaders: ["Content-Type", "Authorization"],
  })
);

// Configuration
const CLOB_HOST = process.env.CLOB_HOST || "https://clob.polymarket.com";
const GAMMA_HOST = process.env.GAMMA_HOST || "https://gamma-api.polymarket.com";
const CHAIN_ID = Chain.POLYGON;

// Polymarket Gamma API types
interface GammaMarket {
  id: string;
  question: string;
  conditionId: string;
  slug: string;
  resolutionSource: string;
  endDate: string;
  liquidity: string;
  volume: string;
  outcomes: string;
  outcomePrices: string;
  clobTokenIds: string;
  acceptingOrders: boolean;
  closed: boolean;
  description: string;
  image: string;
  icon: string;
  negRisk: boolean;
}

interface GammaEvent {
  id: string;
  ticker: string;
  slug: string;
  title: string;
  description: string;
  startDate: string;
  creationDate: string;
  endDate: string;
  image: string;
  icon: string;
  active: boolean;
  closed: boolean;
  archived: boolean;
  new: boolean;
  featured: boolean;
  restricted: boolean;
  liquidity: number;
  volume: number;
  openInterest: number;
  markets: GammaMarket[];
}

// Create a basic client for public data (no auth needed)
function createPublicClient(): ClobClient {
  return new ClobClient(CLOB_HOST, CHAIN_ID);
}

// Create authenticated client
function createAuthenticatedClient(
  privateKey: string,
  creds: ApiKeyCreds,
  funder?: string
): ClobClient {
  const wallet = new Wallet(privateKey);
  return new ClobClient(CLOB_HOST, CHAIN_ID, wallet, creds, 1, funder);
}

// ==================== Public Routes ====================

// Health check
app.get("/", (c) => {
  return c.json({
    name: "PolyZK API",
    version: "0.1.0",
    status: "running",
  });
});

// Get server time
app.get("/time", async (c) => {
  const client = createPublicClient();
  const time = await client.getServerTime();
  return c.json({ time });
});

// ==================== Markets Routes ====================

// Get all events from Gamma API
app.get("/events", async (c) => {
  try {
    const limit = c.req.query("limit") || "100";
    const active = c.req.query("active") || "true";
    const closed = c.req.query("closed") || "false";
    const offset = c.req.query("offset") || "0";

    const params = new URLSearchParams({
      limit,
      active,
      closed,
      offset,
    });

    const response = await fetch(`${GAMMA_HOST}/events?${params}`);
    const events: GammaEvent[] = await response.json();

    // Filter out events without markets
    const eventsWithMarkets = events.filter(e => e.markets && e.markets.length > 0);

    // Determine if there might be more events
    const hasMore = events.length === parseInt(limit);

    return c.json({
      events: eventsWithMarkets,
      count: eventsWithMarkets.length,
      offset: parseInt(offset),
      hasMore,
    });
  } catch (error) {
    console.error("Error fetching events:", error);
    return c.json({ error: "Failed to fetch events" }, 500);
  }
});

// Get single event by slug
app.get("/events/:slug", async (c) => {
  try {
    const slug = c.req.param("slug");
    const response = await fetch(`${GAMMA_HOST}/events?slug=${slug}`);
    const events: GammaEvent[] = await response.json();

    if (events.length === 0) {
      return c.json({ error: "Event not found" }, 404);
    }

    return c.json({ event: events[0] });
  } catch (error) {
    console.error("Error fetching event:", error);
    return c.json({ error: "Failed to fetch event" }, 500);
  }
});

// Get markets
app.get("/markets", async (c) => {
  try {
    const limit = c.req.query("limit") || "100";
    const active = c.req.query("active") || "true";
    const closed = c.req.query("closed") || "false";

    const params = new URLSearchParams({
      limit,
      active,
      closed,
    });

    const response = await fetch(`${GAMMA_HOST}/markets?${params}`);
    const markets: GammaMarket[] = await response.json();

    return c.json({ markets, count: markets.length });
  } catch (error) {
    console.error("Error fetching markets:", error);
    return c.json({ error: "Failed to fetch markets" }, 500);
  }
});

// Get single market by condition ID
app.get("/markets/:conditionId", async (c) => {
  try {
    const conditionId = c.req.param("conditionId");
    const client = createPublicClient();
    const market = await client.getMarket(conditionId);
    return c.json({ market });
  } catch (error) {
    console.error("Error fetching market:", error);
    return c.json({ error: "Failed to fetch market" }, 500);
  }
});

// Get orderbook for a token
app.get("/orderbook/:tokenId", async (c) => {
  try {
    const tokenId = c.req.param("tokenId");
    const client = createPublicClient();
    const orderbook: OrderBookSummary = await client.getOrderBook(tokenId);
    return c.json({ orderbook });
  } catch (error) {
    console.error("Error fetching orderbook:", error);
    return c.json({ error: "Failed to fetch orderbook" }, 500);
  }
});

// Get price for a token
app.get("/price/:tokenId", async (c) => {
  try {
    const tokenId = c.req.param("tokenId");
    const side = (c.req.query("side") as Side) || Side.BUY;
    const client = createPublicClient();
    const price = await client.getPrice(tokenId, side);
    return c.json({ tokenId, side, price });
  } catch (error) {
    console.error("Error fetching price:", error);
    return c.json({ error: "Failed to fetch price" }, 500);
  }
});

// Get midpoint price
app.get("/midpoint/:tokenId", async (c) => {
  try {
    const tokenId = c.req.param("tokenId");
    const client = createPublicClient();
    const midpoint = await client.getMidpoint(tokenId);
    return c.json({ tokenId, midpoint });
  } catch (error) {
    console.error("Error fetching midpoint:", error);
    return c.json({ error: "Failed to fetch midpoint" }, 500);
  }
});

// Get spread
app.get("/spread/:tokenId", async (c) => {
  try {
    const tokenId = c.req.param("tokenId");
    const client = createPublicClient();
    const spread = await client.getSpread(tokenId);
    return c.json({ tokenId, spread });
  } catch (error) {
    console.error("Error fetching spread:", error);
    return c.json({ error: "Failed to fetch spread" }, 500);
  }
});

// Get last trade price
app.get("/last-trade/:tokenId", async (c) => {
  try {
    const tokenId = c.req.param("tokenId");
    const client = createPublicClient();
    const price = await client.getLastTradePrice(tokenId);
    return c.json({ tokenId, lastTradePrice: price });
  } catch (error) {
    console.error("Error fetching last trade price:", error);
    return c.json({ error: "Failed to fetch last trade price" }, 500);
  }
});

// Calculate execution price for a given order amount
// This walks the orderbook to find the average price for filling an order
app.get("/quote/:tokenId", async (c) => {
  try {
    const tokenId = c.req.param("tokenId");
    const amount = parseFloat(c.req.query("amount") || "100");
    const side = c.req.query("side") || "BUY";

    const client = createPublicClient();
    const orderbook: OrderBookSummary = await client.getOrderBook(tokenId);

    // For BUY orders, we consume asks (sorted low to high)
    // For SELL orders, we consume bids (sorted high to low)
    let levels: { price: string; size: string }[] = [];

    if (side === "BUY") {
      levels = (orderbook.asks || []).sort((a, b) => parseFloat(a.price) - parseFloat(b.price));
    } else {
      levels = (orderbook.bids || []).sort((a, b) => parseFloat(b.price) - parseFloat(a.price));
    }

    let totalSpent = 0;
    let totalShares = 0;

    for (const level of levels) {
      if (totalSpent >= amount) break;

      const price = parseFloat(level.price);
      const size = parseFloat(level.size);
      const costForLevel = price * size;
      const remainingToSpend = amount - totalSpent;

      let sharesBought: number;
      let spent: number;

      if (costForLevel <= remainingToSpend) {
        // Buy all shares at this level
        sharesBought = size;
        spent = costForLevel;
      } else {
        // Buy partial
        sharesBought = remainingToSpend / price;
        spent = remainingToSpend;
      }

      totalShares += sharesBought;
      totalSpent += spent;
    }

    const avgPrice = totalShares > 0 ? totalSpent / totalShares : 0;
    const payout = totalShares; // Each share pays $1 if outcome wins
    const toWin = payout - amount;

    return c.json({
      tokenId,
      side,
      amount,
      shares: totalShares,
      avgPrice,
      payout,
      toWin,
    });
  } catch (error) {
    console.error("Error calculating quote:", error);
    return c.json({ error: "Failed to calculate quote" }, 500);
  }
});

// ==================== Authenticated Routes ====================

// Derive API key from wallet signature
app.post("/auth/derive-key", async (c) => {
  try {
    const { privateKey } = await c.req.json();

    if (!privateKey) {
      return c.json({ error: "Private key required" }, 400);
    }

    const wallet = new Wallet(privateKey);
    const client = new ClobClient(CLOB_HOST, CHAIN_ID, wallet);
    const creds = await client.createOrDeriveApiKey();

    return c.json({
      address: await wallet.getAddress(),
      credentials: creds,
    });
  } catch (error) {
    console.error("Error deriving API key:", error);
    return c.json({ error: "Failed to derive API key" }, 500);
  }
});

// Get balance and allowance
app.post("/balance", async (c) => {
  try {
    const { privateKey, credentials } = await c.req.json();

    if (!privateKey || !credentials) {
      return c.json({ error: "Private key and credentials required" }, 400);
    }

    const client = createAuthenticatedClient(privateKey, credentials);
    const balance = await client.getBalanceAllowance({
      asset_type: "COLLATERAL" as any,
    });

    return c.json({ balance });
  } catch (error) {
    console.error("Error fetching balance:", error);
    return c.json({ error: "Failed to fetch balance" }, 500);
  }
});

// Get open orders
app.post("/orders/open", async (c) => {
  try {
    const { privateKey, credentials, market, assetId } = await c.req.json();

    if (!privateKey || !credentials) {
      return c.json({ error: "Private key and credentials required" }, 400);
    }

    const client = createAuthenticatedClient(privateKey, credentials);
    const orders = await client.getOpenOrders({
      market,
      asset_id: assetId,
    });

    return c.json({ orders });
  } catch (error) {
    console.error("Error fetching open orders:", error);
    return c.json({ error: "Failed to fetch open orders" }, 500);
  }
});

// Place a limit order
app.post("/orders/limit", async (c) => {
  try {
    const {
      privateKey,
      credentials,
      funder,
      tokenId,
      price,
      size,
      side,
      tickSize,
      negRisk,
    } = await c.req.json();

    if (!privateKey || !credentials || !tokenId || !price || !size || !side) {
      return c.json({ error: "Missing required fields" }, 400);
    }

    const client = createAuthenticatedClient(privateKey, credentials, funder);

    const response = await client.createAndPostOrder(
      {
        tokenID: tokenId,
        price: parseFloat(price),
        size: parseFloat(size),
        side: side === "BUY" ? Side.BUY : Side.SELL,
      },
      {
        tickSize: tickSize || "0.01",
        negRisk: negRisk || false,
      },
      OrderType.GTC
    );

    return c.json({ response });
  } catch (error) {
    console.error("Error placing limit order:", error);
    return c.json({ error: "Failed to place limit order" }, 500);
  }
});

// Place a market order
app.post("/orders/market", async (c) => {
  try {
    const {
      privateKey,
      credentials,
      funder,
      tokenId,
      amount,
      side,
      tickSize,
      negRisk,
      orderType,
    } = await c.req.json();

    if (!privateKey || !credentials || !tokenId || !amount || !side) {
      return c.json({ error: "Missing required fields" }, 400);
    }

    const client = createAuthenticatedClient(privateKey, credentials, funder);

    const response = await client.createAndPostMarketOrder(
      {
        tokenID: tokenId,
        amount: parseFloat(amount),
        side: side === "BUY" ? Side.BUY : Side.SELL,
      },
      {
        tickSize: tickSize || "0.01",
        negRisk: negRisk || false,
      },
      orderType === "FAK" ? OrderType.FAK : OrderType.FOK
    );

    return c.json({ response });
  } catch (error) {
    console.error("Error placing market order:", error);
    return c.json({ error: "Failed to place market order" }, 500);
  }
});

// Cancel an order
app.post("/orders/cancel", async (c) => {
  try {
    const { privateKey, credentials, orderId } = await c.req.json();

    if (!privateKey || !credentials || !orderId) {
      return c.json({ error: "Missing required fields" }, 400);
    }

    const client = createAuthenticatedClient(privateKey, credentials);
    const response = await client.cancelOrder({ orderID: orderId });

    return c.json({ response });
  } catch (error) {
    console.error("Error canceling order:", error);
    return c.json({ error: "Failed to cancel order" }, 500);
  }
});

// Cancel all orders
app.post("/orders/cancel-all", async (c) => {
  try {
    const { privateKey, credentials } = await c.req.json();

    if (!privateKey || !credentials) {
      return c.json({ error: "Missing required fields" }, 400);
    }

    const client = createAuthenticatedClient(privateKey, credentials);
    const response = await client.cancelAll();

    return c.json({ response });
  } catch (error) {
    console.error("Error canceling all orders:", error);
    return c.json({ error: "Failed to cancel all orders" }, 500);
  }
});

// Get trades
app.post("/trades", async (c) => {
  try {
    const { privateKey, credentials, market, assetId } = await c.req.json();

    if (!privateKey || !credentials) {
      return c.json({ error: "Missing required fields" }, 400);
    }

    const client = createAuthenticatedClient(privateKey, credentials);
    const trades = await client.getTrades({
      market,
      asset_id: assetId,
    });

    return c.json({ trades });
  } catch (error) {
    console.error("Error fetching trades:", error);
    return c.json({ error: "Failed to fetch trades" }, 500);
  }
});

// Start server
const PORT = process.env.PORT || 3001;
const WS_HOST = process.env.WS_HOST || "wss://ws-subscriptions-clob.polymarket.com";

// Track per-client subscriptions: client -> Set of token IDs
const clientSubscriptions = new Map<any, Set<string>>();

// Track token -> Set of clients subscribed to it
const tokenSubscribers = new Map<string, Set<any>>();

// Single Polymarket WebSocket connection for all tokens
let polymarketWs: WebSocket | null = null;
let polymarketPingInterval: ReturnType<typeof setInterval> | null = null;

// All tokens we're currently subscribed to on the Polymarket side
const subscribedTokensUpstream = new Set<string>();

function ensurePolymarketConnection() {
  if (polymarketWs && polymarketWs.readyState === WebSocket.OPEN) {
    return polymarketWs;
  }

  polymarketWs = new WebSocket(`${WS_HOST}/ws/market`);

  polymarketWs.onopen = () => {
    console.log("Connected to Polymarket WebSocket");
    // Resubscribe to all tokens we should be tracking
    if (subscribedTokensUpstream.size > 0) {
      const subscribeMsg = {
        type: "market",
        assets_ids: Array.from(subscribedTokensUpstream),
      };
      polymarketWs!.send(JSON.stringify(subscribeMsg));
      console.log("Resubscribed to", subscribedTokensUpstream.size, "tokens");
    }
  };

  polymarketWs.onmessage = (event) => {
    try {
      const data = JSON.parse(event.data.toString());

      // Extract token IDs from price changes and only send to subscribed clients
      if (data.event_type === "price_change" && data.price_changes) {
        for (const change of data.price_changes) {
          const tokenId = change.asset_id;
          if (tokenId) {
            const subscribers = tokenSubscribers.get(tokenId);
            if (subscribers) {
              for (const clientWs of subscribers) {
                try {
                  clientWs.send(JSON.stringify(data));
                } catch (e) {
                  // Client may have disconnected
                }
              }
            }
          }
        }
      }
    } catch (e) {
      // Handle non-JSON messages (like PONG)
    }
  };

  polymarketWs.onerror = (error) => {
    console.error("Polymarket WebSocket error:", error);
  };

  polymarketWs.onclose = () => {
    console.log("Polymarket WebSocket closed, will reconnect on next subscription");
    polymarketWs = null;
    if (polymarketPingInterval) {
      clearInterval(polymarketPingInterval);
      polymarketPingInterval = null;
    }
  };

  // Keep alive
  polymarketPingInterval = setInterval(() => {
    if (polymarketWs && polymarketWs.readyState === WebSocket.OPEN) {
      polymarketWs.send("PING");
    }
  }, 30000);

  return polymarketWs;
}

function subscribeClientToTokens(clientWs: any, tokenIds: string[]) {
  // Get or create client's subscription set
  let clientTokens = clientSubscriptions.get(clientWs);
  if (!clientTokens) {
    clientTokens = new Set();
    clientSubscriptions.set(clientWs, clientTokens);
  }

  const newTokens: string[] = [];

  for (const tokenId of tokenIds) {
    // Add to client's subscriptions
    clientTokens.add(tokenId);

    // Add client to token's subscribers
    let subscribers = tokenSubscribers.get(tokenId);
    if (!subscribers) {
      subscribers = new Set();
      tokenSubscribers.set(tokenId, subscribers);
    }
    subscribers.add(clientWs);

    // Track if this is a new token we need to subscribe to upstream
    if (!subscribedTokensUpstream.has(tokenId)) {
      subscribedTokensUpstream.add(tokenId);
      newTokens.push(tokenId);
    }
  }

  // Subscribe to new tokens on Polymarket
  if (newTokens.length > 0) {
    const ws = ensurePolymarketConnection();
    if (ws.readyState === WebSocket.OPEN) {
      const subscribeMsg = {
        type: "market",
        assets_ids: newTokens,
      };
      ws.send(JSON.stringify(subscribeMsg));
      console.log("Subscribed to", newTokens.length, "new tokens upstream");
    }
  }
}

function unsubscribeClientFromTokens(clientWs: any, tokenIds: string[]) {
  const clientTokens = clientSubscriptions.get(clientWs);
  if (!clientTokens) return;

  for (const tokenId of tokenIds) {
    // Remove from client's subscriptions
    clientTokens.delete(tokenId);

    // Remove client from token's subscribers
    const subscribers = tokenSubscribers.get(tokenId);
    if (subscribers) {
      subscribers.delete(clientWs);

      // If no more subscribers for this token, we could unsubscribe upstream
      // but Polymarket WS doesn't support unsubscribe, so just clean up our tracking
      if (subscribers.size === 0) {
        tokenSubscribers.delete(tokenId);
        subscribedTokensUpstream.delete(tokenId);
        console.log("No more subscribers for token:", tokenId);
      }
    }
  }
}

function cleanupClient(clientWs: any) {
  const clientTokens = clientSubscriptions.get(clientWs);
  if (clientTokens) {
    unsubscribeClientFromTokens(clientWs, Array.from(clientTokens));
    clientSubscriptions.delete(clientWs);
  }
}

// Bun server with WebSocket support
const server = Bun.serve({
  port: PORT,
  fetch(req, server) {
    const url = new URL(req.url);

    // Handle WebSocket upgrade for /ws path
    if (url.pathname === "/ws") {
      const upgraded = server.upgrade(req);
      if (upgraded) {
        return undefined;
      }
      return new Response("WebSocket upgrade failed", { status: 400 });
    }

    // Handle regular HTTP requests with Hono
    return app.fetch(req);
  },
  websocket: {
    open(ws) {
      console.log("Client WebSocket connected");
    },
    message(ws, message) {
      try {
        const data = JSON.parse(message.toString());

        if (data.type === "subscribe" && data.tokenIds) {
          console.log("Client subscribing to", data.tokenIds.length, "tokens:", data.tokenIds);
          subscribeClientToTokens(ws, data.tokenIds);
          ws.send(JSON.stringify({ type: "subscribed", tokenIds: data.tokenIds }));
        }

        if (data.type === "unsubscribe" && data.tokenIds) {
          console.log("Client unsubscribing from", data.tokenIds.length, "tokens:", data.tokenIds);
          unsubscribeClientFromTokens(ws, data.tokenIds);
          ws.send(JSON.stringify({ type: "unsubscribed", tokenIds: data.tokenIds }));
        }
      } catch (e) {
        console.error("WebSocket message error:", e);
      }
    },
    close(ws) {
      console.log("Client WebSocket disconnected");
      cleanupClient(ws);
    },
  },
});

console.log(`PolyZK API running on http://localhost:${PORT}`);
console.log(`WebSocket available at ws://localhost:${PORT}/ws`);
