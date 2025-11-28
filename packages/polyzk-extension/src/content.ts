// Content script - runs on Polymarket pages
// Intercepts trade actions and provides Polynight trading option
export {};

console.log("[PolyZK] Content script loaded on", window.location.href);

// Intercept network requests to capture market data
let currentMarketData: any = null;

// Hook into fetch to capture API responses with market data
// Only wrap if not already wrapped (prevents recursive wrapping on re-injection)
if (!(window as any).__polyzkFetchWrapped) {
  const originalFetch = window.fetch;
  window.fetch = async (...args) => {
    const response = await originalFetch(...args);

    try {
      const url = args[0]?.toString() || "";

      // Capture market/event data from Polymarket API
      if (url.includes("/markets/") || url.includes("/events/")) {
        const cloned = response.clone();
        const data = await cloned.json();
        if (data) {
          console.log("[PolyZK] Captured market data from API:", url);
          currentMarketData = data;
          chrome.runtime.sendMessage({ type: "MARKET_DATA_CAPTURED", data });
        }
      }
    } catch (e) {
      // Ignore errors
    }

    return response;
  };
  (window as any).__polyzkFetchWrapped = true;
}

// Store a unique session ID to detect extension reloads
const SESSION_ID = Math.random().toString(36).substring(2);
console.log("[PolyZK] Content script loading, session:", SESSION_ID);

// Use event delegation instead of attaching to individual buttons
declare global {
  interface Window {
    __polyzkClickHandler?: (e: Event) => void;
  }
}

// Check if extension context is valid
function isExtensionContextValid(): boolean {
  try {
    // This will throw if the extension context is invalidated
    chrome.runtime.getURL("");
    return true;
  } catch (e) {
    return false;
  }
}

// The click handler
function polyzkClickHandler(e: Event) {
  // Check if extension is still valid
  if (!isExtensionContextValid()) {
    console.log("[PolyZK] Extension context invalidated, removing handler");
    document.removeEventListener("click", polyzkClickHandler, true);
    window.__polyzkClickHandler = undefined;
    return;
  }

  const target = e.target as HTMLElement;
  const button = target.closest('button');

  if (!button) return;

  // Skip buttons inside Polynight UI
  if (button.closest('#polyzk-trade-panel') || button.closest('#polyzk-trade-overlay')) {
    return;
  }

  const text = button.textContent?.trim().toLowerCase() || "";

  // Check if this is a trade button
  const isTradeBtn = text === "trade" ||
    (text.startsWith("buy ") && text.includes("¢")) ||
    (text.startsWith("sell ") && text.includes("¢"));

  if (isTradeBtn) {
    e.preventDefault();
    e.stopPropagation();
    e.stopImmediatePropagation();

    // Hide any Polymarket dialogs that might pop up
    setTimeout(() => {
      const overlay = document.querySelector('[data-slot="dialog-overlay"]') as HTMLElement;
      if (overlay) overlay.style.display = 'none';
      const modal = document.getElementById('authentication-modal');
      if (modal) modal.style.display = 'none';
    }, 0);

    // Extract trade details from Polymarket's UI, passing the clicked button
    const tradeDetails = extractTradeDetails(button);
    console.log("[PolyZK] Intercepted trade button click:", tradeDetails);
    openPolynightTrade(tradeDetails);
  }
}

// Always remove any existing handler and add fresh one
if (window.__polyzkClickHandler) {
  console.log("[PolyZK] Removing old click handler");
  try {
    document.removeEventListener("click", window.__polyzkClickHandler, true);
  } catch (e) {
    console.log("[PolyZK] Error removing old handler:", e);
  }
}

// Store and add new handler
window.__polyzkClickHandler = polyzkClickHandler;
document.addEventListener("click", polyzkClickHandler, true);
console.log("[PolyZK] Global click handler installed, session:", SESSION_ID);

// Also add a periodic check to ensure we're still connected
setInterval(() => {
  if (!isExtensionContextValid() && window.__polyzkClickHandler) {
    console.log("[PolyZK] Extension disconnected, cleaning up");
    document.removeEventListener("click", window.__polyzkClickHandler, true);
    window.__polyzkClickHandler = undefined;
  }
}, 1000);

// No longer needed but keep for compatibility
function hookTradeButtons() {
  // Event delegation handles this now
}

// Extract trade details from Polymarket's existing UI
function extractTradeDetails(clickedButton?: HTMLElement) {
  const details: any = {
    side: "BUY",
    outcome: "",
    amount: 0,
    price: 0,
    shares: 0,
  };

  // First, extract from the clicked button if available (most reliable source)
  if (clickedButton) {
    const text = clickedButton.textContent?.toLowerCase() || "";
    console.log("[PolyZK] Clicked button text:", text);

    if (text.startsWith("sell")) {
      details.side = "SELL";
    } else if (text.startsWith("buy")) {
      details.side = "BUY";
    }

    // Extract outcome (Yes/No) from button text
    if (text.includes("yes")) {
      details.outcome = "Yes";
    } else if (text.includes("no")) {
      details.outcome = "No";
    }

    // Extract price from button text (e.g., "Buy No 0.9¢" or "Buy Yes 54.5¢")
    const priceMatch = text.match(/(\d+\.?\d*)¢/);
    if (priceMatch) {
      details.price = parseFloat(priceMatch[1]) / 100;
      console.log("[PolyZK] Extracted price from button:", details.price);
    }
  }

  // Find the amount input
  // Strategy: Look for an input that contains a dollar amount the user entered
  // The amount input is typically the FIRST numeric input in the trade form
  // and will be smaller than calculated values like "To Win" or "Payout"
  const allInputs = document.querySelectorAll('input');
  const candidates: { value: number; el: HTMLInputElement }[] = [];

  allInputs.forEach((input) => {
    const el = input as HTMLInputElement;
    if (el.type === 'search' || el.type === 'hidden') return;

    const rawValue = el.value;
    const value = parseFloat(rawValue.replace(/[^0-9.]/g, ""));

    if (value > 0) {
      candidates.push({ value, el });
    }
  });

  console.log("[PolyZK] Input candidates:", candidates.map(c => c.value));

  // The amount is typically the smallest value (user's bet)
  // vs larger calculated values (payout, to win)
  if (candidates.length > 0) {
    // Sort by value and take the smallest as the amount
    candidates.sort((a, b) => a.value - b.value);
    details.amount = candidates[0].value;
    console.log("[PolyZK] Using smallest value as amount:", details.amount);
  }

  return details;
}


// Cache for fetched event data by slug
const eventDataCache = new Map<string, any>();

// Extract event slug from URL
function getEventSlugFromUrl(): string {
  const pathParts = window.location.pathname.split('/');
  const eventIndex = pathParts.indexOf('event');
  if (eventIndex !== -1 && pathParts[eventIndex + 1]) {
    // Remove any query params from slug
    return pathParts[eventIndex + 1].split('?')[0];
  }
  return "";
}

// Extract market slug from URL (the part after event slug)
function getMarketSlugFromUrl(): string {
  const pathParts = window.location.pathname.split('/');
  const eventIndex = pathParts.indexOf('event');
  if (eventIndex !== -1 && pathParts[eventIndex + 2]) {
    // Remove any query params from slug
    return pathParts[eventIndex + 2].split('?')[0];
  }
  return "";
}

// Fetch event data from Polymarket API
async function fetchEventData(slug: string): Promise<any> {
  // Check cache first
  if (eventDataCache.has(slug)) {
    console.log("[PolyZK] Using cached event data for:", slug);
    return eventDataCache.get(slug);
  }

  try {
    console.log("[PolyZK] Fetching event data from API for slug:", slug);
    const response = await fetch(`https://gamma-api.polymarket.com/events?slug=${slug}`);
    if (!response.ok) {
      console.log("[PolyZK] API request failed:", response.status);
      return null;
    }

    const events = await response.json();
    if (!events || events.length === 0) {
      console.log("[PolyZK] No events found for slug:", slug);
      return null;
    }

    const event = events[0];
    console.log("[PolyZK] Fetched event:", event.title, "with", event.markets?.length, "markets");

    // Cache the result
    eventDataCache.set(slug, event);
    return event;
  } catch (e) {
    console.log("[PolyZK] Error fetching event data:", e);
    return null;
  }
}

// Parse market data from API response
function parseMarketData(market: any): { outcomes: any[], conditionId: string, negRisk: boolean } {
  let outcomes: string[] = [];
  let prices: string[] = [];
  let tokenIds: string[] = [];

  // Handle both array and JSON string formats
  if (Array.isArray(market.outcomes)) {
    outcomes = market.outcomes;
  } else if (typeof market.outcomes === "string") {
    try {
      outcomes = JSON.parse(market.outcomes);
    } catch {
      outcomes = market.outcomes.split(",").map((s: string) => s.trim());
    }
  }

  if (Array.isArray(market.outcomePrices)) {
    prices = market.outcomePrices;
  } else if (typeof market.outcomePrices === "string") {
    try {
      prices = JSON.parse(market.outcomePrices);
    } catch {
      prices = market.outcomePrices.split(",").map((s: string) => s.trim());
    }
  }

  if (Array.isArray(market.clobTokenIds)) {
    tokenIds = market.clobTokenIds;
  } else if (typeof market.clobTokenIds === "string") {
    try {
      tokenIds = JSON.parse(market.clobTokenIds);
    } catch {
      tokenIds = market.clobTokenIds.split(",").map((s: string) => s.trim());
    }
  }

  // Use bestAsk for Yes price (what you pay to buy Yes)
  // Use 1-bestBid for No price (what you pay to buy No)
  // Fallback to outcomePrices if not available
  let yesPrice = market.bestAsk;
  let noPrice = market.bestBid ? (1 - market.bestBid) : null;

  // Fallback to outcomePrices
  if (yesPrice === undefined || yesPrice === null) {
    yesPrice = parseFloat(prices[0] || "0");
  }
  if (noPrice === undefined || noPrice === null) {
    noPrice = parseFloat(prices[1] || "0");
  }

  return {
    outcomes: outcomes.map((name: string, i: number) => ({
      name,
      price: i === 0 ? yesPrice : noPrice,
      tokenId: tokenIds[i] || "",
    })),
    conditionId: market.conditionId,
    negRisk: market.negRisk || false,
  };
}

// Extract current market data from the page (sync version for backward compat)
function extractMarketData() {
  const eventSlug = getEventSlugFromUrl();

  const data: any = {
    url: window.location.href,
    slug: eventSlug,
    title: "",
    outcomes: [],
    image: "",
  };

  // Get title from page
  const h1 = document.querySelector("h1");
  if (h1) data.title = h1.textContent?.trim() || "";

  // Try to get image from og:image meta tag
  const ogImage = document.querySelector('meta[property="og:image"]');
  if (ogImage) {
    data.image = ogImage.getAttribute("content") || "";
  }

  // Check if we have cached API data for this slug
  if (eventSlug && eventDataCache.has(eventSlug)) {
    const event = eventDataCache.get(eventSlug);
    data.title = event.title || data.title;
    data.description = event.description;
    data.image = event.image || data.image;

    if (event.markets && event.markets.length > 0) {
      // Use first market by default (can be improved with mslug later)
      const market = event.markets[0];
      const parsed = parseMarketData(market);
      data.outcomes = parsed.outcomes;
      data.conditionId = parsed.conditionId;
      data.negRisk = parsed.negRisk;
    }

    console.log("[PolyZK] Using cached API data for event:", eventSlug);
  }

  return data;
}

// Async version that fetches from API if needed
async function extractMarketDataAsync(): Promise<any> {
  const eventSlug = getEventSlugFromUrl();
  const marketSlug = getMarketSlugFromUrl();
  console.log("[PolyZK] extractMarketDataAsync called, eventSlug:", eventSlug, "marketSlug:", marketSlug);

  // Always try to fetch fresh data from API
  if (eventSlug) {
    console.log("[PolyZK] Calling fetchEventData for:", eventSlug);
    const event = await fetchEventData(eventSlug);
    console.log("[PolyZK] fetchEventData returned:", event ? event.title : "null");

    if (event) {
      const data: any = {
        url: window.location.href,
        slug: eventSlug,
        marketSlug,
        title: event.title || "",
        description: event.description,
        image: event.image || "",
        volume: event.volume || 0,
        endDate: event.endDate || null,
        outcomes: [],
        markets: [], // Include all markets for multi-outcome events
      };

      if (event.markets && event.markets.length > 0) {
        // Filter out closed, inactive, or placeholder markets
        const openMarkets = event.markets.filter((m: any) => {
          // Must not be closed and must be accepting orders
          if (m.closed || m.acceptingOrders === false) return false;
          // Must be active
          if (m.active === false) return false;
          // Must have some volume or liquidity (filters out placeholder markets like "Person O")
          const volume = parseFloat(m.volume || "0");
          const liquidity = parseFloat(m.liquidity || "0");
          if (volume === 0 && liquidity === 0) return false;
          return true;
        });
        console.log("[PolyZK] Open markets:", openMarkets.length, "of", event.markets.length);

        // Store open markets for selection
        data.markets = openMarkets;

        // Find the market matching the URL's marketSlug, or use first open market
        let selectedMarket = openMarkets[0];
        if (marketSlug) {
          const matchingMarket = openMarkets.find((m: any) => m.slug === marketSlug);
          if (matchingMarket) {
            selectedMarket = matchingMarket;
            console.log("[PolyZK] Found matching market for slug:", marketSlug);
          }
        }

        if (selectedMarket) {
          const parsed = parseMarketData(selectedMarket);
          data.outcomes = parsed.outcomes;
          data.conditionId = parsed.conditionId;
          data.negRisk = parsed.negRisk;
          data.selectedMarketSlug = selectedMarket.slug;
        }

        console.log("[PolyZK] Parsed market data, open markets:", openMarkets.length, "outcomes:", data.outcomes.length);
      }

      return data;
    }
  }

  // Fallback to sync extraction
  console.log("[PolyZK] Falling back to sync extractMarketData");
  return extractMarketData();
}

// Open Polynight trade panel
function openPolynightTrade(tradeDetails: any) {
  // Show modal immediately with loading state
  const initialData = {
    ...tradeDetails,
    title: document.querySelector("h1")?.textContent?.trim() || "Loading...",
    image: "",
    markets: [],
    outcomes: [],
    loading: true,
  };

  console.log("[PolyZK] Opening trade panel immediately");
  showTradePanel(initialData);

  // Fetch full data from API in background
  extractMarketDataAsync().then(async (marketData) => {
    console.log("[PolyZK] Got market data, updating panel");

    // Update the panel with real data
    updateTradePanelWithData(marketData);

    // Store market data for extension
    chrome.runtime.sendMessage({
      type: "OPEN_TRADE",
      data: { ...marketData, ...tradeDetails },
    });
  });
}

// Track current price state for the modal
let currentTradeState: {
  tokenId: string;
  yesTokenId: string;
  noTokenId: string;
  amount: number;
  price: number;
  side: "BUY" | "SELL";
  marketIndex: number;
  priceListener?: (message: any) => void;
} | null = null;


// Store current trade data for updates
let currentTradeData: any = null;

// Remember last used amount for current event
let lastUsedAmount: number = 0;
let lastEventSlug: string = "";

// Update trade panel with fetched data
function updateTradePanelWithData(marketData: any) {
  currentTradeData = marketData;
  const markets = marketData.markets || [];
  const outcomes = marketData.outcomes || [];

  // Update title if needed
  const titleEl = document.querySelector(".polyzk-market-title");
  if (titleEl && marketData.title) {
    titleEl.textContent = marketData.title;
  }

  // Update image - preload then replace skeleton with actual image
  const imageEl = document.querySelector(".polyzk-market-image");
  if (imageEl && marketData.image) {
    const img = new Image();
    img.onload = () => {
      img.alt = "";
      img.className = "polyzk-market-image";
      imageEl.replaceWith(img);
    };
    img.src = marketData.image;
  }

  // Update meta info (volume and end date)
  const metaEl = document.getElementById("polyzk-market-meta");
  if (metaEl) {
    let metaHtml = "";
    if (marketData.volume) {
      metaHtml += `<span class="meta-item"><span class="meta-label">Vol</span> <span class="meta-value">${formatVolume(marketData.volume)}</span></span>`;
    }
    if (marketData.endDate) {
      metaHtml += `<span class="meta-item"><span class="meta-label">Ends</span> <span class="meta-value">${formatEndDate(marketData.endDate)}</span></span>`;
    }
    metaEl.innerHTML = metaHtml;
  }

  // Update outcome list
  const marketList = document.getElementById("polyzk-market-list");
  const outcomeList = document.getElementById("polyzk-outcome-list");

  if (markets.length > 0 && marketList) {
    // Multi-market event - find which market should be pre-selected based on URL
    const selectedMarketSlug = marketData.selectedMarketSlug || marketData.marketSlug;
    let selectedIndex = 0;
    if (selectedMarketSlug) {
      const matchIdx = markets.findIndex((m: any) => m.slug === selectedMarketSlug);
      if (matchIdx !== -1) selectedIndex = matchIdx;
    }

    marketList.innerHTML = markets.map((market: any, idx: number) => {
      // Use groupItemTitle if available (short form like "300-319"), otherwise extract from question
      let name = market.groupItemTitle;
      if (!name) {
        const question = market.question || "";
        name = question.replace(/^Will\s+/i, "").replace(/\s+win.*$/i, "").trim();
      }
      if (!name) name = `Option ${idx + 1}`;

      return `
        <button class="outcome-option ${idx === selectedIndex ? 'selected' : ''}" data-market-index="${idx}">
          <span class="outcome-name">${name}</span>
        </button>
      `;
    }).join("");

    // Update side button prices for selected market
    const selectedMarket = markets[selectedIndex];
    updateSidePrices(selectedMarket);

    // Set initial token
    if (currentTradeState && selectedMarket) {
      currentTradeState.marketIndex = selectedIndex;
      const tokenIds = getBothTokenIdsFromMarket(selectedMarket);
      currentTradeState.yesTokenId = tokenIds.yesTokenId;
      currentTradeState.noTokenId = tokenIds.noTokenId;
      currentTradeState.tokenId = currentTradeState.side === "BUY" ? tokenIds.yesTokenId : tokenIds.noTokenId;
      // Trigger initial quote fetch
      updateQuoteDisplay(currentTradeState.tokenId, currentTradeState.amount, currentTradeState.side);
      // Setup live price updates
      setupLivePriceUpdates(currentTradeState.tokenId);
    }

    // Re-attach click handlers
    setupMarketListeners(markets);
  } else if (outcomes.length > 0) {
    // Single market with Yes/No - update side button prices
    updateSidePricesFromOutcomes(outcomes);

    // Set initial token
    if (currentTradeState && outcomes.length >= 2) {
      currentTradeState.yesTokenId = outcomes[0]?.tokenId || "";
      currentTradeState.noTokenId = outcomes[1]?.tokenId || "";
      currentTradeState.tokenId = currentTradeState.side === "BUY" ? currentTradeState.yesTokenId : currentTradeState.noTokenId;
      updateQuoteDisplay(currentTradeState.tokenId, currentTradeState.amount, currentTradeState.side);
      // Setup live price updates
      setupLivePriceUpdates(currentTradeState.tokenId);
    }
  } else {
    // No markets found - show loading placeholder
    const selectorContainer = document.querySelector(".polyzk-outcome-selector .outcome-list");
    if (selectorContainer) {
      selectorContainer.innerHTML = `
        <div class="outcome-option" style="justify-content: center; color: #666;">
          <span>No outcomes available</span>
        </div>
      `;
    }
  }
}

// Setup market list click handlers
function setupMarketListeners(markets: any[]) {
  const marketList = document.getElementById("polyzk-market-list");
  if (!marketList) return;

  marketList.addEventListener("click", (e) => {
    const btn = (e.target as HTMLElement).closest(".outcome-option") as HTMLElement;
    if (!btn) return;

    marketList.querySelectorAll(".outcome-option").forEach(el => el.classList.remove("selected"));
    btn.classList.add("selected");

    const marketIndex = parseInt(btn.dataset.marketIndex || "0");
    const market = markets[marketIndex];
    if (market && currentTradeState) {
      currentTradeState.marketIndex = marketIndex;
      const tokenIds = getBothTokenIdsFromMarket(market);
      currentTradeState.yesTokenId = tokenIds.yesTokenId;
      currentTradeState.noTokenId = tokenIds.noTokenId;
      currentTradeState.tokenId = currentTradeState.side === "BUY" ? tokenIds.yesTokenId : tokenIds.noTokenId;
      // Update Yes/No prices for this market
      updateSidePrices(market);
      updateQuoteDisplay(currentTradeState.tokenId, currentTradeState.amount, currentTradeState.side);
      // Re-subscribe to new tokens
      setupLivePriceUpdates(currentTradeState.tokenId);
    }
  });
}

// Setup outcome list click handlers
function setupOutcomeListeners(outcomes: any[]) {
  const outcomeList = document.getElementById("polyzk-outcome-list");
  if (!outcomeList) return;

  outcomeList.addEventListener("click", (e) => {
    const btn = (e.target as HTMLElement).closest(".outcome-option") as HTMLElement;
    if (!btn) return;

    outcomeList.querySelectorAll(".outcome-option").forEach(el => el.classList.remove("selected"));
    btn.classList.add("selected");

    const outcomeIndex = parseInt(btn.dataset.outcomeIndex || "0");
    const outcome = outcomes[outcomeIndex];
    if (outcome && currentTradeState) {
      currentTradeState.tokenId = outcome.tokenId;
      updateQuoteDisplay(outcome.tokenId, currentTradeState.amount, currentTradeState.side);
      // Re-subscribe to new token
      setupLivePriceUpdates(outcome.tokenId);
    }
  });
}

// Track currently subscribed tokens
let subscribedYesToken: string = "";
let subscribedNoToken: string = "";

// Setup live price updates via WebSocket
function setupLivePriceUpdates(tokenId: string) {
  if (!currentTradeState) return;

  // Remove existing listener if any
  if (currentTradeState.priceListener) {
    try {
      chrome.runtime.onMessage.removeListener(currentTradeState.priceListener);
    } catch (e) {
      // Extension context may be invalid
    }
  }

  try {
    if (!isExtensionContextValid()) {
      // Extension was reloaded - silently skip
      return;
    }

    // Unsubscribe from old tokens if they changed
    if (subscribedYesToken && subscribedYesToken !== currentTradeState.yesTokenId) {
      chrome.runtime.sendMessage({ type: "UNSUBSCRIBE_TOKEN", tokenId: subscribedYesToken });
    }
    if (subscribedNoToken && subscribedNoToken !== currentTradeState.noTokenId) {
      chrome.runtime.sendMessage({ type: "UNSUBSCRIBE_TOKEN", tokenId: subscribedNoToken });
    }

    // Subscribe to new tokens
    if (currentTradeState.yesTokenId) {
      chrome.runtime.sendMessage({ type: "SUBSCRIBE_TOKEN", tokenId: currentTradeState.yesTokenId });
      subscribedYesToken = currentTradeState.yesTokenId;
    }
    if (currentTradeState.noTokenId) {
      chrome.runtime.sendMessage({ type: "SUBSCRIBE_TOKEN", tokenId: currentTradeState.noTokenId });
      subscribedNoToken = currentTradeState.noTokenId;
    }
  } catch (e) {
    // Extension context invalidated (extension reloaded) - silently skip
    return;
  }

  // Listen for price updates and update UI
  const priceListener = (message: any) => {
    if (message.type === "PRICE_UPDATE" && currentTradeState) {
      const prices = message.prices || {};

      // Update Yes/No button prices if we have new prices for those tokens
      const yesPrice = prices[currentTradeState.yesTokenId];
      const noPrice = prices[currentTradeState.noTokenId];

      if (yesPrice !== undefined || noPrice !== undefined) {
        console.log("[PolyZK] Price update received - Yes:", yesPrice, "No:", noPrice);

        const yesPriceEl = document.getElementById("polyzk-yes-price");
        const noPriceEl = document.getElementById("polyzk-no-price");

        if (yesPriceEl && yesPrice !== undefined) {
          yesPriceEl.textContent = formatPriceCents(yesPrice);
        }
        if (noPriceEl && noPrice !== undefined) {
          noPriceEl.textContent = formatPriceCents(noPrice);
        }
      }

      // Refetch quote when prices change (if we have an amount)
      if (currentTradeState.amount > 0) {
        updateQuoteDisplay(currentTradeState.tokenId, currentTradeState.amount, currentTradeState.side);
      }
    }
  };

  currentTradeState.priceListener = priceListener;
  chrome.runtime.onMessage.addListener(priceListener);
  console.log("[PolyZK] Live price updates enabled for tokens - Yes:", currentTradeState.yesTokenId, "No:", currentTradeState.noTokenId);
}

// Format price in cents for display
function formatPriceCents(price: number): string {
  const cents = price * 100;
  // For prices < 10¢ or > 90¢, show one decimal place for precision
  if (cents < 10 || cents > 90) {
    // Remove trailing zero after decimal (e.g., "1.0¢" -> "1¢")
    const formatted = cents.toFixed(1);
    return formatted.endsWith('.0') ? `${Math.round(cents)}¢` : `${formatted}¢`;
  }
  return `${Math.round(cents)}¢`;
}

// Format volume for display (e.g., $1.2M, $500K)
function formatVolume(volume: number): string {
  if (volume >= 1000000) {
    return `$${(volume / 1000000).toFixed(1)}M`;
  } else if (volume >= 1000) {
    return `$${(volume / 1000).toFixed(0)}K`;
  }
  return `$${volume.toFixed(0)}`;
}

// Format date for display (e.g., "Dec 31, 2024")
function formatEndDate(dateStr: string): string {
  try {
    const date = new Date(dateStr);
    return date.toLocaleDateString('en-US', { month: 'short', day: 'numeric', year: 'numeric' });
  } catch {
    return "";
  }
}

// Update side button prices from market data
// Uses bestAsk for Yes (what you pay to buy Yes) and 1-bestBid for No (since No = 1-Yes)
function updateSidePrices(market: any) {
  const yesPriceEl = document.getElementById("polyzk-yes-price");
  const noPriceEl = document.getElementById("polyzk-no-price");

  try {
    // bestAsk is the price to buy Yes, bestBid is the price to sell Yes
    // To buy No, we use 1 - bestBid (or the No token's bestAsk if available)
    let yesPrice = market.bestAsk;
    let noPrice = market.bestBid ? (1 - market.bestBid) : null;

    // Fallback to outcomePrices if bestAsk/bestBid not available
    if (yesPrice === undefined || yesPrice === null) {
      const prices = typeof market.outcomePrices === "string"
        ? JSON.parse(market.outcomePrices)
        : market.outcomePrices || [];
      yesPrice = parseFloat(prices[0] || "0");
      noPrice = parseFloat(prices[1] || "0");
    }

    if (yesPriceEl && yesPrice !== null) yesPriceEl.textContent = formatPriceCents(yesPrice);
    if (noPriceEl && noPrice !== null) noPriceEl.textContent = formatPriceCents(noPrice);
  } catch (e) {
    if (yesPriceEl) yesPriceEl.textContent = "...";
    if (noPriceEl) noPriceEl.textContent = "...";
  }
}

// Update side button prices from outcomes array
function updateSidePricesFromOutcomes(outcomes: any[]) {
  const yesPriceEl = document.getElementById("polyzk-yes-price");
  const noPriceEl = document.getElementById("polyzk-no-price");

  if (outcomes.length >= 2) {
    const yesPrice = outcomes[0]?.price || 0;
    const noPrice = outcomes[1]?.price || 0;

    if (yesPriceEl) yesPriceEl.textContent = formatPriceCents(yesPrice);
    if (noPriceEl) noPriceEl.textContent = formatPriceCents(noPrice);
  }
}

// Show trade confirmation panel
function showTradePanel(tradeData: any) {
  // Remove existing panel if any
  const existing = document.getElementById("polyzk-trade-panel");
  if (existing) existing.remove();
  const existingOverlay = document.getElementById("polyzk-trade-overlay");
  if (existingOverlay) existingOverlay.remove();

  // Lock page scroll
  const scrollY = window.scrollY;
  document.body.style.overflow = "hidden";
  document.body.style.position = "fixed";
  document.body.style.top = `-${scrollY}px`;
  document.body.style.width = "100%";
  document.documentElement.style.overflow = "hidden";
  document.body.dataset.polyzkScrollY = String(scrollY);

  // Create overlay
  const overlay = document.createElement("div");
  overlay.id = "polyzk-trade-overlay";
  overlay.className = "polyzk-overlay";
  overlay.addEventListener("click", (e) => {
    if (e.target === overlay) closeTradePanel();
  });

  // Prevent wheel events from propagating to the page
  overlay.addEventListener("wheel", (e) => {
    e.stopPropagation();
  }, { passive: false });

  // Create panel
  const panel = document.createElement("div");
  panel.id = "polyzk-trade-panel";
  panel.className = "polyzk-trade-panel";

  // Get current event slug
  const eventSlug = getEventSlugFromUrl() || "";

  // Reset amount if switching to a different event
  if (eventSlug !== lastEventSlug) {
    lastUsedAmount = 0;
    lastEventSlug = eventSlug;
  }

  // Use last used amount if available, otherwise use tradeData amount
  const amount = lastUsedAmount > 0 ? lastUsedAmount : (tradeData.amount || 0);
  const imageUrl = tradeData.image || "";

  // Check if this is a multi-market event (has markets array) or single market (has outcomes)
  const markets = tradeData.markets || [];
  const hasMultipleMarkets = markets.length > 1;

  // For single market events, outcomes are Yes/No
  // For multi-market events, each market is an outcome with its own Yes/No
  const outcomes = tradeData.outcomes || [];

  // Initialize trade state (will be updated when user selects)
  // Get initial token IDs from first market or outcomes
  let initialYesTokenId = "";
  let initialNoTokenId = "";
  if (markets.length > 0) {
    const tokenIds = getBothTokenIdsFromMarket(markets[0]);
    initialYesTokenId = tokenIds.yesTokenId;
    initialNoTokenId = tokenIds.noTokenId;
  } else if (outcomes.length >= 2) {
    initialYesTokenId = outcomes[0]?.tokenId || "";
    initialNoTokenId = outcomes[1]?.tokenId || "";
  }

  currentTradeState = {
    tokenId: initialYesTokenId,
    yesTokenId: initialYesTokenId,
    noTokenId: initialNoTokenId,
    amount,
    price: 0,
    side: "BUY",
    marketIndex: 0,
  };

  // Generate outcome selector HTML
  let outcomeSelectorHtml = "";
  const isLoading = tradeData.loading && markets.length === 0 && outcomes.length === 0;

  if (isLoading) {
    // Show skeleton loading state with 10 items
    const skeletonWidths = [60, 75, 50, 65, 80, 55, 70, 45, 72, 58];
    const skeletonItems = skeletonWidths.map(width => `
          <div class="outcome-option skeleton-option">
            <span class="skeleton skeleton-text" style="width: ${width}%"></span>
          </div>
    `).join('');

    outcomeSelectorHtml = `
      <div class="polyzk-outcome-selector">
        <label class="selector-label">Select Outcome</label>
        <div class="outcome-list" id="polyzk-market-list">
          ${skeletonItems}
        </div>
      </div>
    `;
  } else if (hasMultipleMarkets) {
    // Multi-market event: show market selection
    outcomeSelectorHtml = `
      <div class="polyzk-outcome-selector">
        <label class="selector-label">Select Outcome</label>
        <div class="outcome-list" id="polyzk-market-list">
          ${markets.map((market: any, idx: number) => {
            // Use groupItemTitle if available (short form), otherwise extract from question
            let name = market.groupItemTitle;
            if (!name) {
              const question = market.question || "";
              name = question.replace(/^Will\s+/i, "").replace(/\s+win.*$/i, "").trim();
            }
            if (!name) name = `Option ${idx + 1}`;

            return `
              <button class="outcome-option ${idx === 0 ? 'selected' : ''}" data-market-index="${idx}">
                <span class="outcome-name">${name}</span>
              </button>
            `;
          }).join("")}
        </div>
      </div>
    `;
  } else if (outcomes.length > 0) {
    // Single market with Yes/No outcomes - no outcome selector needed, just use side buttons
    outcomeSelectorHtml = "";
  }

  // Get initial prices for side selector
  let initialYesPrice = 0;
  let initialNoPrice = 0;
  if (hasMultipleMarkets && markets[0]) {
    try {
      const prices = typeof markets[0].outcomePrices === "string"
        ? JSON.parse(markets[0].outcomePrices)
        : markets[0].outcomePrices || [];
      initialYesPrice = parseFloat(prices[0] || "0");
      initialNoPrice = parseFloat(prices[1] || "0");
    } catch (e) {}
  } else if (outcomes.length >= 2) {
    initialYesPrice = outcomes[0]?.price || 0;
    initialNoPrice = outcomes[1]?.price || 0;
  }

  // Generate side selector (Buy/Sell) with prices
  const sideSelectorHtml = `
    <div class="polyzk-side-selector">
      <button class="side-option selected" data-side="BUY">
        <span class="side-label">Buy Yes</span>
        <span class="side-price" id="polyzk-yes-price">${initialYesPrice > 0 ? formatPriceCents(initialYesPrice) : '<span class="skeleton skeleton-price"></span>'}</span>
      </button>
      <button class="side-option" data-side="SELL">
        <span class="side-label">Buy No</span>
        <span class="side-price" id="polyzk-no-price">${initialNoPrice > 0 ? formatPriceCents(initialNoPrice) : '<span class="skeleton skeleton-price"></span>'}</span>
      </button>
    </div>
  `;

  panel.innerHTML = `
    <div class="polyzk-panel-header">
      <div class="polyzk-header-left">
        <div class="polyzk-logo"></div>
        <span class="polyzk-header-title">PolyZK</span>
        <span class="polyzk-version">v0.0.1</span>
      </div>
      <div class="polyzk-header-right">
        <a href="https://polyzk.io" target="_blank" class="polyzk-header-link" title="Website">
          <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
            <circle cx="12" cy="12" r="10"/>
            <path d="M2 12h20M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"/>
          </svg>
        </a>
        <a href="https://discord.gg/polyzk" target="_blank" class="polyzk-header-link" title="Discord">
          <svg width="18" height="18" viewBox="0 0 24 24" fill="currentColor">
            <path d="M20.317 4.37a19.791 19.791 0 0 0-4.885-1.515.074.074 0 0 0-.079.037c-.21.375-.444.864-.608 1.25a18.27 18.27 0 0 0-5.487 0 12.64 12.64 0 0 0-.617-1.25.077.077 0 0 0-.079-.037A19.736 19.736 0 0 0 3.677 4.37a.07.07 0 0 0-.032.027C.533 9.046-.32 13.58.099 18.057a.082.082 0 0 0 .031.057 19.9 19.9 0 0 0 5.993 3.03.078.078 0 0 0 .084-.028 14.09 14.09 0 0 0 1.226-1.994.076.076 0 0 0-.041-.106 13.107 13.107 0 0 1-1.872-.892.077.077 0 0 1-.008-.128 10.2 10.2 0 0 0 .372-.292.074.074 0 0 1 .077-.01c3.928 1.793 8.18 1.793 12.062 0a.074.074 0 0 1 .078.01c.12.098.246.198.373.292a.077.077 0 0 1-.006.127 12.299 12.299 0 0 1-1.873.892.077.077 0 0 0-.041.107c.36.698.772 1.362 1.225 1.993a.076.076 0 0 0 .084.028 19.839 19.839 0 0 0 6.002-3.03.077.077 0 0 0 .032-.054c.5-5.177-.838-9.674-3.549-13.66a.061.061 0 0 0-.031-.03zM8.02 15.33c-1.183 0-2.157-1.085-2.157-2.419 0-1.333.956-2.419 2.157-2.419 1.21 0 2.176 1.096 2.157 2.42 0 1.333-.956 2.418-2.157 2.418zm7.975 0c-1.183 0-2.157-1.085-2.157-2.419 0-1.333.955-2.419 2.157-2.419 1.21 0 2.176 1.096 2.157 2.42 0 1.333-.946 2.418-2.157 2.418z"/>
          </svg>
        </a>
        <button class="polyzk-panel-close" id="polyzk-close">
          <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
            <path d="M18 6L6 18M6 6l12 12"/>
          </svg>
        </button>
      </div>
    </div>

    <div class="polyzk-panel-content">
      <div class="polyzk-market-header">
        <div class="polyzk-image-wrapper">
          <div class="polyzk-image-bar"></div>
          ${imageUrl ? `<img src="${imageUrl}" alt="" class="polyzk-market-image" />` : `<div class="polyzk-market-image skeleton"></div>`}
        </div>
        <div class="polyzk-market-info">
          <div class="polyzk-market-title">${tradeData.title || "Unknown Market"}</div>
          <div class="polyzk-market-meta" id="polyzk-market-meta">
            ${tradeData.loading ? `
              <span class="meta-item skeleton-meta"><span class="skeleton skeleton-meta-text"></span></span>
              <span class="meta-item skeleton-meta"><span class="skeleton skeleton-meta-text"></span></span>
            ` : `
              ${tradeData.volume ? `<span class="meta-item"><span class="meta-label">Vol</span> <span class="meta-value">${formatVolume(tradeData.volume)}</span></span>` : ''}
              ${tradeData.endDate ? `<span class="meta-item"><span class="meta-label">Ends</span> <span class="meta-value">${formatEndDate(tradeData.endDate)}</span></span>` : ''}
            `}
          </div>
        </div>
      </div>

      <div class="polyzk-two-column">
        <div class="polyzk-left-column">
          ${outcomeSelectorHtml}
          ${sideSelectorHtml}
        </div>

        <div class="polyzk-right-column">
          <div class="polyzk-amount-input">
            <label class="amount-label">Amount (USD)</label>
            <div class="amount-input-wrapper">
              <span class="amount-prefix">$</span>
              <input type="number" id="polyzk-amount" class="amount-input" placeholder="0" min="0" step="1" value="${amount || ''}">
            </div>
            <div class="amount-presets">
              <button class="preset-btn" data-amount="10">$10</button>
              <button class="preset-btn" data-amount="50">$50</button>
              <button class="preset-btn" data-amount="100">$100</button>
              <button class="preset-btn" data-amount="500">$500</button>
            </div>
          </div>

          <div class="polyzk-trade-card">
            <div class="trade-row">
              <div class="trade-item">
                <span class="item-label">Avg Price</span>
                <span class="item-value" id="polyzk-avg-price"><span class="skeleton skeleton-value"></span></span>
              </div>
              <div class="trade-item">
                <span class="item-label">Shares</span>
                <span class="item-value" id="polyzk-live-shares"><span class="skeleton skeleton-value"></span></span>
              </div>
            </div>
            <div class="trade-divider"></div>
            <div class="trade-row">
              <div class="trade-item">
                <span class="item-label">Payout</span>
                <span class="item-value" id="polyzk-live-payout"><span class="skeleton skeleton-value"></span></span>
              </div>
              <div class="trade-item">
                <span class="item-label">To Win</span>
                <span class="item-value highlight" id="polyzk-live-towin"><span class="skeleton skeleton-value"></span></span>
              </div>
            </div>
          </div>

          <div class="polyzk-privacy-banner">
            <div class="privacy-icon">
              <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                <rect x="3" y="11" width="18" height="11" rx="2" ry="2"/>
                <path d="M7 11V7a5 5 0 0 1 10 0v4"/>
              </svg>
            </div>
            <div class="privacy-text">
              <span class="privacy-title">Private & Anonymous</span>
              <span class="privacy-desc">Executed via Midnight ZK proofs</span>
            </div>
          </div>

          <div class="polyzk-actions">
            <button id="polyzk-cancel" class="polyzk-cancel-btn">Cancel</button>
            <button id="polyzk-submit" class="polyzk-submit-btn" disabled>
              Checking wallet...
            </button>
          </div>
        </div>
      </div>
    </div>
  `;

  overlay.appendChild(panel);
  document.body.appendChild(overlay);

  console.log("[PolyZK] Modal opened, markets:", markets.length, "outcomes:", outcomes.length, "amount:", amount);

  // Setup event listeners (this also triggers initial quote fetch)
  setupConfirmationListeners(tradeData, "");
}

// Helper to get token ID from market data
function getTokenIdFromMarket(market: any, side: "BUY" | "SELL"): string {
  try {
    const tokenIds = typeof market.clobTokenIds === "string"
      ? JSON.parse(market.clobTokenIds)
      : market.clobTokenIds || [];
    // BUY = Yes token (index 0), SELL (Buy No) = No token (index 1)
    return side === "BUY" ? tokenIds[0] : tokenIds[1];
  } catch (e) {
    return "";
  }
}

function getBothTokenIdsFromMarket(market: any): { yesTokenId: string; noTokenId: string } {
  try {
    const tokenIds = typeof market.clobTokenIds === "string"
      ? JSON.parse(market.clobTokenIds)
      : market.clobTokenIds || [];
    return { yesTokenId: tokenIds[0] || "", noTokenId: tokenIds[1] || "" };
  } catch (e) {
    return { yesTokenId: "", noTokenId: "" };
  }
}

// Helper to update quote display
function updateQuoteDisplay(tokenId: string, amount: number, side: "BUY" | "SELL") {
  const avgPriceEl = document.getElementById("polyzk-avg-price");
  const sharesEl = document.getElementById("polyzk-live-shares");
  const payoutEl = document.getElementById("polyzk-live-payout");
  const toWinEl = document.getElementById("polyzk-live-towin");
  const submitBtn = document.getElementById("polyzk-submit") as HTMLButtonElement;

  const skeletonHtml = '<span class="skeleton skeleton-value"></span>';

  if (!tokenId || amount <= 0) {
    if (avgPriceEl) avgPriceEl.textContent = "0.00¢";
    if (sharesEl) sharesEl.textContent = "0.00";
    if (payoutEl) payoutEl.textContent = "$0.00";
    if (toWinEl) toWinEl.textContent = "$0.00";
    if (submitBtn) {
      submitBtn.disabled = true;
      submitBtn.innerHTML = 'Enter Amount';
    }
    return;
  }

  // Show skeleton loading state
  if (avgPriceEl) avgPriceEl.innerHTML = skeletonHtml;
  if (sharesEl) sharesEl.innerHTML = skeletonHtml;
  if (payoutEl) payoutEl.innerHTML = skeletonHtml;
  if (toWinEl) toWinEl.innerHTML = skeletonHtml;

  // Note: Always pass "BUY" to the quote API since we're buying tokens
  // The 'side' parameter in our UI determines which token (Yes/No) we're buying,
  // but the API side should always be BUY when purchasing tokens
  console.log("[PolyZK] Fetching quote for token:", tokenId, "amount:", amount);

  chrome.runtime.sendMessage({
    type: "GET_QUOTE",
    tokenId,
    amount,
    side: "BUY" // Always BUY since we're purchasing tokens
  }, (response) => {
    if (response?.quote && currentTradeState) {
      const quote = response.quote;

      if (avgPriceEl) avgPriceEl.textContent = `${(quote.avgPrice * 100).toFixed(2)}¢`;
      if (sharesEl) sharesEl.textContent = quote.shares.toLocaleString('en-US', { minimumFractionDigits: 2, maximumFractionDigits: 2 });
      if (payoutEl) payoutEl.textContent = `$${quote.payout.toLocaleString('en-US', { minimumFractionDigits: 2, maximumFractionDigits: 2 })}`;
      if (toWinEl) toWinEl.textContent = `$${quote.toWin.toLocaleString('en-US', { minimumFractionDigits: 2, maximumFractionDigits: 2 })}`;

      currentTradeState.price = quote.avgPrice;

      // Enable submit button
      if (submitBtn) {
        submitBtn.disabled = false;
        submitBtn.innerHTML = 'Confirm Trade';
      }
    } else {
      // No liquidity or error
      if (avgPriceEl) avgPriceEl.textContent = "No liquidity";
      if (sharesEl) sharesEl.textContent = "-";
      if (payoutEl) payoutEl.textContent = "-";
      if (toWinEl) toWinEl.textContent = "-";
    }
  });
}

function setupConfirmationListeners(tradeData: any, initialTokenId: string) {
  const closeBtn = document.getElementById("polyzk-close");
  const cancelBtn = document.getElementById("polyzk-cancel");
  const submitBtn = document.getElementById("polyzk-submit") as HTMLButtonElement;
  const amountInput = document.getElementById("polyzk-amount") as HTMLInputElement;
  const markets = tradeData.markets || [];
  const outcomes = tradeData.outcomes || [];

  // Close handlers
  closeBtn?.addEventListener("click", closeTradePanel);
  cancelBtn?.addEventListener("click", closeTradePanel);

  // Escape key to close
  const escHandler = (e: KeyboardEvent) => {
    if (e.key === "Escape") closeTradePanel();
  };
  document.addEventListener("keydown", escHandler);

  // Amount input with debounce
  let debounceTimer: ReturnType<typeof setTimeout>;
  if (amountInput) {
    amountInput.addEventListener("input", () => {
      clearTimeout(debounceTimer);
      debounceTimer = setTimeout(() => {
        const amount = parseFloat(amountInput.value) || 0;
        if (currentTradeState) {
          currentTradeState.amount = amount;
          updateQuoteDisplay(currentTradeState.tokenId, amount, currentTradeState.side);
        }
      }, 300); // 300ms debounce
    });
  }

  // Amount preset buttons
  const presetBtns = document.querySelectorAll(".preset-btn");
  presetBtns.forEach(btn => {
    btn.addEventListener("click", () => {
      const amount = parseInt((btn as HTMLElement).dataset.amount || "0");
      if (amountInput) {
        amountInput.value = amount.toString();
      }
      if (currentTradeState) {
        currentTradeState.amount = amount;
        updateQuoteDisplay(currentTradeState.tokenId, amount, currentTradeState.side);
      }
    });
  });

  // Market selection (for multi-market events)
  const marketList = document.getElementById("polyzk-market-list");
  if (marketList) {
    // Ensure scroll works on the outcome list by stopping propagation
    marketList.addEventListener("wheel", (e) => {
      e.stopPropagation();
    });
  }
  if (marketList && markets.length > 0) {
    marketList.addEventListener("mousedown", (e) => {
      const btn = (e.target as HTMLElement).closest(".outcome-option") as HTMLElement;
      if (!btn) return;

      // Prevent default focus behavior
      e.preventDefault();

      // Save scroll position before any changes
      const scrollTop = marketList.scrollTop;

      // Update selection UI
      marketList.querySelectorAll(".outcome-option").forEach(el => el.classList.remove("selected"));
      btn.classList.add("selected");

      // Restore scroll position
      marketList.scrollTop = scrollTop;

      // Update trade state
      const marketIndex = parseInt(btn.dataset.marketIndex || "0");
      const market = markets[marketIndex];
      if (market && currentTradeState) {
        currentTradeState.marketIndex = marketIndex;
        const tokenId = getTokenIdFromMarket(market, currentTradeState.side);
        currentTradeState.tokenId = tokenId;

        // Update quote
        updateQuoteDisplay(tokenId, currentTradeState.amount, currentTradeState.side);
      }
    });

    // Set initial token from first market
    if (markets[0] && currentTradeState) {
      currentTradeState.tokenId = getTokenIdFromMarket(markets[0], currentTradeState.side);
    }
  }

  // Outcome selection (for single-market Yes/No)
  const outcomeList = document.getElementById("polyzk-outcome-list");
  if (outcomeList && outcomes.length > 0) {
    outcomeList.addEventListener("click", (e) => {
      const btn = (e.target as HTMLElement).closest(".outcome-option") as HTMLElement;
      if (!btn) return;

      // Update selection UI
      outcomeList.querySelectorAll(".outcome-option").forEach(el => el.classList.remove("selected"));
      btn.classList.add("selected");

      // Update trade state
      const outcomeIndex = parseInt(btn.dataset.outcomeIndex || "0");
      const outcome = outcomes[outcomeIndex];
      if (outcome && currentTradeState) {
        currentTradeState.tokenId = outcome.tokenId;
        updateQuoteDisplay(outcome.tokenId, currentTradeState.amount, currentTradeState.side);
      }
    });
  }

  // Side selection (Buy Yes / Buy No)
  const sideSelector = document.querySelector(".polyzk-side-selector");
  if (sideSelector) {
    sideSelector.addEventListener("click", (e) => {
      const btn = (e.target as HTMLElement).closest(".side-option") as HTMLElement;
      if (!btn) return;

      // Update selection UI
      sideSelector.querySelectorAll(".side-option").forEach(el => el.classList.remove("selected"));
      btn.classList.add("selected");

      // Update trade state
      const side = btn.dataset.side as "BUY" | "SELL";
      if (currentTradeState) {
        currentTradeState.side = side;
        // Use stored token IDs - BUY=Yes token, SELL=No token
        currentTradeState.tokenId = side === "BUY" ? currentTradeState.yesTokenId : currentTradeState.noTokenId;

        updateQuoteDisplay(currentTradeState.tokenId, currentTradeState.amount, side);
        // Re-subscribe to new token for live updates
        setupLivePriceUpdates(currentTradeState.tokenId);
      }
    });
  }

  // Check wallet and update button
  chrome.storage.local.get(["wallet"], (result) => {
    const wallet = result.wallet;
    if (!wallet?.connected) {
      submitBtn.textContent = "Connect Wallet";
      submitBtn.disabled = true;
      submitBtn.className = "polyzk-submit-btn";
    } else {
      // Wallet is connected - enable button if we have an amount
      if (currentTradeState && currentTradeState.amount > 0) {
        submitBtn.textContent = "Confirm Trade";
        submitBtn.disabled = false;
        submitBtn.className = "polyzk-submit-btn buy";
      } else {
        submitBtn.textContent = "Enter Amount";
        submitBtn.disabled = true;
        submitBtn.className = "polyzk-submit-btn";
      }
    }
  });

  // Initial quote fetch
  if (currentTradeState?.tokenId && currentTradeState.amount > 0) {
    updateQuoteDisplay(currentTradeState.tokenId, currentTradeState.amount, currentTradeState.side);
  }

  // Submit trade
  submitBtn?.addEventListener("click", async () => {
    submitBtn.disabled = true;
    submitBtn.textContent = "Placing order...";

    try {
      const walletData = await chrome.storage.local.get(["wallet"]);
      const wallet = walletData.wallet;

      if (!wallet?.privateKey) {
        showNotification("Please connect your wallet via the extension popup");
        submitBtn.disabled = false;
        submitBtn.textContent = "Connect Wallet";
        return;
      }

      // Use the live price from currentTradeState
      const currentPrice = currentTradeState?.price || tradeData.price;

      const response = await chrome.runtime.sendMessage({
        type: "PLACE_ORDER",
        data: {
          privateKey: wallet.privateKey,
          tokenId: tokenId,
          price: currentPrice,
          amount: tradeData.amount,
          side: tradeData.side,
          market: tradeData,
        },
      });

      if (response.success) {
        showNotification("Order placed privately! 🎉");
        closeTradePanel();
      } else {
        showNotification(`Order failed: ${response.error}`);
        submitBtn.disabled = false;
        submitBtn.textContent = "Retry";
      }
    } catch (error) {
      console.error("[PolyZK] Trade error:", error);
      showNotification("Failed to place order");
      submitBtn.disabled = false;
      submitBtn.textContent = "Retry";
    }
  });
}

function closeTradePanel() {
  // Clean up price listener and unsubscribe (safely - extension may have reloaded)
  if (currentTradeState) {
    // Save the last used amount for next time
    if (currentTradeState.amount > 0) {
      lastUsedAmount = currentTradeState.amount;
    }
    if (currentTradeState.priceListener) {
      try {
        chrome.runtime.onMessage.removeListener(currentTradeState.priceListener);
      } catch (e) {
        // Extension context invalidated, ignore
      }
    }
    // Unsubscribe from both yes and no tokens
    try {
      if (subscribedYesToken) {
        chrome.runtime.sendMessage({ type: "UNSUBSCRIBE_TOKEN", tokenId: subscribedYesToken });
      }
      if (subscribedNoToken) {
        chrome.runtime.sendMessage({ type: "UNSUBSCRIBE_TOKEN", tokenId: subscribedNoToken });
      }
    } catch (e) {
      // Extension context invalidated, ignore
    }
    currentTradeState = null;
    subscribedYesToken = "";
    subscribedNoToken = "";
  }

  const overlay = document.getElementById("polyzk-trade-overlay");
  if (overlay) {
    overlay.classList.add("closing");
    setTimeout(() => overlay.remove(), 200);
  }

  // Restore page scroll
  const scrollY = document.body.dataset.polyzkScrollY || "0";
  document.body.style.removeProperty("overflow");
  document.body.style.removeProperty("position");
  document.body.style.removeProperty("top");
  document.body.style.removeProperty("width");
  document.documentElement.style.removeProperty("overflow");
  delete document.body.dataset.polyzkScrollY;
  window.scrollTo(0, parseInt(scrollY));
}

// Show a temporary notification
function showNotification(message: string) {
  // Remove existing notification
  const existing = document.getElementById("polyzk-notification");
  if (existing) existing.remove();

  const notification = document.createElement("div");
  notification.id = "polyzk-notification";
  notification.className = "polyzk-notification";
  notification.textContent = message;
  document.body.appendChild(notification);

  // Animate in
  setTimeout(() => notification.classList.add("show"), 10);

  // Remove after 3 seconds
  setTimeout(() => {
    notification.classList.remove("show");
    setTimeout(() => notification.remove(), 300);
  }, 3000);
}

// Listen for messages from extension
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.type === "GET_MARKET_DATA") {
    sendResponse({ data: extractMarketData() });
  }
  if (message.type === "PING") {
    sendResponse({ pong: true, url: window.location.href });
  }
  return true;
});

// Watch for DOM changes to re-hook buttons
function watchForChanges() {
  const observer = new MutationObserver(() => {
    hookTradeButtons();
  });

  observer.observe(document.body, {
    childList: true,
    subtree: true,
  });
}

// Initialize
function init() {
  console.log("[PolyZK] Initializing content script, session:", SESSION_ID);

  // Initial setup after page loads
  setTimeout(() => {
    hookTradeButtons();
    watchForChanges();

    // Send initial market data
    const data = extractMarketData();
    if (data.title || data.outcomes?.length) {
      chrome.runtime.sendMessage({ type: "MARKET_DATA", data });
    }
  }, 1000);

  // Also try immediately in case page is already loaded
  hookTradeButtons();
}

if (document.readyState === "loading") {
  document.addEventListener("DOMContentLoaded", init);
} else {
  init();
}
