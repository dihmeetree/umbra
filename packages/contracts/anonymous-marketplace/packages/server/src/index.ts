import { Hono } from 'hono'
import { cors } from 'hono/cors'
import { serve } from '@hono/node-server'
import { MarketplaceSimulator } from './simulator.js'

const app = new Hono()
const PORT = Number(process.env.PORT) || 3001

// Middleware
app.use('*', cors())

// Initialize the marketplace simulator
const marketplace = new MarketplaceSimulator()

// Health check
app.get('/health', (c) => {
  return c.json({ status: 'ok', timestamp: Date.now() })
})

// ==================== WALLET ENDPOINTS ====================

// Create a new wallet
app.post('/api/wallet/create', async (c) => {
  try {
    const { name } = await c.req.json()
    const wallet = marketplace.createWallet(name)
    return c.json({
      success: true,
      wallet: {
        name: wallet.name,
        publicKey: wallet.coinPublicKey,
        privateBalance: wallet.privateBalance.toString(),
        publicBalance: wallet.publicBalance.toString()
      }
    })
  } catch (error) {
    return c.json({ success: false, error: (error as Error).message }, 500)
  }
})

// Get wallet by name
app.get('/api/wallet/:name', (c) => {
  try {
    const wallet = marketplace.getWallet(c.req.param('name'))
    if (!wallet) {
      return c.json({ success: false, error: 'Wallet not found' }, 404)
    }
    return c.json({
      success: true,
      wallet: {
        name: wallet.name,
        publicKey: wallet.coinPublicKey,
        privateBalance: wallet.privateBalance.toString(),
        publicBalance: wallet.publicBalance.toString()
      }
    })
  } catch (error) {
    return c.json({ success: false, error: (error as Error).message }, 500)
  }
})

// List all wallets
app.get('/api/wallets', (c) => {
  try {
    const wallets = marketplace.listWallets()
    return c.json({
      success: true,
      wallets: wallets.map(w => ({
        name: w.name,
        publicKey: w.coinPublicKey,
        privateBalance: w.privateBalance.toString(),
        publicBalance: w.publicBalance.toString()
      }))
    })
  } catch (error) {
    return c.json({ success: false, error: (error as Error).message }, 500)
  }
})

// ==================== BALANCE ENDPOINTS ====================

// Deposit public USDM to receive private pUSDM
app.post('/api/wallet/:name/deposit', async (c) => {
  try {
    const { amount } = await c.req.json()
    if (amount === undefined) {
      return c.json({ success: false, error: 'amount required' }, 400)
    }

    const result = marketplace.deposit(c.req.param('name'), BigInt(amount))
    return c.json({
      success: true,
      privateBalance: result.newPrivateBalance.toString(),
      publicBalance: result.newPublicBalance.toString()
    })
  } catch (error) {
    return c.json({ success: false, error: (error as Error).message }, 500)
  }
})

// Withdraw private pUSDM to receive public USDM
app.post('/api/wallet/:name/withdraw', async (c) => {
  try {
    const { amount } = await c.req.json()
    if (amount === undefined) {
      return c.json({ success: false, error: 'amount required' }, 400)
    }

    const result = marketplace.withdraw(c.req.param('name'), BigInt(amount))
    return c.json({
      success: true,
      privateBalance: result.newPrivateBalance.toString(),
      publicBalance: result.newPublicBalance.toString()
    })
  } catch (error) {
    return c.json({ success: false, error: (error as Error).message }, 500)
  }
})

// ==================== LISTING ENDPOINTS ====================

// Create a new listing
app.post('/api/listing/create', async (c) => {
  try {
    const { walletName, itemDescription, pricePerUnit, quantity, escrowDeadline } = await c.req.json()

    if (!walletName || !itemDescription || pricePerUnit === undefined) {
      return c.json({
        success: false,
        error: 'Missing required fields: walletName, itemDescription, pricePerUnit'
      }, 400)
    }

    // quantity defaults to 1, escrowDeadline defaults to 0 (no timeout)
    const qty = quantity ? BigInt(quantity) : 1n
    const deadline = escrowDeadline ? BigInt(escrowDeadline) : 0n

    const result = marketplace.createListing(walletName, itemDescription, BigInt(pricePerUnit), qty, deadline)

    return c.json({
      success: true,
      listing: {
        listingHash: result.listingHash,
        itemDescription,
        pricePerUnit: pricePerUnit.toString(),
        quantity: qty.toString(),
        remainingQuantity: qty.toString(),
        escrowDeadline: deadline.toString(),
        status: 'Active'
      }
    })
  } catch (error) {
    return c.json({ success: false, error: (error as Error).message }, 500)
  }
})

// Get listing by hash (requires knowing the hash - privacy feature!)
app.get('/api/listing/:hash', (c) => {
  try {
    const listing = marketplace.getListing(c.req.param('hash'))
    if (!listing) {
      return c.json({ success: false, error: 'Listing not found' }, 404)
    }
    return c.json({ success: true, listing })
  } catch (error) {
    return c.json({ success: false, error: (error as Error).message }, 500)
  }
})

// Get listing details (for purchase - seller shares this with buyer)
app.get('/api/listing/:hash/details', (c) => {
  try {
    const sellerWallet = c.req.query('sellerWallet')
    if (!sellerWallet) {
      return c.json({
        success: false,
        error: 'sellerWallet query param required'
      }, 400)
    }

    const details = marketplace.getListingDetails(
      c.req.param('hash'),
      sellerWallet
    )

    if (!details) {
      return c.json({
        success: false,
        error: 'Listing details not found'
      }, 404)
    }

    return c.json({ success: true, details })
  } catch (error) {
    return c.json({ success: false, error: (error as Error).message }, 500)
  }
})

// Get all listings for a wallet (seller's view)
app.get('/api/wallet/:name/listings', (c) => {
  try {
    const listings = marketplace.getWalletListings(c.req.param('name'))
    return c.json({ success: true, listings })
  } catch (error) {
    return c.json({ success: false, error: (error as Error).message }, 500)
  }
})

// Cancel a listing
app.post('/api/listing/:hash/cancel', async (c) => {
  try {
    const { walletName } = await c.req.json()
    if (!walletName) {
      return c.json({
        success: false,
        error: 'walletName required'
      }, 400)
    }

    marketplace.cancelListing(c.req.param('hash'), walletName)
    return c.json({ success: true, message: 'Listing cancelled' })
  } catch (error) {
    return c.json({ success: false, error: (error as Error).message }, 500)
  }
})

// ==================== PURCHASE ENDPOINTS ====================

// Purchase an item
app.post('/api/listing/:hash/purchase', async (c) => {
  try {
    const { buyerWallet, listingDetails, quantity, nonce } = await c.req.json()

    if (!buyerWallet || !listingDetails) {
      return c.json({
        success: false,
        error: 'buyerWallet and listingDetails required'
      }, 400)
    }

    // quantity defaults to 1
    const purchaseQty = quantity ? BigInt(quantity) : 1n

    const result = marketplace.purchaseListing(
      c.req.param('hash'),
      buyerWallet,
      listingDetails,
      purchaseQty,
      nonce
    )

    return c.json({
      success: true,
      purchase: result
    })
  } catch (error) {
    return c.json({ success: false, error: (error as Error).message }, 500)
  }
})

// Buyer confirms receipt (releases funds to seller)
app.post('/api/listing/:hash/confirm', async (c) => {
  try {
    const { walletName, nonce } = await c.req.json()
    if (!walletName || !nonce) {
      return c.json({
        success: false,
        error: 'walletName and nonce required'
      }, 400)
    }

    marketplace.confirmReceipt(c.req.param('hash'), walletName, nonce)
    return c.json({ success: true, message: 'Receipt confirmed - seller can now claim payment' })
  } catch (error) {
    return c.json({ success: false, error: (error as Error).message }, 500)
  }
})

// Seller claims payment (after buyer confirms)
app.post('/api/listing/:hash/claim', async (c) => {
  try {
    const { walletName } = await c.req.json()
    if (!walletName) {
      return c.json({
        success: false,
        error: 'walletName required'
      }, 400)
    }

    marketplace.claimPayment(c.req.param('hash'), walletName)
    return c.json({ success: true, message: 'Payment claimed' })
  } catch (error) {
    return c.json({ success: false, error: (error as Error).message }, 500)
  }
})

// Get wallet's purchases
app.get('/api/wallet/:name/purchases', (c) => {
  try {
    const purchases = marketplace.getWalletPurchases(c.req.param('name'))
    return c.json({ success: true, purchases })
  } catch (error) {
    return c.json({ success: false, error: (error as Error).message }, 500)
  }
})

// ==================== STATS ENDPOINTS ====================

// Get marketplace stats
app.get('/api/stats', (c) => {
  try {
    const stats = marketplace.getStats()
    return c.json({ success: true, stats })
  } catch (error) {
    return c.json({ success: false, error: (error as Error).message }, 500)
  }
})

console.log(`Marketplace server running on http://localhost:${PORT}`)
console.log('Anonymous marketplace ready!')

serve({
  fetch: app.fetch,
  port: PORT
})
