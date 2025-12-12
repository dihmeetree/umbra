const API_BASE = '/api'

export interface Wallet {
  name: string
  publicKey: string
  privateBalance: string  // pUSDM - for purchasing
  publicBalance: string   // USDM - for depositing
}

export interface Listing {
  listingHash: string
  itemDescription: string
  pricePerUnit: string
  quantity: string
  remainingQuantity: string
  escrowDeadline: string  // Unix timestamp - 0 means no timeout
  status: 'Active' | 'Sold' | 'Completed' | 'Claimed' | 'Cancelled' | 'Refunded'
}

export interface Purchase {
  listingHash: string
  itemDescription: string
  pricePerUnit: string
  quantity: string
  totalPrice: string
  purchasedAt: number
  status: 'Pending' | 'Confirmed' | 'Refunded'
  buyerCommitment: string
  nonce: string
}

export interface Stats {
  totalWallets: number
  totalListings: number
  activeListings: number
  totalSales: number
}

async function fetchApi<T>(
  endpoint: string,
  options?: RequestInit
): Promise<T> {
  const response = await fetch(`${API_BASE}${endpoint}`, {
    ...options,
    headers: {
      'Content-Type': 'application/json',
      ...options?.headers
    }
  })

  const data = await response.json()

  if (!data.success) {
    throw new Error(data.error || 'API request failed')
  }

  return data
}

// Wallet endpoints
export async function createWallet(name: string): Promise<Wallet> {
  const data = await fetchApi<{ success: boolean; wallet: Wallet }>(
    '/wallet/create',
    {
      method: 'POST',
      body: JSON.stringify({ name })
    }
  )
  return data.wallet
}

export async function getWallet(name: string): Promise<Wallet> {
  const data = await fetchApi<{ success: boolean; wallet: Wallet }>(
    `/wallet/${name}`
  )
  return data.wallet
}

export async function listWallets(): Promise<Wallet[]> {
  const data = await fetchApi<{ success: boolean; wallets: Wallet[] }>(
    '/wallets'
  )
  return data.wallets
}

// Listing endpoints
export async function createListing(
  walletName: string,
  itemDescription: string,
  pricePerUnit: string,
  quantity: string = '1',
  escrowDeadline: string = '0'  // 0 = no timeout, otherwise Unix timestamp
): Promise<Listing> {
  const data = await fetchApi<{ success: boolean; listing: Listing }>(
    '/listing/create',
    {
      method: 'POST',
      body: JSON.stringify({ walletName, itemDescription, pricePerUnit, quantity, escrowDeadline })
    }
  )
  return data.listing
}

export async function getListing(hash: string): Promise<Listing> {
  const data = await fetchApi<{ success: boolean; listing: Listing }>(
    `/listing/${hash}`
  )
  return data.listing
}

export async function getListingDetails(
  hash: string,
  sellerWallet: string
): Promise<any> {
  const data = await fetchApi<{ success: boolean; details: any }>(
    `/listing/${hash}/details?sellerWallet=${sellerWallet}`
  )
  return data.details
}

export async function getWalletListings(walletName: string): Promise<Listing[]> {
  const data = await fetchApi<{ success: boolean; listings: Listing[] }>(
    `/wallet/${walletName}/listings`
  )
  return data.listings
}

export async function cancelListing(
  hash: string,
  walletName: string
): Promise<void> {
  await fetchApi(`/listing/${hash}/cancel`, {
    method: 'POST',
    body: JSON.stringify({ walletName })
  })
}

// Purchase endpoints
export async function purchaseListing(
  hash: string,
  buyerWallet: string,
  listingDetails: any,
  quantity: string = '1',
  nonce?: string
): Promise<{ success: boolean; purchase: { buyerCommitment: string; nonce: string } }> {
  const data = await fetchApi<{ success: boolean; purchase: { buyerCommitment: string; nonce: string } }>(
    `/listing/${hash}/purchase`,
    {
      method: 'POST',
      body: JSON.stringify({ buyerWallet, listingDetails, quantity, nonce })
    }
  )
  return data
}

// Buyer confirms receipt (releases funds to seller)
export async function confirmReceipt(
  hash: string,
  walletName: string,
  nonce: string
): Promise<void> {
  await fetchApi(`/listing/${hash}/confirm`, {
    method: 'POST',
    body: JSON.stringify({ walletName, nonce })
  })
}

// Seller claims payment (after buyer confirms)
export async function claimPayment(
  hash: string,
  walletName: string
): Promise<void> {
  await fetchApi(`/listing/${hash}/claim`, {
    method: 'POST',
    body: JSON.stringify({ walletName })
  })
}

// Alias for backwards compatibility
export async function markAsClaimed(
  hash: string,
  walletName: string
): Promise<void> {
  await claimPayment(hash, walletName)
}

export async function getWalletPurchases(
  walletName: string
): Promise<Purchase[]> {
  const data = await fetchApi<{ success: boolean; purchases: Purchase[] }>(
    `/wallet/${walletName}/purchases`
  )
  return data.purchases
}

// Stats endpoint
export async function getStats(): Promise<Stats> {
  const data = await fetchApi<{ success: boolean; stats: Stats }>('/stats')
  return data.stats
}

// Deposit public USDM to receive private pUSDM
export async function deposit(
  walletName: string,
  amount: string
): Promise<{ privateBalance: string; publicBalance: string }> {
  const data = await fetchApi<{
    success: boolean
    privateBalance: string
    publicBalance: string
  }>(`/wallet/${walletName}/deposit`, {
    method: 'POST',
    body: JSON.stringify({ amount })
  })
  return {
    privateBalance: data.privateBalance,
    publicBalance: data.publicBalance
  }
}

// Withdraw private pUSDM to receive public USDM
export async function withdraw(
  walletName: string,
  amount: string
): Promise<{ privateBalance: string; publicBalance: string }> {
  const data = await fetchApi<{
    success: boolean
    privateBalance: string
    publicBalance: string
  }>(`/wallet/${walletName}/withdraw`, {
    method: 'POST',
    body: JSON.stringify({ amount })
  })
  return {
    privateBalance: data.privateBalance,
    publicBalance: data.publicBalance
  }
}
