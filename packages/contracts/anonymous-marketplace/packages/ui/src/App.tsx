import { Component, createSignal, createEffect, onMount, For, Show } from 'solid-js'
import { WalletSelector } from './components/WalletSelector'
import { CreateListing } from './components/CreateListing'
import { ListingCard } from './components/ListingCard'
import { PurchaseModal } from './components/PurchaseModal'
import { PurchaseList } from './components/PurchaseList'
import { StatsDisplay } from './components/Stats'
import * as api from './lib/api'
import type { Wallet, Listing, Purchase, Stats } from './lib/api'

const App: Component = () => {
  const [wallets, setWallets] = createSignal<Wallet[]>([])
  const [selectedWallet, setSelectedWallet] = createSignal<Wallet | null>(null)
  const [myListings, setMyListings] = createSignal<Listing[]>([])
  const [myPurchases, setMyPurchases] = createSignal<Purchase[]>([])
  const [stats, setStats] = createSignal<Stats | null>(null)
  const [purchaseListing, setPurchaseListing] = createSignal<Listing | null>(null)
  const [lookupHash, setLookupHash] = createSignal('')
  const [lookupResult, setLookupResult] = createSignal<Listing | null>(null)
  const [lookupError, setLookupError] = createSignal('')
  const [activeTab, setActiveTab] = createSignal<'sell' | 'buy' | 'purchases'>('sell')

  // Load initial data
  onMount(async () => {
    await refreshAll()
  })

  // Refresh wallet data when selected wallet changes
  createEffect(async () => {
    const wallet = selectedWallet()
    if (wallet) {
      await refreshWalletData(wallet.name)
    } else {
      setMyListings([])
      setMyPurchases([])
    }
  })

  const refreshAll = async () => {
    try {
      const [walletsData, statsData] = await Promise.all([
        api.listWallets(),
        api.getStats()
      ])
      setWallets(walletsData)
      setStats(statsData)

      // Update selected wallet with fresh data (for balance updates)
      const current = selectedWallet()
      if (current) {
        const updated = walletsData.find(w => w.name === current.name)
        if (updated) {
          setSelectedWallet(updated)
        }
      }
    } catch (e) {
      console.error('Failed to refresh data:', e)
    }
  }

  const refreshWalletData = async (walletName: string) => {
    try {
      const [listings, purchases] = await Promise.all([
        api.getWalletListings(walletName),
        api.getWalletPurchases(walletName)
      ])
      setMyListings(listings)
      setMyPurchases(purchases)
    } catch (e) {
      console.error('Failed to refresh wallet data:', e)
    }
  }

  const handleCreateWallet = async (name: string) => {
    const wallet = await api.createWallet(name)
    setWallets([...wallets(), wallet])
    setSelectedWallet(wallet)
    await refreshAll()
  }

  const handleDeposit = async (amount: string) => {
    const wallet = selectedWallet()
    if (!wallet) return

    await api.deposit(wallet.name, amount)
    await refreshAll()
  }

  const handleWithdraw = async (amount: string) => {
    const wallet = selectedWallet()
    if (!wallet) return

    await api.withdraw(wallet.name, amount)
    await refreshAll()
  }

  const handleCreateListing = async (description: string, pricePerUnit: string, quantity: string, escrowDeadline: string) => {
    const wallet = selectedWallet()
    if (!wallet) return

    await api.createListing(wallet.name, description, pricePerUnit, quantity, escrowDeadline)
    await refreshWalletData(wallet.name)
    await refreshAll()
  }

  const handleCancelListing = async (hash: string) => {
    const wallet = selectedWallet()
    if (!wallet) return

    await api.cancelListing(hash, wallet.name)
    await refreshWalletData(wallet.name)
    await refreshAll()
  }

  const handleClaimListing = async (hash: string) => {
    const wallet = selectedWallet()
    if (!wallet) return

    await api.claimPayment(hash, wallet.name)
    await refreshWalletData(wallet.name)
    await refreshAll()
  }

  const handleConfirmReceipt = async (hash: string, nonce: string) => {
    const wallet = selectedWallet()
    if (!wallet) return

    await api.confirmReceipt(hash, wallet.name, nonce)
    await refreshWalletData(wallet.name)
    await refreshAll()
  }

  const handleLookupListing = async () => {
    const hash = lookupHash().trim()
    if (!hash) {
      setLookupError('Please enter a listing hash')
      return
    }

    setLookupError('')
    setLookupResult(null)

    try {
      const listing = await api.getListing(hash)
      setLookupResult(listing)
    } catch (e) {
      setLookupError((e as Error).message)
    }
  }

  const handlePurchase = async (listingHash: string, quantity: string) => {
    const wallet = selectedWallet()
    const listing = lookupResult()
    if (!wallet || !listing) return

    // Get listing details (in real app, seller would share these privately)
    // For demo, we use the lookup which simulates knowing the seller
    const allListings = await Promise.all(
      wallets().map((w) => api.getWalletListings(w.name))
    )

    // Find the listing owner
    let sellerWallet = ''
    for (let i = 0; i < wallets().length; i++) {
      const found = allListings[i].find((l) => l.listingHash === listingHash)
      if (found) {
        sellerWallet = wallets()[i].name
        break
      }
    }

    if (!sellerWallet) {
      throw new Error('Could not find listing seller')
    }

    const details = await api.getListingDetails(listingHash, sellerWallet)
    await api.purchaseListing(listingHash, wallet.name, details, quantity)

    setPurchaseListing(null)
    setLookupResult(null)
    setLookupHash('')
    await refreshWalletData(wallet.name)
    await refreshAll()
  }

  return (
    <div class="min-h-screen bg-gray-900 text-white">
      <header class="bg-gray-800 border-b border-gray-700">
        <div class="max-w-6xl mx-auto px-4 py-4">
          <h1 class="text-2xl font-bold">Anonymous Marketplace</h1>
          <p class="text-gray-400 text-sm">
            Privacy-preserving peer-to-peer trading
          </p>
        </div>
      </header>

      <main class="max-w-6xl mx-auto px-4 py-6">
        {/* Stats */}
        <div class="mb-6">
          <StatsDisplay stats={stats()} />
        </div>

        <div class="grid grid-cols-1 lg:grid-cols-3 gap-6">
          {/* Sidebar - Wallet */}
          <div class="space-y-6">
            <WalletSelector
              wallets={wallets()}
              selectedWallet={selectedWallet()}
              onSelect={setSelectedWallet}
              onCreate={handleCreateWallet}
              onDeposit={handleDeposit}
              onWithdraw={handleWithdraw}
            />

            <Show when={selectedWallet()}>
              <CreateListing
                wallet={selectedWallet()}
                onSubmit={handleCreateListing}
              />
            </Show>
          </div>

          {/* Main Content */}
          <div class="lg:col-span-2 space-y-6">
            {/* Tabs */}
            <div class="flex border-b border-gray-700">
              <button
                onClick={() => setActiveTab('sell')}
                class={`px-4 py-2 font-medium border-b-2 -mb-px ${
                  activeTab() === 'sell'
                    ? 'border-blue-500 text-white'
                    : 'border-transparent text-gray-400 hover:text-white'
                }`}
              >
                My Listings
              </button>
              <button
                onClick={() => setActiveTab('buy')}
                class={`px-4 py-2 font-medium border-b-2 -mb-px ${
                  activeTab() === 'buy'
                    ? 'border-blue-500 text-white'
                    : 'border-transparent text-gray-400 hover:text-white'
                }`}
              >
                Browse / Buy
              </button>
              <button
                onClick={() => setActiveTab('purchases')}
                class={`px-4 py-2 font-medium border-b-2 -mb-px ${
                  activeTab() === 'purchases'
                    ? 'border-blue-500 text-white'
                    : 'border-transparent text-gray-400 hover:text-white'
                }`}
              >
                My Purchases
              </button>
            </div>

            {/* My Listings Tab */}
            <Show when={activeTab() === 'sell'}>
              <Show
                when={selectedWallet()}
                fallback={
                  <div class="bg-gray-800 rounded-lg p-8 text-center">
                    <p class="text-gray-400">
                      Select or create a wallet to view your listings
                    </p>
                  </div>
                }
              >
                <Show
                  when={myListings().length > 0}
                  fallback={
                    <div class="bg-gray-800 rounded-lg p-8 text-center">
                      <p class="text-gray-400">No listings yet</p>
                      <p class="text-sm text-gray-500 mt-2">
                        Create your first anonymous listing using the form
                      </p>
                    </div>
                  }
                >
                  <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
                    <For each={myListings()}>
                      {(listing) => (
                        <ListingCard
                          listing={listing}
                          isOwner={true}
                          onCancel={handleCancelListing}
                          onClaim={handleClaimListing}
                        />
                      )}
                    </For>
                  </div>
                </Show>
              </Show>
            </Show>

            {/* Browse / Buy Tab */}
            <Show when={activeTab() === 'buy'}>
              <div class="bg-gray-800 rounded-lg p-4">
                <h3 class="font-medium mb-3">Lookup Listing by Hash</h3>
                <p class="text-sm text-gray-400 mb-4">
                  In this anonymous marketplace, listings are private. You need
                  the listing hash (shared by the seller) to find and purchase
                  items.
                </p>

                <div class="flex gap-2 mb-4">
                  <input
                    type="text"
                    value={lookupHash()}
                    onInput={(e) => setLookupHash(e.currentTarget.value)}
                    placeholder="Enter listing hash..."
                    class="flex-1 bg-gray-700 border border-gray-600 rounded px-3 py-2 text-sm font-mono focus:outline-none focus:border-blue-500"
                  />
                  <button
                    onClick={handleLookupListing}
                    class="bg-blue-600 hover:bg-blue-700 px-4 py-2 rounded font-medium"
                  >
                    Lookup
                  </button>
                </div>

                <Show when={lookupError()}>
                  <p class="text-red-400 text-sm mb-4">{lookupError()}</p>
                </Show>

                <Show when={lookupResult()}>
                  <div class="border-t border-gray-700 pt-4">
                    <h4 class="text-sm text-gray-400 mb-3">Found Listing:</h4>
                    <ListingCard
                      listing={lookupResult()!}
                      isOwner={false}
                      onBuy={(hash) => {
                        setPurchaseListing(lookupResult())
                      }}
                    />
                  </div>
                </Show>
              </div>
            </Show>

            {/* My Purchases Tab */}
            <Show when={activeTab() === 'purchases'}>
              <Show
                when={selectedWallet()}
                fallback={
                  <div class="bg-gray-800 rounded-lg p-8 text-center">
                    <p class="text-gray-400">
                      Select a wallet to view your purchases
                    </p>
                  </div>
                }
              >
                <PurchaseList purchases={myPurchases()} onConfirmReceipt={handleConfirmReceipt} />
              </Show>
            </Show>
          </div>
        </div>
      </main>

      {/* Purchase Modal */}
      <PurchaseModal
        listing={purchaseListing()}
        wallet={selectedWallet()}
        onConfirm={handlePurchase}
        onClose={() => setPurchaseListing(null)}
      />
    </div>
  )
}

export default App
