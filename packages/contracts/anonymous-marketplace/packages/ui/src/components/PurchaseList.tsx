import { Component, createSignal, For, Show } from 'solid-js'
import type { Purchase } from '../lib/api'

interface PurchaseListProps {
  purchases: Purchase[]
  onConfirmReceipt: (listingHash: string, nonce: string) => Promise<void>
}

export const PurchaseList: Component<PurchaseListProps> = (props) => {
  const [confirming, setConfirming] = createSignal<string | null>(null)

  const formatDate = (timestamp: number) => {
    return new Date(timestamp).toLocaleString()
  }

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'Pending': return 'text-yellow-400'
      case 'Confirmed': return 'text-green-400'
      case 'Refunded': return 'text-orange-400'
      default: return 'text-gray-400'
    }
  }

  const getStatusText = (status: string) => {
    switch (status) {
      case 'Pending': return 'Awaiting your confirmation'
      case 'Confirmed': return 'Confirmed - seller can claim'
      case 'Refunded': return 'Refunded'
      default: return status
    }
  }

  const handleConfirm = async (listingHash: string, nonce: string) => {
    setConfirming(listingHash + nonce)
    try {
      await props.onConfirmReceipt(listingHash, nonce)
    } finally {
      setConfirming(null)
    }
  }

  return (
    <div class="bg-gray-800 rounded-lg p-4">
      <h2 class="text-lg font-semibold mb-4">My Purchases</h2>

      <Show
        when={props.purchases.length > 0}
        fallback={<p class="text-gray-400 text-sm">No purchases yet</p>}
      >
        <div class="space-y-3">
          <For each={props.purchases}>
            {(purchase) => (
              <div class="bg-gray-700 rounded p-3">
                <div class="flex justify-between items-start">
                  <div>
                    <p class="font-medium">{purchase.itemDescription}</p>
                    <p class="text-xs text-gray-500 font-mono truncate">
                      {purchase.listingHash.slice(0, 16)}...
                    </p>
                  </div>
                  <div class="text-right">
                    <p class="text-green-400 font-bold">
                      {purchase.totalPrice}
                      <span class="text-xs text-gray-400 ml-1">pUSDM</span>
                    </p>
                    <p class="text-xs text-gray-400">
                      {purchase.quantity} x {purchase.pricePerUnit}
                    </p>
                  </div>
                </div>
                <div class="flex justify-between items-center mt-2">
                  <div>
                    <p class="text-xs text-gray-400">
                      Purchased: {formatDate(purchase.purchasedAt)}
                    </p>
                    <p class={`text-xs ${getStatusColor(purchase.status)}`}>
                      {getStatusText(purchase.status)}
                    </p>
                  </div>
                  <Show when={purchase.status === 'Pending'}>
                    <button
                      onClick={() => handleConfirm(purchase.listingHash, purchase.nonce)}
                      disabled={confirming() === purchase.listingHash + purchase.nonce}
                      class="bg-green-600 hover:bg-green-700 disabled:bg-green-800 disabled:opacity-50 px-3 py-1 rounded text-sm font-medium"
                    >
                      {confirming() === purchase.listingHash + purchase.nonce ? 'Confirming...' : 'Confirm Receipt'}
                    </button>
                  </Show>
                </div>
              </div>
            )}
          </For>
        </div>
      </Show>
    </div>
  )
}
