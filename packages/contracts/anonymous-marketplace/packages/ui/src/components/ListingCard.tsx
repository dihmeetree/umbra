import { Component, Show, createSignal } from 'solid-js'
import type { Listing } from '../lib/api'

interface ListingCardProps {
  listing: Listing
  isOwner: boolean
  onCancel?: (hash: string) => Promise<void>
  onClaim?: (hash: string) => Promise<void>
  onBuy?: (hash: string) => void
}

export const ListingCard: Component<ListingCardProps> = (props) => {
  const [isLoading, setIsLoading] = createSignal(false)
  const [copied, setCopied] = createSignal(false)

  const statusColors: Record<string, string> = {
    Active: 'bg-green-600',
    Sold: 'bg-yellow-600',
    Completed: 'bg-blue-600',
    Claimed: 'bg-purple-600',
    Cancelled: 'bg-red-600',
    Refunded: 'bg-orange-600'
  }

  const statusText: Record<string, string> = {
    Active: 'Active',
    Sold: 'Sold - Awaiting buyer confirmation',
    Completed: 'Completed - Ready to claim',
    Claimed: 'Claimed',
    Cancelled: 'Cancelled',
    Refunded: 'Refunded'
  }

  const formatDeadline = (timestamp: string) => {
    if (timestamp === '0') return 'No timeout'
    const date = new Date(parseInt(timestamp) * 1000)
    return date.toLocaleDateString()
  }

  const handleCancel = async () => {
    if (!props.onCancel) return
    setIsLoading(true)
    try {
      await props.onCancel(props.listing.listingHash)
    } finally {
      setIsLoading(false)
    }
  }

  const handleClaim = async () => {
    if (!props.onClaim) return
    setIsLoading(true)
    try {
      await props.onClaim(props.listing.listingHash)
    } finally {
      setIsLoading(false)
    }
  }

  const copyHash = async () => {
    await navigator.clipboard.writeText(props.listing.listingHash)
    setCopied(true)
    setTimeout(() => setCopied(false), 2000)
  }

  return (
    <div class="bg-gray-700 rounded-lg p-4">
      <div class="flex justify-between items-start mb-2">
        <h3 class="font-medium truncate flex-1">
          {props.listing.itemDescription}
        </h3>
        <span
          class={`${statusColors[props.listing.status]} px-2 py-0.5 rounded text-xs font-medium ml-2`}
        >
          {props.listing.status}
        </span>
      </div>

      <p class="text-2xl font-bold text-green-400 mb-1">
        {props.listing.pricePerUnit} <span class="text-sm text-gray-400">pUSDM/unit</span>
      </p>
      <p class="text-sm text-gray-300 mb-1">
        {props.listing.remainingQuantity}/{props.listing.quantity} available
      </p>

      <Show when={props.listing.escrowDeadline}>
        <p class="text-xs text-gray-500 mb-2">
          Escrow deadline: {formatDeadline(props.listing.escrowDeadline)}
        </p>
      </Show>

      <Show when={props.isOwner && (props.listing.status === 'Sold' || props.listing.status === 'Completed')}>
        <p class="text-xs text-yellow-400 mb-2">
          {statusText[props.listing.status]}
        </p>
      </Show>

      <div class="mb-3">
        <p class="text-xs text-gray-500 mb-1">Listing Hash:</p>
        <button
          onClick={copyHash}
          class="w-full text-left bg-gray-800 hover:bg-gray-600 rounded px-2 py-1 text-xs font-mono text-gray-300 break-all transition-colors"
          title="Click to copy"
        >
          {props.listing.listingHash}
          <span class="ml-2 text-gray-500">
            {copied() ? '(copied!)' : '(click to copy)'}
          </span>
        </button>
      </div>

      <div class="flex gap-2">
        <Show when={!props.isOwner && props.listing.status === 'Active'}>
          <button
            onClick={() => props.onBuy?.(props.listing.listingHash)}
            class="flex-1 bg-blue-600 hover:bg-blue-700 px-3 py-2 rounded text-sm font-medium"
          >
            Buy
          </button>
        </Show>

        <Show when={props.isOwner && props.listing.status === 'Active'}>
          <button
            onClick={handleCancel}
            disabled={isLoading()}
            class="flex-1 bg-red-600 hover:bg-red-700 disabled:opacity-50 px-3 py-2 rounded text-sm font-medium"
          >
            {isLoading() ? 'Cancelling...' : 'Cancel'}
          </button>
        </Show>

        <Show when={props.isOwner && props.listing.status === 'Completed'}>
          <button
            onClick={handleClaim}
            disabled={isLoading()}
            class="flex-1 bg-green-600 hover:bg-green-700 disabled:opacity-50 px-3 py-2 rounded text-sm font-medium"
          >
            {isLoading() ? 'Claiming...' : 'Claim Payment'}
          </button>
        </Show>

        <Show when={props.isOwner && props.listing.status === 'Sold'}>
          <p class="text-xs text-gray-400 italic">Waiting for buyer to confirm receipt...</p>
        </Show>
      </div>
    </div>
  )
}
