import { Component, createSignal, Show } from 'solid-js'
import type { Wallet } from '../lib/api'

interface CreateListingProps {
  wallet: Wallet | null
  onSubmit: (description: string, pricePerUnit: string, quantity: string, escrowDeadline: string) => Promise<void>
}

export const CreateListing: Component<CreateListingProps> = (props) => {
  const [description, setDescription] = createSignal('')
  const [pricePerUnit, setPricePerUnit] = createSignal('')
  const [quantity, setQuantity] = createSignal('1')
  const [escrowDays, setEscrowDays] = createSignal('7') // Default 7 days
  const [noTimeout, setNoTimeout] = createSignal(false)
  const [isSubmitting, setIsSubmitting] = createSignal(false)
  const [error, setError] = createSignal('')
  const [success, setSuccess] = createSignal('')

  const calculateDeadline = (): string => {
    if (noTimeout()) return '0'
    const days = parseInt(escrowDays()) || 7
    const deadline = Math.floor(Date.now() / 1000) + (days * 24 * 60 * 60)
    return deadline.toString()
  }

  const handleSubmit = async (e: Event) => {
    e.preventDefault()

    if (!props.wallet) {
      setError('Please select a wallet first')
      return
    }

    if (!description().trim()) {
      setError('Item description is required')
      return
    }

    if (!pricePerUnit().trim() || isNaN(Number(pricePerUnit()))) {
      setError('Valid price per unit is required')
      return
    }

    if (!quantity().trim() || isNaN(Number(quantity())) || Number(quantity()) < 1) {
      setError('Valid quantity is required (minimum 1)')
      return
    }

    setIsSubmitting(true)
    setError('')
    setSuccess('')

    try {
      await props.onSubmit(description().trim(), pricePerUnit().trim(), quantity().trim(), calculateDeadline())
      setDescription('')
      setPricePerUnit('')
      setQuantity('1')
      setSuccess('Listing created successfully!')
      setTimeout(() => setSuccess(''), 3000)
    } catch (e) {
      setError((e as Error).message)
    } finally {
      setIsSubmitting(false)
    }
  }

  return (
    <div class="bg-gray-800 rounded-lg p-4">
      <h2 class="text-lg font-semibold mb-4">Create Listing</h2>

      <form onSubmit={handleSubmit} class="space-y-4">
        <div>
          <label class="block text-sm text-gray-400 mb-1">
            Item Description
          </label>
          <input
            type="text"
            value={description()}
            onInput={(e) => setDescription(e.currentTarget.value)}
            placeholder="Describe your item..."
            maxLength={32}
            disabled={!props.wallet}
            class="w-full bg-gray-700 border border-gray-600 rounded px-3 py-2 text-sm focus:outline-none focus:border-blue-500 disabled:opacity-50"
          />
          <p class="text-xs text-gray-500 mt-1">{description().length}/32 characters</p>
        </div>

        <div class="grid grid-cols-2 gap-4">
          <div>
            <label class="block text-sm text-gray-400 mb-1">Price per Unit (pUSDM)</label>
            <input
              type="number"
              value={pricePerUnit()}
              onInput={(e) => setPricePerUnit(e.currentTarget.value)}
              placeholder="0"
              min="0"
              disabled={!props.wallet}
              class="w-full bg-gray-700 border border-gray-600 rounded px-3 py-2 text-sm focus:outline-none focus:border-blue-500 disabled:opacity-50"
            />
          </div>
          <div>
            <label class="block text-sm text-gray-400 mb-1">Quantity</label>
            <input
              type="number"
              value={quantity()}
              onInput={(e) => setQuantity(e.currentTarget.value)}
              placeholder="1"
              min="1"
              disabled={!props.wallet}
              class="w-full bg-gray-700 border border-gray-600 rounded px-3 py-2 text-sm focus:outline-none focus:border-blue-500 disabled:opacity-50"
            />
          </div>
        </div>

        <div>
          <label class="block text-sm text-gray-400 mb-1">Escrow Timeout</label>
          <div class="flex items-center gap-2 mb-2">
            <input
              type="checkbox"
              id="noTimeout"
              checked={noTimeout()}
              onChange={(e) => setNoTimeout(e.currentTarget.checked)}
              disabled={!props.wallet}
              class="w-4 h-4"
            />
            <label for="noTimeout" class="text-sm text-gray-300">
              No timeout (buyer must always confirm)
            </label>
          </div>
          <Show when={!noTimeout()}>
            <div class="flex items-center gap-2">
              <input
                type="number"
                value={escrowDays()}
                onInput={(e) => setEscrowDays(e.currentTarget.value)}
                min="1"
                max="365"
                disabled={!props.wallet}
                class="w-20 bg-gray-700 border border-gray-600 rounded px-3 py-2 text-sm focus:outline-none focus:border-blue-500 disabled:opacity-50"
              />
              <span class="text-sm text-gray-400">days until auto-release</span>
            </div>
            <p class="text-xs text-gray-500 mt-1">
              After this time, you can claim payment even if buyer hasn't confirmed
            </p>
          </Show>
        </div>

        <Show when={error()}>
          <p class="text-red-400 text-sm">{error()}</p>
        </Show>

        <Show when={success()}>
          <p class="text-green-400 text-sm">{success()}</p>
        </Show>

        <button
          type="submit"
          disabled={isSubmitting() || !props.wallet}
          class="w-full bg-green-600 hover:bg-green-700 disabled:bg-green-800 disabled:cursor-not-allowed px-4 py-2 rounded font-medium"
        >
          {isSubmitting() ? 'Creating...' : 'Create Listing'}
        </button>

        <Show when={!props.wallet}>
          <p class="text-yellow-400 text-sm text-center">
            Select a wallet to create listings
          </p>
        </Show>
      </form>
    </div>
  )
}
