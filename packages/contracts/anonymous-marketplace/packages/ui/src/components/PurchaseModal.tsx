import { Component, createSignal, Show } from 'solid-js'
import type { Listing, Wallet } from '../lib/api'

interface PurchaseModalProps {
  listing: Listing | null
  wallet: Wallet | null
  onConfirm: (listingHash: string, quantity: string) => Promise<void>
  onClose: () => void
}

export const PurchaseModal: Component<PurchaseModalProps> = (props) => {
  const [isPurchasing, setIsPurchasing] = createSignal(false)
  const [error, setError] = createSignal('')
  const [purchaseQuantity, setPurchaseQuantity] = createSignal('1')

  const totalPrice = () => {
    const qty = parseInt(purchaseQuantity()) || 1
    const price = parseInt(props.listing?.pricePerUnit || '0')
    return qty * price
  }

  const maxQuantity = () => parseInt(props.listing?.remainingQuantity || '0')

  const handlePurchase = async () => {
    if (!props.listing || !props.wallet) return

    const qty = parseInt(purchaseQuantity())
    if (qty < 1 || qty > maxQuantity()) {
      setError(`Quantity must be between 1 and ${maxQuantity()}`)
      return
    }

    setIsPurchasing(true)
    setError('')

    try {
      await props.onConfirm(props.listing.listingHash, purchaseQuantity())
      props.onClose()
    } catch (e) {
      setError((e as Error).message)
    } finally {
      setIsPurchasing(false)
    }
  }

  return (
    <Show when={props.listing}>
      <div class="fixed inset-0 bg-black/50 flex items-center justify-center z-50">
        <div class="bg-gray-800 rounded-lg p-6 max-w-md w-full mx-4">
          <h2 class="text-xl font-semibold mb-4">Confirm Purchase</h2>

          <div class="bg-gray-700 rounded p-4 mb-4">
            <p class="text-gray-400 text-sm mb-1">Item</p>
            <p class="font-medium">{props.listing!.itemDescription}</p>

            <p class="text-gray-400 text-sm mb-1 mt-3">Price per Unit</p>
            <p class="text-xl font-bold text-green-400">
              {props.listing!.pricePerUnit}{' '}
              <span class="text-sm text-gray-400">pUSDM</span>
            </p>

            <p class="text-gray-400 text-sm mb-1 mt-3">Available</p>
            <p class="font-medium">{props.listing!.remainingQuantity} units</p>

            <div class="mt-3">
              <label class="text-gray-400 text-sm mb-1 block">Quantity to Purchase</label>
              <input
                type="number"
                value={purchaseQuantity()}
                onInput={(e) => setPurchaseQuantity(e.currentTarget.value)}
                min="1"
                max={maxQuantity()}
                class="w-full bg-gray-600 border border-gray-500 rounded px-3 py-2 text-sm focus:outline-none focus:border-blue-500"
              />
            </div>

            <p class="text-gray-400 text-sm mb-1 mt-3">Total Price</p>
            <p class="text-2xl font-bold text-green-400">
              {totalPrice()}{' '}
              <span class="text-sm text-gray-400">pUSDM</span>
            </p>
          </div>

          <Show when={!props.wallet}>
            <p class="text-yellow-400 text-sm mb-4">
              Please select a wallet to make purchases
            </p>
          </Show>

          <Show when={props.wallet}>
            <div class="mb-4">
              <p class="text-gray-400 text-sm">
                Purchasing as:{' '}
                <span class="text-white font-medium">{props.wallet!.name}</span>
              </p>
              <p class="text-gray-400 text-sm mt-1">
                Private balance (pUSDM):{' '}
                <span class={`font-medium ${Number(props.wallet!.privateBalance) >= totalPrice() ? 'text-green-400' : 'text-red-400'}`}>
                  {Number(props.wallet!.privateBalance).toLocaleString()}
                </span>
              </p>
              <Show when={Number(props.wallet!.privateBalance) < totalPrice()}>
                <p class="text-yellow-400 text-sm mt-2">
                  Insufficient private balance. Deposit more USDM to pUSDM first.
                </p>
              </Show>
            </div>
          </Show>

          <Show when={error()}>
            <p class="text-red-400 text-sm mb-4">{error()}</p>
          </Show>

          <div class="flex gap-3">
            <button
              onClick={props.onClose}
              class="flex-1 bg-gray-600 hover:bg-gray-500 px-4 py-2 rounded font-medium"
            >
              Cancel
            </button>
            <button
              onClick={handlePurchase}
              disabled={isPurchasing() || !props.wallet || Number(props.wallet?.privateBalance || 0) < totalPrice()}
              class="flex-1 bg-green-600 hover:bg-green-700 disabled:bg-gray-600 disabled:text-gray-400 disabled:cursor-not-allowed disabled:opacity-50 px-4 py-2 rounded font-medium"
            >
              {isPurchasing() ? 'Purchasing...' : 'Confirm Purchase'}
            </button>
          </div>
        </div>
      </div>
    </Show>
  )
}
