import { Component, createSignal, For, Show } from 'solid-js'
import type { Wallet } from '../lib/api'

interface WalletSelectorProps {
  wallets: Wallet[]
  selectedWallet: Wallet | null
  onSelect: (wallet: Wallet) => void
  onCreate: (name: string) => Promise<void>
  onDeposit: (amount: string) => Promise<void>
  onWithdraw: (amount: string) => Promise<void>
}

export const WalletSelector: Component<WalletSelectorProps> = (props) => {
  const [newWalletName, setNewWalletName] = createSignal('')
  const [isCreating, setIsCreating] = createSignal(false)
  const [error, setError] = createSignal('')
  const [depositAmount, setDepositAmount] = createSignal('')
  const [withdrawAmount, setWithdrawAmount] = createSignal('')
  const [isDepositing, setIsDepositing] = createSignal(false)
  const [isWithdrawing, setIsWithdrawing] = createSignal(false)

  const handleCreate = async () => {
    const name = newWalletName().trim()
    if (!name) {
      setError('Wallet name is required')
      return
    }

    setIsCreating(true)
    setError('')

    try {
      await props.onCreate(name)
      setNewWalletName('')
    } catch (e) {
      setError((e as Error).message)
    } finally {
      setIsCreating(false)
    }
  }

  const handleDeposit = async () => {
    const amount = depositAmount().trim()
    if (!amount || isNaN(Number(amount)) || Number(amount) <= 0) {
      setError('Enter a valid amount')
      return
    }

    setIsDepositing(true)
    setError('')

    try {
      await props.onDeposit(amount)
      setDepositAmount('')
    } catch (e) {
      setError((e as Error).message)
    } finally {
      setIsDepositing(false)
    }
  }

  const handleWithdraw = async () => {
    const amount = withdrawAmount().trim()
    if (!amount || isNaN(Number(amount)) || Number(amount) <= 0) {
      setError('Enter a valid amount')
      return
    }

    setIsWithdrawing(true)
    setError('')

    try {
      await props.onWithdraw(amount)
      setWithdrawAmount('')
    } catch (e) {
      setError((e as Error).message)
    } finally {
      setIsWithdrawing(false)
    }
  }

  return (
    <div class="bg-gray-800 rounded-lg p-4">
      <h2 class="text-lg font-semibold mb-4">Wallet</h2>

      <div class="space-y-3">
        <div class="flex gap-2">
          <input
            type="text"
            value={newWalletName()}
            onInput={(e) => setNewWalletName(e.currentTarget.value)}
            placeholder="New wallet name"
            class="flex-1 bg-gray-700 border border-gray-600 rounded px-3 py-2 text-sm focus:outline-none focus:border-blue-500"
          />
          <button
            onClick={handleCreate}
            disabled={isCreating()}
            class="bg-blue-600 hover:bg-blue-700 disabled:bg-blue-800 disabled:cursor-not-allowed px-4 py-2 rounded text-sm font-medium"
          >
            {isCreating() ? 'Creating...' : 'Create'}
          </button>
        </div>

        <Show when={error()}>
          <p class="text-red-400 text-sm">{error()}</p>
        </Show>

        <Show when={props.wallets.length > 0}>
          <div class="border-t border-gray-700 pt-3">
            <label class="block text-sm text-gray-400 mb-2">Select Wallet</label>
            <select
              value={props.selectedWallet?.name || ''}
              onChange={(e) => {
                const wallet = props.wallets.find(
                  (w) => w.name === e.currentTarget.value
                )
                if (wallet) props.onSelect(wallet)
              }}
              class="w-full bg-gray-700 border border-gray-600 rounded px-3 py-2 text-sm focus:outline-none focus:border-blue-500"
            >
              <option value="">Select a wallet...</option>
              <For each={props.wallets}>
                {(wallet) => <option value={wallet.name}>{wallet.name}</option>}
              </For>
            </select>
          </div>
        </Show>

        <Show when={props.selectedWallet}>
          <div class="bg-gray-700 rounded p-3 space-y-3">
            <div class="flex justify-between items-start">
              <div>
                <p class="text-gray-400 text-xs">Wallet</p>
                <p class="font-medium text-green-400">
                  {props.selectedWallet!.name}
                </p>
              </div>
            </div>

            {/* Balances */}
            <div class="grid grid-cols-2 gap-3">
              <div class="bg-gray-800 rounded p-2">
                <p class="text-gray-400 text-xs">Public (USDM)</p>
                <p class="font-bold text-lg text-blue-400">
                  {Number(props.selectedWallet!.publicBalance).toLocaleString()}
                </p>
              </div>
              <div class="bg-gray-800 rounded p-2">
                <p class="text-gray-400 text-xs">Private (pUSDM)</p>
                <p class="font-bold text-lg text-green-400">
                  {Number(props.selectedWallet!.privateBalance).toLocaleString()}
                </p>
              </div>
            </div>

            {/* Deposit */}
            <div class="border-t border-gray-600 pt-3">
              <p class="text-xs text-gray-400 mb-2">Deposit USDM → pUSDM</p>
              <div class="flex gap-2">
                <input
                  type="number"
                  value={depositAmount()}
                  onInput={(e) => setDepositAmount(e.currentTarget.value)}
                  placeholder="Amount"
                  class="flex-1 bg-gray-800 border border-gray-600 rounded px-2 py-1 text-sm focus:outline-none focus:border-blue-500"
                />
                <button
                  onClick={handleDeposit}
                  disabled={isDepositing()}
                  class="bg-blue-600 hover:bg-blue-700 disabled:bg-blue-800 px-3 py-1 rounded text-sm"
                >
                  {isDepositing() ? '...' : 'Deposit'}
                </button>
              </div>
            </div>

            {/* Withdraw */}
            <div class="border-t border-gray-600 pt-3">
              <p class="text-xs text-gray-400 mb-2">Withdraw pUSDM → USDM</p>
              <div class="flex gap-2">
                <input
                  type="number"
                  value={withdrawAmount()}
                  onInput={(e) => setWithdrawAmount(e.currentTarget.value)}
                  placeholder="Amount"
                  class="flex-1 bg-gray-800 border border-gray-600 rounded px-2 py-1 text-sm focus:outline-none focus:border-blue-500"
                />
                <button
                  onClick={handleWithdraw}
                  disabled={isWithdrawing()}
                  class="bg-purple-600 hover:bg-purple-700 disabled:bg-purple-800 px-3 py-1 rounded text-sm"
                >
                  {isWithdrawing() ? '...' : 'Withdraw'}
                </button>
              </div>
            </div>

            <p class="text-xs text-gray-500 font-mono truncate">
              {props.selectedWallet!.publicKey.slice(0, 20)}...
            </p>
          </div>
        </Show>
      </div>
    </div>
  )
}
