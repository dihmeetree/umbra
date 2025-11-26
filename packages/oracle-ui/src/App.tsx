import { createSignal, Show, onMount } from 'solid-js'
import {
  initializeOracle,
  fetchVerifiedBitcoinPrice,
  formatBigInt,
  type VerifiedPrice,
  type OracleStatus
} from './api'

function App() {
  const [oracleStatus, setOracleStatus] = createSignal<OracleStatus | null>(null)
  const [price, setPrice] = createSignal<VerifiedPrice | null>(null)
  const [loading, setLoading] = createSignal(false)
  const [initializing, setInitializing] = createSignal(true)
  const [error, setError] = createSignal<string | null>(null)
  const [proverUrl, setProverUrl] = createSignal('http://localhost:3000')

  // Initialize contract on mount via backend API
  onMount(async () => {
    try {
      setInitializing(true)
      const response = await initializeOracle()
      if (response.success && response.data) {
        setOracleStatus({
          initialized: true,
          adminPublicKey: response.data.adminPublicKey
        })
      } else {
        setError(`Failed to initialize oracle: ${response.error}`)
      }
    } catch (err) {
      setError(`Failed to connect to oracle server: ${err}`)
    } finally {
      setInitializing(false)
    }
  })

  const fetchPrice = async () => {
    const status = oracleStatus()
    if (!status?.initialized) {
      setError('Oracle not initialized')
      return
    }

    setLoading(true)
    setError(null)

    try {
      const response = await fetchVerifiedBitcoinPrice(proverUrl())
      if (response.success && response.data) {
        setPrice(response.data)
      } else {
        setError(`Failed to fetch price: ${response.error}`)
      }
    } catch (err) {
      setError(`Failed to fetch price: ${err instanceof Error ? err.message : String(err)}`)
    } finally {
      setLoading(false)
    }
  }

  const formatPrice = (value: number): string => {
    return new Intl.NumberFormat('en-US', {
      style: 'currency',
      currency: 'USD',
      minimumFractionDigits: 2,
      maximumFractionDigits: 2
    }).format(value)
  }

  const formatTimestamp = (timestamp: string): string => {
    return new Date(timestamp).toLocaleString('en-US', {
      dateStyle: 'medium',
      timeStyle: 'medium'
    })
  }

  return (
    <div class="container">
      <header class="header">
        <h1>Bitcoin Price Oracle</h1>
        <p>Cryptographically verified prices using Umbra</p>
      </header>

      <Show when={error()}>
        <div class="error-message">
          {error()}
        </div>
      </Show>

      <div class="price-card">
        <div class="price-header">
          <div class="bitcoin-icon">&#8383;</div>
          <div class="price-title">
            <h2>Bitcoin</h2>
            <span>BTC/USD</span>
          </div>
          <Show when={price()}>
            <span class="status-badge verified">
              Verified
            </span>
          </Show>
          <Show when={loading()}>
            <span class="status-badge loading">
              <span class="spinner"></span>
              Fetching...
            </span>
          </Show>
        </div>

        <Show
          when={price()}
          fallback={
            <div class="price-value loading">
              {loading() ? 'Fetching verified price...' : 'Click "Fetch Price" to get started'}
            </div>
          }
        >
          {(p) => (
            <>
              <div class="price-value">{formatPrice(p().price)}</div>
              <div class="price-timestamp">
                Last updated: {formatTimestamp(p().timestamp)}
              </div>
            </>
          )}
        </Show>

        <div class="actions">
          <button
            class="btn btn-primary"
            onClick={fetchPrice}
            disabled={loading() || !oracleStatus()?.initialized || initializing()}
          >
            <Show when={initializing()}>
              <span class="spinner"></span>
              <span>Connecting...</span>
            </Show>
            <Show when={!initializing() && loading()}>
              <span class="spinner"></span>
              <span>Verifying...</span>
            </Show>
            <Show when={!initializing() && !loading()}>
              <span>Fetch Verified Price</span>
            </Show>
          </button>
        </div>
      </div>

      <Show when={price()}>
        {(p) => (
          <div class="verification-card">
            <h3>Cryptographic Verification Details</h3>

            <div class="verification-item">
              <span class="verification-label">Notary Public Key (x)</span>
              <span class="verification-value">
                {formatBigInt(p().signature.pk.x, 24)}
              </span>
            </div>

            <div class="verification-item">
              <span class="verification-label">Signature R (x)</span>
              <span class="verification-value">
                {formatBigInt(p().signature.r.x, 24)}
              </span>
            </div>

            <div class="verification-item">
              <span class="verification-label">Signature S</span>
              <span class="verification-value">
                {formatBigInt(p().signature.s, 24)}
              </span>
            </div>

            <div class="verification-item">
              <span class="verification-label">Data Size</span>
              <span class="verification-value">
                {p().rawData.length} bytes (base64)
              </span>
            </div>

            <div class="verification-item">
              <span class="verification-label">Contract Verified</span>
              <span class="verification-value" style={{ color: 'var(--accent-green)' }}>
                {p().contractVerified ? 'Yes - Schnorr signature verified on-chain' : 'No'}
              </span>
            </div>
          </div>
        )}
      </Show>

      <div class="verification-card">
        <h3>Configuration</h3>
        <div class="verification-item">
          <span class="verification-label">Prover URL</span>
          <input
            type="text"
            value={proverUrl()}
            onInput={(e) => setProverUrl(e.currentTarget.value)}
            style={{
              background: 'var(--bg-primary)',
              border: '1px solid var(--border-color)',
              'border-radius': '8px',
              padding: '0.5rem 1rem',
              color: 'var(--text-primary)',
              'font-family': "'JetBrains Mono', monospace",
              'font-size': '0.875rem',
              width: '300px'
            }}
          />
        </div>
        <div class="verification-item">
          <span class="verification-label">Oracle Server</span>
          <span class="verification-value" style={{ color: oracleStatus()?.initialized ? 'var(--accent-green)' : initializing() ? 'var(--accent-yellow)' : 'var(--accent-red)' }}>
            {initializing() ? 'Connecting to server...' : oracleStatus()?.initialized ? 'Connected (Backend Simulator)' : 'Not connected'}
          </span>
        </div>
      </div>

      <footer class="footer">
        <p>
          Powered by <a href="https://umbra.network" target="_blank">Umbra</a> and{' '}
          <a href="https://midnight.network" target="_blank">Midnight</a>
        </p>
        <p style={{ 'margin-top': '0.5rem' }}>
          Price data from <a href="https://diadata.org" target="_blank">DIA Data</a>
        </p>
      </footer>
    </div>
  )
}

export default App
