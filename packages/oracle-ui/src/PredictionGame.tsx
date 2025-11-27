import { createSignal, Show, For, onMount } from 'solid-js'
import type { VerifiedPrice } from './api'
import { initializeGame, resolveBet, getGameStats, type GameStats, type GameResult } from './api'

type Prediction = 'up' | 'down' | null
type GameState = 'idle' | 'waiting' | 'fetching_end' | 'resolving' | 'resolved'

interface GameHistoryEntry {
  id: number
  prediction: 'up' | 'down'
  result: 'Won' | 'Lost' | 'Push'
  startPrice: string
  endPrice: string
  priceDiff: string
  timestamp: Date
}

interface PredictionGameProps {
  currentPrice: VerifiedPrice | null
  onFetchPrice: () => Promise<void>
  loading: boolean
  disabled: boolean
  onGameStateChange?: (inProgress: boolean) => void
  onGameResult?: (entry: GameHistoryEntry) => void
}

export function PredictionGame(props: PredictionGameProps) {
  const [gameState, setGameState] = createSignal<GameState>('idle')
  const [prediction, setPrediction] = createSignal<Prediction>(null)
  const [startAttestation, setStartAttestation] = createSignal<VerifiedPrice | null>(null)
  const [countdown, setCountdown] = createSignal(60)
  const [result, setResult] = createSignal<GameResult | null>(null)
  const [stats, setStats] = createSignal<GameStats>({ totalBets: '0', totalWins: '0', totalLosses: '0' })
  const [gameInitialized, setGameInitialized] = createSignal(false)
  const [contractVerified, setContractVerified] = createSignal(false)

  // Initialize game contract on mount
  onMount(async () => {
    try {
      const response = await initializeGame()
      if (response.success) {
        setGameInitialized(true)
        // Fetch initial stats
        const statsResponse = await getGameStats()
        if (statsResponse.success && statsResponse.data) {
          setStats(statsResponse.data)
        }
      }
    } catch (err) {
      console.error('Failed to initialize game:', err)
    }
  })

  const makePrediction = async (direction: 'up' | 'down') => {
    setPrediction(direction)
    setGameState('waiting')
    setResult(null)
    setContractVerified(false)
    setCountdown(60)
    props.onGameStateChange?.(true)

    // Fetch fresh price for the start attestation
    await props.onFetchPrice()

    // Use the freshly fetched price as start attestation
    if (!props.currentPrice) {
      setGameState('idle')
      return
    }
    setStartAttestation(props.currentPrice)

    // Countdown timer
    const interval = setInterval(() => {
      setCountdown((c) => {
        if (c <= 1) {
          clearInterval(interval)
          return 0
        }
        return c - 1
      })
    }, 1000)

    // Wait 60 seconds then fetch new price and resolve
    setTimeout(async () => {
      clearInterval(interval)
      setGameState('fetching_end')

      // Fetch the end price
      await props.onFetchPrice()

      // Now verify on contract
      setGameState('resolving')
      await resolveGame()
    }, 60000)
  }

  const resolveGame = async () => {
    const start = startAttestation()
    const end = props.currentPrice
    const pred = prediction()

    if (!start || !end || !pred) {
      setGameState('idle')
      return
    }

    try {
      // Call the contract to resolve the bet
      const response = await resolveBet(pred, start, end)

      if (response.success && response.data) {
        setResult(response.data)
        setContractVerified(true)

        // Update stats
        const statsResponse = await getGameStats()
        if (statsResponse.success && statsResponse.data) {
          setStats(statsResponse.data)
        }
      } else {
        // Fallback to local calculation if contract fails
        const startPrice = start.price
        const endPrice = end.price
        const priceWentUp = endPrice > startPrice
        const won = (pred === 'up' && priceWentUp) || (pred === 'down' && !priceWentUp && endPrice !== startPrice)
        const isPush = endPrice === startPrice

        setResult({
          result: isPush ? 'Push' : won ? 'Won' : 'Lost',
          startPrice: startPrice.toFixed(2),
          endPrice: endPrice.toFixed(2),
          priceDiff: (endPrice - startPrice).toFixed(2)
        })
      }
    } catch (err) {
      console.error('Failed to resolve bet:', err)
      // Fallback to local calculation
      const startPrice = start.price
      const endPrice = end.price
      const priceWentUp = endPrice > startPrice
      const won = (pred === 'up' && priceWentUp) || (pred === 'down' && !priceWentUp && endPrice !== startPrice)
      const isPush = endPrice === startPrice

      setResult({
        result: isPush ? 'Push' : won ? 'Won' : 'Lost',
        startPrice: startPrice.toFixed(2),
        endPrice: endPrice.toFixed(2),
        priceDiff: (endPrice - startPrice).toFixed(2)
      })
    }

    setGameState('resolved')
    props.onGameStateChange?.(false)

    // Notify parent of game result
    const currentResult = result()
    const currentPrediction = prediction()
    if (currentResult && currentPrediction && props.onGameResult) {
      const historyEntry: GameHistoryEntry = {
        id: Date.now(),
        prediction: currentPrediction,
        result: currentResult.result as 'Won' | 'Lost' | 'Push',
        startPrice: currentResult.startPrice,
        endPrice: currentResult.endPrice,
        priceDiff: currentResult.priceDiff,
        timestamp: new Date()
      }
      props.onGameResult(historyEntry)
    }
  }

  const playAgain = () => {
    setGameState('idle')
    setPrediction(null)
    setStartAttestation(null)
    setResult(null)
    setContractVerified(false)
    props.onGameStateChange?.(false)
  }

  const formatPrice = (value: number | string): string => {
    const num = typeof value === 'string' ? parseFloat(value) : value
    return new Intl.NumberFormat('en-US', {
      style: 'currency',
      currency: 'USD',
      minimumFractionDigits: 2,
      maximumFractionDigits: 2
    }).format(num)
  }

  return (
    <div class="game-card">
        <div class="game-header">
          <h3>Price Prediction Game</h3>
          <div class="game-stats">
            <span class="stat win">{stats().totalWins}W</span>
            <span class="stat-divider">-</span>
            <span class="stat loss">{stats().totalLosses}L</span>
          </div>
        </div>

      <Show when={gameState() === 'idle'}>
        <div class="game-content">
          <p class="game-description">
            Predict if Bitcoin's price will go <strong>up</strong> or <strong>down</strong> in the next 60 seconds.
            {gameInitialized() && ' Results verified on-chain via smart contract!'}
          </p>

          <div class="prediction-buttons">
            <button
              class="btn btn-up"
              onClick={() => makePrediction('up')}
              disabled={props.disabled || props.loading || !gameInitialized() || gameState() !== 'idle'}
            >
              <span class="arrow">&#9650;</span>
              <span>UP</span>
            </button>
            <button
              class="btn btn-down"
              onClick={() => makePrediction('down')}
              disabled={props.disabled || props.loading || !gameInitialized() || gameState() !== 'idle'}
            >
              <span class="arrow">&#9660;</span>
              <span>DOWN</span>
            </button>
          </div>
        </div>
      </Show>

      <Show when={gameState() === 'waiting' || gameState() === 'fetching_end' || gameState() === 'resolving'}>
        <div class="game-content waiting">
          <div class="prediction-badge">
            You predicted: <strong class={prediction() === 'up' ? 'up' : 'down'}>
              {prediction()?.toUpperCase()}
            </strong>
          </div>

          <div class="countdown-container">
            <div class="countdown-circle">
              <Show when={gameState() === 'waiting' && startAttestation()}>
                <span class="countdown-number">{countdown()}</span>
              </Show>
              <Show when={gameState() !== 'waiting' || !startAttestation()}>
                <span class="spinner"></span>
              </Show>
            </div>
            <p>
              {!startAttestation()
                ? 'Fetching start price...'
                : gameState() === 'waiting'
                  ? 'seconds remaining'
                  : (gameState() === 'fetching_end' || props.loading)
                    ? 'Fetching end price...'
                    : 'Verifying on contract...'}
            </p>
          </div>

          <Show when={startAttestation()}>
            <div class="price-comparison">
              <div class="price-box">
                <span class="price-label">Start Price</span>
                <span class="price-amount">{formatPrice(startAttestation()!.price)}</span>
              </div>
              <div class="vs">vs</div>
              <div class="price-box">
                <span class="price-label">End Price</span>
                <span class="price-amount pending">???</span>
              </div>
            </div>
          </Show>
        </div>
      </Show>

      <Show when={gameState() === 'resolved' && result()}>
        {(r) => (
          <div class="game-content resolved">
            <div class={`result-banner ${r().result === 'Won' ? 'win' : r().result === 'Push' ? 'push' : 'loss'}`}>
              <Show when={r().result === 'Push'}>
                <span class="result-emoji">🤝</span>
                <span class="result-text">PUSH - Same Price!</span>
              </Show>
              <Show when={r().result !== 'Push'}>
                <span class="result-emoji">{r().result === 'Won' ? '🎉' : '😔'}</span>
                <span class="result-text">{r().result === 'Won' ? 'YOU WON!' : 'YOU LOST'}</span>
              </Show>
            </div>

            <div class="price-comparison">
              <div class="price-box">
                <span class="price-label">Start Price</span>
                <span class="price-amount">{formatPrice(r().startPrice)}</span>
              </div>
              <div class="vs">
                <span class={parseFloat(r().priceDiff) > 0 ? 'up' : parseFloat(r().priceDiff) < 0 ? 'down' : ''}>
                  {parseFloat(r().priceDiff) > 0 ? '▲' : parseFloat(r().priceDiff) < 0 ? '▼' : '='}
                </span>
              </div>
              <div class="price-box">
                <span class="price-label">End Price</span>
                <span class="price-amount">{formatPrice(r().endPrice)}</span>
              </div>
            </div>

            <div class="result-details">
              <p>
                You predicted <strong class={prediction() === 'up' ? 'up' : 'down'}>{prediction()?.toUpperCase()}</strong>
                {' '}&bull;{' '}
                Price went <strong class={parseFloat(r().priceDiff) > 0 ? 'up' : 'down'}>
                  {parseFloat(r().priceDiff) > 0 ? 'UP' : parseFloat(r().priceDiff) < 0 ? 'DOWN' : 'UNCHANGED'}
                </strong>
                {' '}by {formatPrice(Math.abs(parseFloat(r().priceDiff)))}
              </p>
            </div>

            <button class="btn btn-primary" onClick={playAgain}>
              Play Again
            </button>
          </div>
        )}
      </Show>
    </div>
  )
}

// Export GameHistoryEntry type for use in App
export type { GameHistoryEntry }

// Export a separate GameHistory component
export function GameHistory(props: { history: GameHistoryEntry[] }) {
  const formatPrice = (value: number | string): string => {
    const num = typeof value === 'string' ? parseFloat(value) : value
    return new Intl.NumberFormat('en-US', {
      style: 'currency',
      currency: 'USD',
      minimumFractionDigits: 2,
      maximumFractionDigits: 2
    }).format(num)
  }

  const formatTime = (date: Date): string => {
    return date.toLocaleTimeString('en-US', {
      hour: '2-digit',
      minute: '2-digit'
    })
  }

  return (
    <div class="game-history-card">
      <div class="game-history-header">
        <h3>Game History</h3>
      </div>
      <div class="game-history-content">
        <Show
          when={props.history.length > 0}
          fallback={
            <p class="game-history-empty">No games played yet</p>
          }
        >
          <div class="game-history-list">
            <For each={props.history}>
              {(entry) => {
                const priceDiff = parseFloat(entry.priceDiff)
                const priceDirection = priceDiff > 0 ? 'up' : priceDiff < 0 ? 'down' : 'unchanged'
                return (
                  <div class={`history-item ${entry.result.toLowerCase()}`}>
                    <div class="history-item-header">
                      <span class={`history-prediction ${priceDirection === 'unchanged' ? 'unchanged' : entry.prediction}`}>
                        {priceDirection === 'unchanged' ? '▶' : entry.prediction === 'up' ? '▲' : '▼'} {priceDirection === 'unchanged' ? 'NO CHANGE' : entry.prediction.toUpperCase()}
                      </span>
                      <span class={`history-result ${entry.result.toLowerCase()}`}>
                        {entry.result}
                      </span>
                    </div>
                    <div class="history-item-prices">
                      <span>{formatPrice(entry.startPrice)}</span>
                      <span class={`history-arrow ${priceDirection}`}>
                        {priceDirection === 'up' ? '▲' : priceDirection === 'down' ? '▼' : '='}
                      </span>
                      <span>{formatPrice(entry.endPrice)}</span>
                    </div>
                    <div class="history-item-time">
                      {formatTime(entry.timestamp)}
                    </div>
                  </div>
                )
              }}
            </For>
          </div>
        </Show>
      </div>
    </div>
  )
}
