/**
 * Oracle Server - HonoJS backend for Bitcoin price oracle
 */
import { Hono } from 'hono'
import { cors } from 'hono/cors'
import { logger } from 'hono/logger'
import { initializeOracle, fetchVerifiedBitcoinPrice, getOracleState } from './oracle'
import { initializeGame, resolveBet, getGameStats, getTimeConstraints, Direction, BetState, createPriceAttestation } from './game'
import { ProverClient, padToBytes512 } from '@statera/prover-client'

const app = new Hono()

// Middleware
app.use('*', logger())
app.use('*', cors({
  origin: ['http://localhost:3001', 'http://localhost:3000'],
  allowMethods: ['GET', 'POST', 'OPTIONS'],
  allowHeaders: ['Content-Type'],
}))

// Health check
app.get('/health', (c) => {
  return c.json({ status: 'ok', service: 'oracle-server' })
})

// Initialize the oracle contract
app.post('/api/oracle/init', async (c) => {
  try {
    const result = await initializeOracle()
    return c.json({
      success: true,
      data: result
    })
  } catch (error) {
    console.error('Failed to initialize oracle:', error)
    return c.json({
      success: false,
      error: error instanceof Error ? error.message : 'Unknown error'
    }, 500)
  }
})

// Get oracle status
app.get('/api/oracle/status', async (c) => {
  try {
    const state = await getOracleState()
    return c.json({
      success: true,
      data: {
        initialized: true,
        adminPublicKey: {
          x: state.adminPublicKey.x.toString(),
          y: state.adminPublicKey.y.toString()
        }
      }
    })
  } catch (error) {
    console.error('Failed to get oracle status:', error)
    return c.json({
      success: false,
      error: error instanceof Error ? error.message : 'Unknown error'
    }, 500)
  }
})

// Fetch verified Bitcoin price
app.get('/api/oracle/price', async (c) => {
  try {
    const proverUrl = c.req.query('proverUrl') || 'http://localhost:8080'
    const result = await fetchVerifiedBitcoinPrice(proverUrl)
    return c.json({
      success: true,
      data: result
    })
  } catch (error) {
    console.error('Failed to fetch price:', error)
    return c.json({
      success: false,
      error: error instanceof Error ? error.message : 'Unknown error'
    }, 500)
  }
})

// Fetch verified Bitcoin price (POST with custom prover URL)
app.post('/api/oracle/price', async (c) => {
  try {
    const body = await c.req.json<{ proverUrl?: string }>()
    const proverUrl = body.proverUrl || 'http://localhost:8080'
    const result = await fetchVerifiedBitcoinPrice(proverUrl)
    return c.json({
      success: true,
      data: result
    })
  } catch (error) {
    console.error('Failed to fetch price:', error)
    return c.json({
      success: false,
      error: error instanceof Error ? error.message : 'Unknown error'
    }, 500)
  }
})

// ============ Game Endpoints ============

// Initialize the prediction game contract
app.post('/api/game/init', async (c) => {
  try {
    const result = await initializeGame()
    return c.json({
      success: true,
      data: result
    })
  } catch (error) {
    console.error('Failed to initialize game:', error)
    return c.json({
      success: false,
      error: error instanceof Error ? error.message : 'Unknown error'
    }, 500)
  }
})

// Get game stats
app.get('/api/game/stats', async (c) => {
  try {
    const stats = await getGameStats()
    return c.json({
      success: true,
      data: {
        totalBets: stats.totalBets.toString(),
        totalWins: stats.totalWins.toString(),
        totalLosses: stats.totalLosses.toString()
      }
    })
  } catch (error) {
    console.error('Failed to get game stats:', error)
    return c.json({
      success: false,
      error: error instanceof Error ? error.message : 'Unknown error'
    }, 500)
  }
})

// Get time constraints
app.get('/api/game/constraints', async (c) => {
  try {
    const constraints = await getTimeConstraints()
    return c.json({
      success: true,
      data: constraints
    })
  } catch (error) {
    console.error('Failed to get time constraints:', error)
    return c.json({
      success: false,
      error: error instanceof Error ? error.message : 'Unknown error'
    }, 500)
  }
})

// Resolve a bet - takes start/end attestations and prediction
app.post('/api/game/resolve', async (c) => {
  try {
    const body = await c.req.json<{
      prediction: 'up' | 'down'
      startAttestation: any
      endAttestation: any
    }>()

    const prediction = body.prediction === 'up' ? Direction.Up : Direction.Down

    // Convert string values back to bigints for attestations
    // Pad data to 512 bytes as required by the contract's SignedBytes<Bytes<512>> type
    const startAttestation = {
      signedData: {
        data: padToBytes512(new Uint8Array(Buffer.from(body.startAttestation.rawData, 'base64'))),
        dataLen: BigInt(body.startAttestation.dataLen),
        signature: {
          r: {
            x: BigInt(body.startAttestation.signature.r.x),
            y: BigInt(body.startAttestation.signature.r.y)
          },
          s: BigInt(body.startAttestation.signature.s)
        },
        pk: {
          x: BigInt(body.startAttestation.signature.pk.x),
          y: BigInt(body.startAttestation.signature.pk.y)
        }
      },
      priceCents: BigInt(Math.round(body.startAttestation.price * 100)),
      timestamp: BigInt(Math.floor(new Date(body.startAttestation.timestamp).getTime() / 1000))
    }

    const endAttestation = {
      signedData: {
        data: padToBytes512(new Uint8Array(Buffer.from(body.endAttestation.rawData, 'base64'))),
        dataLen: BigInt(body.endAttestation.dataLen),
        signature: {
          r: {
            x: BigInt(body.endAttestation.signature.r.x),
            y: BigInt(body.endAttestation.signature.r.y)
          },
          s: BigInt(body.endAttestation.signature.s)
        },
        pk: {
          x: BigInt(body.endAttestation.signature.pk.x),
          y: BigInt(body.endAttestation.signature.pk.y)
        }
      },
      priceCents: BigInt(Math.round(body.endAttestation.price * 100)),
      timestamp: BigInt(Math.floor(new Date(body.endAttestation.timestamp).getTime() / 1000))
    }

    const result = await resolveBet(prediction, startAttestation, endAttestation)

    return c.json({
      success: true,
      data: {
        result: BetState[result.result],
        startPrice: result.startPrice,
        endPrice: result.endPrice,
        priceDiff: result.priceDiff
      }
    })
  } catch (error) {
    console.error('Failed to resolve bet:', error)
    return c.json({
      success: false,
      error: error instanceof Error ? error.message : 'Unknown error'
    }, 500)
  }
})

const port = parseInt(process.env.PORT || '3002')

console.log(`Oracle server starting on port ${port}...`)

export default {
  port,
  fetch: app.fetch,
}
