/**
 * Oracle Server - HonoJS backend for Bitcoin price oracle
 */
import { Hono } from 'hono'
import { cors } from 'hono/cors'
import { logger } from 'hono/logger'
import { initializeOracle, fetchVerifiedBitcoinPrice, getOracleState } from './oracle'

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

const port = parseInt(process.env.PORT || '3002')

console.log(`Oracle server starting on port ${port}...`)

export default {
  port,
  fetch: app.fetch,
}
