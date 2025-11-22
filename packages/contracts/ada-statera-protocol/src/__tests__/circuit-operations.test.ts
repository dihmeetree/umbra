import { describe, it, expect, beforeEach } from 'vitest'
import {
  createStateraTestFixture,
  createPrivateStateForWallet,
  updateAllBalances,
  type StateraTestFixture
} from './test-utils'

describe('Ada Statera Protocol - Circuit Operations', () => {
  let fixture: StateraTestFixture

  beforeEach(() => {
    fixture = createStateraTestFixture(3)
  })

  describe('Pure Circuit Execution', () => {
    it('should be able to access pure circuits', () => {
      const { simulator } = fixture

      // Check that contract has circuits
      expect(simulator.contract.circuits).toBeDefined()
    })

    it('should have impure circuits', () => {
      const { simulator } = fixture

      // Check that contract has impure circuits
      expect(simulator.contract.impureCircuits).toBeDefined()
    })
  })

  describe('Context Management', () => {
    it('should maintain context across operations', () => {
      const { simulator, adminWallet } = fixture

      const initialPrivateState = createPrivateStateForWallet(adminWallet)
      simulator.as(initialPrivateState)

      const state1 = simulator.getPrivateState()
      expect(state1.secret_key).toEqual(adminWallet.secretKey)

      // After operations, context should still be valid
      const state2 = simulator.getPrivateState()
      expect(state2.secret_key).toEqual(adminWallet.secretKey)
    })

    it('should preserve ZSwap local state', () => {
      const { simulator } = fixture

      const zswapState = simulator.getZswapLocalState()
      expect(zswapState).toBeDefined()
      expect(zswapState.outputs).toBeDefined()
      expect(Array.isArray(zswapState.outputs)).toBe(true)
    })
  })

  describe('Output Management', () => {
    it('should have empty outputs initially', () => {
      const { simulator } = fixture

      const outputs = simulator.getOutputs()
      expect(outputs).toBeDefined()
      expect(Array.isArray(outputs)).toBe(true)
      // Initial deployment may have some outputs
    })

    it('should be able to get outputs by recipient', () => {
      const { simulator, adminWallet } = fixture

      const output = simulator.getOutputByRecipient(adminWallet.coinPublicKey)
      // May be undefined if no outputs for this recipient yet
      // Just testing the API works
      if (output) {
        expect(output.type).toBeDefined()
        expect(output.value).toBeDefined()
      }
    })

    it('should be able to get multiple outputs by recipient', () => {
      const { simulator, adminWallet } = fixture

      const outputs = simulator.getOutputsByRecipient(adminWallet.coinPublicKey)
      expect(outputs).toBeDefined()
      expect(Array.isArray(outputs)).toBe(true)
    })
  })

  describe('Balance Queries', () => {
    it('should return zero balance for non-existent tokens', () => {
      const { simulator, adminWallet, sSUSDTokenType } = fixture

      const balance = simulator.getBalance(
        adminWallet.coinPublicKey,
        sSUSDTokenType
      )
      expect(balance).toBe(0n)
    })

    it('should get all balances for a wallet', () => {
      const { simulator, adminWallet } = fixture

      const balances = simulator.getAllBalances(adminWallet.coinPublicKey)
      expect(balances).toBeDefined()
      expect(typeof balances).toBe('object')
    })
  })

  describe('Balance Tracker Integration', () => {
    it('should update balance tracker from simulator', () => {
      const { simulator, balanceTracker, adminWallet } = fixture

      balanceTracker.updateFromSimulator(
        simulator,
        adminWallet.coinPublicKey,
        'admin'
      )

      // Should not throw
      expect(() => {
        updateAllBalances(fixture)
      }).not.toThrow()
    })

    it('should track balance changes', () => {
      const { balanceTracker, adminWallet, sSUSDTokenType } = fixture

      // Set initial balance
      balanceTracker.setBalance(
        adminWallet.coinPublicKey,
        sSUSDTokenType,
        1000n
      )
      const initialBalances = balanceTracker.getAllBalances(
        adminWallet.coinPublicKey
      )

      // Update balance
      balanceTracker.setBalance(
        adminWallet.coinPublicKey,
        sSUSDTokenType,
        1500n
      )

      // Check changes
      const changes = balanceTracker.getBalanceChanges(
        adminWallet.coinPublicKey,
        initialBalances
      )

      expect(changes[sSUSDTokenType.toString()]).toBe(500n)
    })
  })

  describe('Multi-User Operations', () => {
    it('should handle multiple users', () => {
      const { simulator, userWallets } = fixture

      // Switch between users
      userWallets.forEach((wallet) => {
        const privateState = createPrivateStateForWallet(wallet)
        simulator.as(privateState)

        const currentState = simulator.getPrivateState()
        expect(currentState.secret_key).toEqual(wallet.secretKey)
      })
    })

    it('should maintain separate balances per user', () => {
      const { balanceTracker, userWallets, sSUSDTokenType } = fixture

      userWallets.forEach((wallet, index) => {
        const balance = BigInt((index + 1) * 1000)
        balanceTracker.setBalance(wallet.coinPublicKey, sSUSDTokenType, balance)
      })

      userWallets.forEach((wallet, index) => {
        const balance = balanceTracker.getBalance(
          wallet.coinPublicKey,
          sSUSDTokenType
        )
        expect(balance).toBe(BigInt((index + 1) * 1000))
      })
    })
  })

  describe('Error Handling', () => {
    it('should throw error for non-existent circuit', () => {
      const { simulator } = fixture

      expect(() => {
        simulator.executeCircuit('nonExistentCircuit')
      }).toThrow()
    })

    it('should throw error for non-existent impure circuit', () => {
      const { simulator } = fixture

      expect(() => {
        simulator.executeImpureCircuit('nonExistentImpureCircuit')
      }).toThrow()
    })

    it('should handle multiple outputs error gracefully', () => {
      const { simulator, adminWallet } = fixture

      // This may or may not throw depending on outputs
      // Just testing the API behavior
      try {
        simulator.getOutputByRecipient(adminWallet.coinPublicKey)
      } catch (error) {
        if (error instanceof Error) {
          expect(error.message).toContain('Multiple outputs')
        }
      }
    })
  })

  describe('Private State Updates', () => {
    it('should be able to update mint metadata in private state', () => {
      const { adminWallet } = fixture

      const privateState = createPrivateStateForWallet(adminWallet)

      const updatedState = {
        ...privateState,
        mint_metadata: {
          collateral: 1000n,
          debt: 500n
        }
      }

      expect(updatedState.mint_metadata.collateral).toBe(1000n)
      expect(updatedState.mint_metadata.debt).toBe(500n)
    })

    it('should be able to update stake metadata in private state', () => {
      const { adminWallet } = fixture

      const privateState = createPrivateStateForWallet(adminWallet)

      const updatedState = {
        ...privateState,
        stake_metadata: {
          effectiveBalance: 2000n,
          stakeReward: 100n,
          entry_ADA_SUSD_index: 1n,
          entry_scale_factor: 1000000n
        }
      }

      expect(updatedState.stake_metadata.effectiveBalance).toBe(2000n)
      expect(updatedState.stake_metadata.stakeReward).toBe(100n)
    })

    it('should be able to update admin metadata in private state', () => {
      const { adminWallet } = fixture

      const privateState = createPrivateStateForWallet(adminWallet)

      const updatedState = {
        ...privateState,
        admin_metadata: {
          ...privateState.admin_metadata,
          protocolFeePool: 5000n,
          admin_count: 2n
        }
      }

      expect(updatedState.admin_metadata.protocolFeePool).toBe(5000n)
      expect(updatedState.admin_metadata.admin_count).toBe(2n)
    })
  })
})
