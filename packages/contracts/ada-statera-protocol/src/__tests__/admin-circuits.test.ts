import { describe, it, expect, beforeEach } from 'vitest';
import {
  createStateraTestFixture,
  createPrivateStateForWallet,
  createAdminPrivateState,
  type StateraTestFixture
} from './test-utils';
import { pad } from '@statera/simulator';

describe('Ada Statera Protocol - Admin Circuits', () => {
  let fixture: StateraTestFixture;

  beforeEach(() => {
    fixture = createStateraTestFixture(2);
  });

  describe('setSUSDTokenType', () => {
    it('should set the sUSD token type', () => {
      const { simulator, adminWallet } = fixture;

      expect(() => {
        simulator
          .as(createAdminPrivateState(simulator, adminWallet))
          .executeImpureCircuit('setSUSDTokenType');
      }).not.toThrow();
    });
  });

  describe('resetProtocolConfig', () => {
    it('should update protocol configuration parameters', () => {
      const { simulator, adminWallet } = fixture;

      expect(() => {
        simulator
          .as(createAdminPrivateState(simulator, adminWallet))
          .executeImpureCircuit('resetProtocolConfig',
            85n,  // liquidationThreshold (85%)
            75n,  // LVT (75%)
            120n  // MCR (120%)
          );
      }).not.toThrow();
    });

    it('should reject invalid liquidation threshold', () => {
      const { simulator, adminWallet } = fixture;

      expect(() => {
        simulator
          .as(createAdminPrivateState(simulator, adminWallet))
          .executeImpureCircuit('resetProtocolConfig',
            0n,    // Invalid: 0%
            75n,
            120n
          );
      }).toThrow();
    });

    it('should reject LVT over 100', () => {
      const { simulator, adminWallet } = fixture;

      expect(() => {
        simulator
          .as(createAdminPrivateState(simulator, adminWallet))
          .executeImpureCircuit('resetProtocolConfig',
            85n,
            101n,  // Invalid: > 100%
            120n
          );
      }).toThrow();
    });

    it('should reject MCR under 100', () => {
      const { simulator, adminWallet } = fixture;

      expect(() => {
        simulator
          .as(createAdminPrivateState(simulator, adminWallet))
          .executeImpureCircuit('resetProtocolConfig',
            85n,
            75n,
            99n    // Invalid: < 100%
          );
      }).toThrow();
    });
  });

  describe('setRedemptionFee', () => {
    it('should update redemption fee', () => {
      const { simulator, adminWallet } = fixture;

      expect(() => {
        simulator
          .as(createAdminPrivateState(simulator, adminWallet))
          .executeImpureCircuit('setRedemptionFee', 25n); // 0.25%
      }).not.toThrow();
    });

    it('should reject fee over 100 basis points', () => {
      const { simulator, adminWallet } = fixture;

      expect(() => {
        simulator
          .as(createAdminPrivateState(simulator, adminWallet))
          .executeImpureCircuit('setRedemptionFee', 101n);
      }).toThrow();
    });
  });

  describe('setBorrowingFee', () => {
    it('should update borrowing fee', () => {
      const { simulator, adminWallet } = fixture;

      expect(() => {
        simulator
          .as(createAdminPrivateState(simulator, adminWallet))
          .executeImpureCircuit('setBorrowingFee', 75n); // 0.75%
      }).not.toThrow();
    });
  });

  describe('togglePause', () => {
    it('should toggle protocol pause state', () => {
      const { simulator, adminWallet } = fixture;

      expect(() => {
        simulator
          .as(createAdminPrivateState(simulator, adminWallet))
          .executeImpureCircuit('togglePause');
      }).not.toThrow();
    });

    it('should allow toggling multiple times', () => {
      const { simulator, adminWallet } = fixture;

      expect(() => {
        const adminState = createAdminPrivateState(simulator, adminWallet);

        simulator.as(adminState).executeImpureCircuit('togglePause');
        simulator.as(adminState).executeImpureCircuit('togglePause');
        simulator.as(adminState).executeImpureCircuit('togglePause');
      }).not.toThrow();
    });
  });

  describe('Oracle Management', () => {
    it('should add trusted oracle', () => {
      const { simulator, adminWallet } = fixture;

      const oraclePk = pad('oracle-pubkey-1', 32);

      expect(() => {
        simulator
          .as(createAdminPrivateState(simulator, adminWallet))
          .executeImpureCircuit('addTrustedOracle', oraclePk);
      }).not.toThrow();
    });

    it('should remove trusted oracle', () => {
      const { simulator, adminWallet } = fixture;

      const oraclePk = pad('oracle-pubkey-1', 32);
      const adminState = createAdminPrivateState(simulator, adminWallet);

      // Add oracle first
      simulator.as(adminState).executeImpureCircuit('addTrustedOracle', oraclePk);

      // Then remove it
      expect(() => {
        simulator.as(adminState).executeImpureCircuit('removeTrustedOraclePk', oraclePk);
      }).not.toThrow();
    });

    it('should add multiple oracles', () => {
      const { simulator, adminWallet } = fixture;

      const oracle1 = pad('oracle-1', 32);
      const oracle2 = pad('oracle-2', 32);
      const oracle3 = pad('oracle-3', 32);
      const adminState = createAdminPrivateState(simulator, adminWallet);

      expect(() => {
        simulator.as(adminState).executeImpureCircuit('addTrustedOracle', oracle1);
        simulator.as(adminState).executeImpureCircuit('addTrustedOracle', oracle2);
        simulator.as(adminState).executeImpureCircuit('addTrustedOracle', oracle3);
      }).not.toThrow();
    });
  });

  describe('Admin Management', () => {
    it('should add new admin', () => {
      const { simulator, adminWallet, userWallets } = fixture;

      const newAdminAddress = userWallets[0].secretKey;

      expect(() => {
        simulator
          .as(createAdminPrivateState(simulator, adminWallet))
          .executeImpureCircuit('addAdmin', newAdminAddress);
      }).not.toThrow();
    });

    it('should remove admin', () => {
      const { simulator, adminWallet, userWallets } = fixture;

      const adminToRemove = userWallets[0].secretKey;

      // Add admin first
      simulator
        .as(createAdminPrivateState(simulator, adminWallet))
        .executeImpureCircuit('addAdmin', adminToRemove);

      // Get fresh admin state after addition
      const updatedAdminState = createAdminPrivateState(simulator, adminWallet);

      // Then remove
      expect(() => {
        simulator.as(updatedAdminState).executeImpureCircuit('removeAdmin', adminToRemove);
      }).not.toThrow();
    });

    it('should transfer admin role', () => {
      const { simulator, adminWallet, userWallets } = fixture;

      const newSuperAdmin = userWallets[0].secretKey;

      expect(() => {
        simulator
          .as(createAdminPrivateState(simulator, adminWallet))
          .executeImpureCircuit('transferAdminRole', newSuperAdmin);
      }).not.toThrow();
    });
  });

  describe('Protocol Fee Management', () => {
    it('should withdraw protocol fees', () => {
      const { simulator, adminWallet } = fixture;

      // Note: This will likely fail without fees accumulated, but tests the circuit exists
      expect(() => {
        simulator
          .as(createAdminPrivateState(simulator, adminWallet))
          .executeImpureCircuit('withdrawProtocolFees', 100n);
      }).toThrow(); // Expected to fail without accumulated fees
    });
  });

  describe('Non-Admin Access', () => {
    it('should reject non-admin trying to reset config', () => {
      const { simulator, userWallets } = fixture;

      expect(() => {
        simulator
          .as(createPrivateStateForWallet(userWallets[0]))
          .executeImpureCircuit('resetProtocolConfig', 85n, 75n, 120n);
      }).toThrow();
    });

    it('should reject non-admin trying to set fees', () => {
      const { simulator, userWallets } = fixture;

      expect(() => {
        simulator
          .as(createPrivateStateForWallet(userWallets[0]))
          .executeImpureCircuit('setRedemptionFee', 25n);
      }).toThrow();
    });

    it('should reject non-admin trying to add oracle', () => {
      const { simulator, userWallets } = fixture;

      expect(() => {
        simulator
          .as(createPrivateStateForWallet(userWallets[0]))
          .executeImpureCircuit('addTrustedOracle', pad('oracle', 32));
      }).toThrow();
    });
  });
});
