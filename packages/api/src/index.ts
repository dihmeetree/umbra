import { combineLatest, concat, from, map, Observable, tap } from 'rxjs'
import {
  DeployedStateraOnchainContract,
  DerivedStateraContractState,
  StateraContract,
  StateraContractProviders,
  stateraPrivateStateId
} from './common-types.js'
import {
  ContractAddress,
  encodeCoinPublicKey
} from '@midnight-ntwrk/compact-runtime'
import {
  deployContract,
  FinalizedCallTxData,
  findDeployedContract
} from '@midnight-ntwrk/midnight-js-contracts'
import {
  Contract,
  ledger,
  StateraPrivateState,
  witnesses,
  type CoinInfo,
  createPrivateStateraState
} from '@statera/ada-statera-protocol'
import { type Logger } from 'pino'
import * as utils from './utils.js'
import { encodeTokenType, nativeToken, tokenType } from '@midnight-ntwrk/ledger'

const StateraContractInstance: StateraContract = new Contract(witnesses)

export interface DeployedStateraAPI {
  readonly deployedContractAddress: ContractAddress
  readonly state: Observable<DerivedStateraContractState>
  depositToCollateralPool: (
    amount: number
  ) => Promise<FinalizedCallTxData<StateraContract, 'depositToCollateralPool'>>
  liquidatePosition: (
    collateralId: string,
    providers: StateraContractProviders
  ) => Promise<FinalizedCallTxData<StateraContract, 'liquidateDebtPosition'>>
  depositToStakePool: (
    amount: number
  ) => Promise<FinalizedCallTxData<StateraContract, 'depositToStabilityPool'>>
  withdrawStakeReward: (
    amountToWithdraw: number
  ) => Promise<FinalizedCallTxData<StateraContract, 'withdrawStakeReward'>>
  withdrawStake: (
    amount: number
  ) => Promise<FinalizedCallTxData<StateraContract, 'withdrawStake'>>
  mint_sUSD: (
    mint_amount: number
  ) => Promise<FinalizedCallTxData<StateraContract, 'mint_sUSD'>>
  repay: (
    amount: number
  ) => Promise<FinalizedCallTxData<StateraContract, 'repay'>>
  withdrawCollateral: (
    amountToWithdraw: number,
    _oraclePrice: number,
    oraclePk: string
  ) => Promise<FinalizedCallTxData<StateraContract, 'withdrawCollateral'>>
  checkStakeReward: () => Promise<
    FinalizedCallTxData<StateraContract, 'checkStakeReward'>
  >
  reset: (
    liquidation_threshold: number,
    LVT: number,
    MCR: number
  ) => Promise<FinalizedCallTxData<StateraContract, 'resetProtocolConfig'>>
  addAdmin: (
    addrs: string
  ) => Promise<FinalizedCallTxData<StateraContract, 'addAdmin'>>
  setSUSDColor: () => Promise<
    FinalizedCallTxData<StateraContract, 'setSUSDTokenType'>
  >
  transferSuperAdminRole: (
    addrs: string
  ) => Promise<FinalizedCallTxData<StateraContract, 'transferAdminRole'>>
  addTrustedOracle: (
    oraclePk: string
  ) => Promise<FinalizedCallTxData<StateraContract, 'addTrustedOracle'>>
  removeTrustedOracle: (
    oraclePk: string
  ) => Promise<FinalizedCallTxData<StateraContract, 'removeTrustedOraclePk'>>
  redeemSUSD: (
    amount: number,
    oraclePrice: number,
    oraclePk: string
  ) => Promise<FinalizedCallTxData<StateraContract, 'redeemSUSD'>>
  setRedemptionFee: (
    feeInBasisPoints: number
  ) => Promise<FinalizedCallTxData<StateraContract, 'setRedemptionFee'>>
}

export class StateraAPI implements DeployedStateraAPI {
  deployedContractAddress: string
  state: Observable<DerivedStateraContractState>

  /**
   * @param allReadyDeployedContract
   * @param logger becomes accessible s if they were decleared as static properties as part of the class
   */
  private constructor(
    private providers: StateraContractProviders,
    public readonly allReadyDeployedContract: DeployedStateraOnchainContract,
    private logger?: Logger
  ) {
    this.deployedContractAddress =
      allReadyDeployedContract.deployTxData.public.contractAddress

    // Set the state property
    this.state = combineLatest(
      [
        providers.publicDataProvider
          .contractStateObservable(this.deployedContractAddress, {
            type: 'all'
          })
          .pipe(
            map((contractState) => ledger(contractState.data)),
            tap((ledgerState) =>
              logger?.trace({
                ledgerStateChanged: {
                  ledgerState: {
                    ...ledgerState
                  }
                }
              })
            )
          ),
        concat(from(providers.privateStateProvider.get(stateraPrivateStateId)))
      ],
      (ledgerState, privateState) => {
        return {
          sUSDTokenType: ledgerState.sUSDTokenType,
          liquidationThreshold: ledgerState.liquidationThreshold,
          // Direct Map storage - count entries
          depositorsCount: ledgerState.depositors.size(),
          stakersCount: ledgerState.stakers.size(),
          mintMetadata: privateState?.mint_metadata,
          secret_key: privateState?.secret_key,
          LVT: ledgerState.LVT,
          MCR: ledgerState.MCR,
          liquidationCount: ledgerState.liquidationCount,
          validCollateralType: ledgerState.validCollateralAssetType,
          trustedOracles: utils.createDerivedOraclesArray(
            ledgerState.trustedOracles
          )
        }
      }
    )
  }

  static async deployStateraContract(
    providers: StateraContractProviders,
    logger?: Logger
  ): Promise<StateraAPI> {
    logger?.info('deploy contract')
    /**
     * Should deploy a new contract to the blockchain
     * Return the newly deployed contract
     * Log the resulting data about of the newly deployed contract using (logger)
     */
    const deployedContract = await deployContract<StateraContract>(providers, {
      contract: StateraContractInstance,
      initialPrivateState: await StateraAPI.getPrivateState(providers),
      privateStateId: stateraPrivateStateId,
      args: [
        90n, // initLiquidationThreshold: 90%
        80n, // initialLVT: 80%
        120n, // initialMCR: 120%
        encodeTokenType(nativeToken()), // _validCollateralAssetType
        5n, // initialRedemptionFee: 5% (stored as percentage, max 255)
        5n, // initialBorrowingFee: 5% (stored as percentage, max 255)
        10n, // initialLiquidationIncentive: 10% (stored as percentage, max 255)
        100n // initialMinimumDebt: 100 sUSD minimum debt
      ]
    })

    logger?.trace('Deployment successfull', {
      contractDeployed: {
        finalizedDeployTxData: deployedContract.deployTxData.public
      }
    })

    const api = new StateraAPI(providers, deployedContract, logger)

    // Note: Skipping automatic initialization of oracle and sUSD token type
    // These can be called manually after deployment if needed:
    // - await api.addTrustedOracle(oraclePk)
    // - await api.setSUSDColor()

    return api
  }

  static async joinStateraContract(
    providers: StateraContractProviders,
    contractAddress: string,
    logger?: Logger
  ): Promise<StateraAPI> {
    logger?.info({
      joinContract: {
        contractAddress
      }
    })
    /**
     * Should deploy a new contract to the blockchain
     * Return the newly deployed contract
     * Log the resulting data about of the newly deployed contract using (logger)
     */
    const existingContract = await findDeployedContract<StateraContract>(
      providers,
      {
        contract: StateraContractInstance,
        contractAddress: contractAddress,
        privateStateId: stateraPrivateStateId,
        initialPrivateState: await StateraAPI.getPrivateState(providers)
      }
    )

    logger?.trace('Found Contract...', {
      contractJoined: {
        finalizedDeployTxData: existingContract.deployTxData.public
      }
    })
    return new StateraAPI(providers, existingContract, logger)
  }

  coin(amount: number): CoinInfo {
    return {
      color: encodeTokenType(nativeToken()),
      nonce: utils.randomNonceBytes(32),
      value: BigInt(amount)
    }
  }

  sUSD_coin(amount: number): CoinInfo {
    return {
      color: encodeTokenType(
        tokenType(utils.pad('sUSD_token', 32), this.deployedContractAddress)
      ),
      nonce: utils.randomNonceBytes(32),
      value: BigInt(amount)
    }
  }

  async depositToCollateralPool(
    amount: number
  ): Promise<FinalizedCallTxData<StateraContract, 'depositToCollateralPool'>> {
    this.logger?.info(`Depositing collateral...`)

    // Check if this is a new depositor by checking private state
    const privateState = await this.providers.privateStateProvider.get(stateraPrivateStateId)
    const isNewDepositor = !privateState?.mint_metadata ||
                           (privateState.mint_metadata.collateral === 0n && privateState.mint_metadata.debt === 0n)

    this.logger?.debug(`Depositor status: ${isNewDepositor ? 'NEW' : 'EXISTING'}`)

    const deposit_unit_specks = amount * 1_000_000
    const txData =
      await this.allReadyDeployedContract.callTx.depositToCollateralPool(
        this.coin(deposit_unit_specks),
        BigInt(amount),
        utils.getTestComplianceToken()
      )

    this.logger?.trace('Collateral Deposit was successful', {
      transactionAdded: {
        circuit: 'depositToCollateralPool',
        txHash: txData.public.txHash,
        blockDetails: {
          blockHash: txData.public.blockHash,
          blockHeight: txData.public.blockHeight
        }
      }
    })

    return txData
  }

  // Repays debtAsset
  async repay(
    amount: number
  ): Promise<FinalizedCallTxData<StateraContract, 'repay'>> {
    this.logger?.info('Repaying debt asset...')
    // Construct tx with dynamic coin data
    const txData = await this.allReadyDeployedContract.callTx.repay(
      this.sUSD_coin(amount),
      BigInt(amount)
    )

    this.logger?.trace({
      transactionAdded: {
        circuit: 'repay',
        txHash: txData.public.txHash,
        blockDetails: {
          blockHash: txData.public.blockHash,
          blockHeight: txData.public.blockHeight
        }
      }
    })
    return txData
  }

  async setSUSDColor(): Promise<
    FinalizedCallTxData<StateraContract, 'setSUSDTokenType'>
  > {
    const txData = await this.allReadyDeployedContract.callTx.setSUSDTokenType()

    this.logger?.trace({
      transactionAdded: {
        circuit: 'setSUSDTokenType',
        txHash: txData.public.txHash,
        blockDetails: {
          blockHash: txData.public.blockHash,
          blockHeight: txData.public.blockHeight
        }
      }
    })

    return txData
  }

  async reset(
    liquidation_threshold: number,
    LVT: number,
    MCR: number
  ): Promise<FinalizedCallTxData<StateraContract, 'resetProtocolConfig'>> {
    const txData =
      await this.allReadyDeployedContract.callTx.resetProtocolConfig(
        BigInt(liquidation_threshold),
        BigInt(LVT),
        BigInt(MCR)
      )

    this.logger?.trace({
      transactionAdded: {
        circuit: 'reset',
        txHash: txData.public.txHash,
        blockDetails: {
          blockHash: txData.public.blockHash,
          blockHeight: txData.public.blockHeight
        }
      }
    })

    return txData
  }

  async addAdmin(
    addrs: string
  ): Promise<FinalizedCallTxData<StateraContract, 'addAdmin'>> {
    const txData = await this.allReadyDeployedContract.callTx.addAdmin(
      encodeCoinPublicKey(addrs)
    )

    this.logger?.trace({
      transactionAdded: {
        circuit: 'addAdmin',
        txHash: txData.public.txHash,
        blockDetails: {
          blockHash: txData.public.blockHash,
          blockHeight: txData.public.blockHeight
        }
      }
    })

    return txData
  }

  async addTrustedOracle(
    oraclePk: string
  ): Promise<FinalizedCallTxData<StateraContract, 'addTrustedOracle'>> {
    const txData = await this.allReadyDeployedContract.callTx.addTrustedOracle(
      utils.hexStringToUint8Array(oraclePk)
    )

    this.logger?.trace({
      transactionAdded: {
        circuit: 'addAdmin',
        txHash: txData.public.txHash,
        blockDetails: {
          blockHash: txData.public.blockHash,
          blockHeight: txData.public.blockHeight
        }
      }
    })

    return txData
  }

  async removeTrustedOracle(
    oraclePk: string
  ): Promise<FinalizedCallTxData<StateraContract, 'removeTrustedOraclePk'>> {
    const txData =
      await this.allReadyDeployedContract.callTx.removeTrustedOraclePk(
        utils.hexStringToUint8Array(oraclePk)
      )

    this.logger?.trace({
      transactionAdded: {
        circuit: 'addAdmin',
        txHash: txData.public.txHash,
        blockDetails: {
          blockHash: txData.public.blockHash,
          blockHeight: txData.public.blockHeight
        }
      }
    })

    return txData
  }

  async transferSuperAdminRole(
    addrs: string
  ): Promise<FinalizedCallTxData<StateraContract, 'transferAdminRole'>> {
    const txData = await this.allReadyDeployedContract.callTx.transferAdminRole(
      encodeCoinPublicKey(addrs)
    )

    this.logger?.trace({
      transactionAdded: {
        circuit: 'transferSuperAdminRole',
        txHash: txData.public.txHash,
        blockDetails: {
          blockHash: txData.public.blockHash,
          blockHeight: txData.public.blockHeight
        }
      }
    })

    return txData
  }

  // Repay debtAsset
  async withdrawCollateral(
    amountToWithdraw: number,
    _oraclePrice: number,
    oraclePk: string
  ): Promise<FinalizedCallTxData<StateraContract, 'withdrawCollateral'>> {
    this.logger?.info('Withdrawing collateral asset...')
    // Construct tx with dynamic coin data
    const txData =
      await this.allReadyDeployedContract.callTx.withdrawCollateral(
        BigInt(amountToWithdraw),
        BigInt(_oraclePrice),
        utils.hexStringToUint8Array(oraclePk)
      )

    this.logger?.trace({
      transactionAdded: {
        circuit: 'witdrawCollateral',
        txHash: txData.public.txHash,
        blockDetails: {
          blockHash: txData.public.blockHash,
          blockHeight: txData.public.blockHeight
        }
      }
    })
    return txData
  }

  // Mints sUSD
  async mint_sUSD(
    mint_amount: number
  ): Promise<FinalizedCallTxData<StateraContract, 'mint_sUSD'>> {
    this.logger?.trace(`Minting sUSD for your loan position...`)

    const txData = await this.allReadyDeployedContract.callTx.mint_sUSD(
      BigInt(mint_amount)
    )
    this.logger?.trace({
      transactionAdded: {
        circuit: 'mint_sUSD',
        txHash: txData.public.txHash,
        mintValue: txData.public.tx.mint?.coin.value,
        blockDetails: {
          blockHash: txData.public.blockHash,
          blockHeight: txData.public.blockHeight
        }
      }
    })
    return txData
  }

  async depositToStakePool(
    amount: number
  ): Promise<FinalizedCallTxData<StateraContract, 'depositToStabilityPool'>> {
    this.logger?.info('Depositing to stake pool...')

    // Check if this is a new staker by checking private state
    const privateState = await this.providers.privateStateProvider.get(stateraPrivateStateId)
    const isNewStaker = !privateState?.stake_metadata ||
                        (privateState.stake_metadata.effectiveBalance === 0n && privateState.stake_metadata.stakeReward === 0n)

    this.logger?.debug(`Staker status: ${isNewStaker ? 'NEW' : 'EXISTING'}`)

    const txData =
      await this.allReadyDeployedContract.callTx.depositToStabilityPool(
        this.sUSD_coin(amount)
      )

    this.logger?.trace({
      transactionAdded: {
        circuit: 'depositToStabilityPool',
        txHash: txData.public.txHash,
        blockDetails: {
          blockHash: txData.public.blockHash,
          blockHeight: txData.public.blockHeight
        }
      }
    })
    return txData
  }

  async checkStakeReward(): Promise<
    FinalizedCallTxData<StateraContract, 'checkStakeReward'>
  > {
    this.logger?.info('Checking your stake reward...')
    // Construct tx with dynamic coin data
    const txData = await this.allReadyDeployedContract.callTx.checkStakeReward()

    this.logger?.trace({
      transactionAdded: {
        circuit: 'checkStakeReward',
        txHash: txData.public.txHash,
        blockDetails: {
          blockHash: txData.public.blockHash,
          blockHeight: txData.public.blockHeight
        }
      }
    })
    return txData
  }

  async withdrawStakeReward(amountToWithdraw: number) {
    this.logger?.info(`Withdrawing ${amountToWithdraw} of your stake reward...`)
    // Construct tx with dynamic coin data
    const txData =
      await this.allReadyDeployedContract.callTx.withdrawStakeReward(
        BigInt(amountToWithdraw)
      )

    this.logger?.trace({
      transactionAdded: {
        circuit: 'withdrawStakeReward',
        txHash: txData.public.txHash,
        blockDetails: {
          blockHash: txData.public.blockHash,
          blockHeight: txData.public.blockHeight
        }
      }
    })
    return txData
  }

  async withdrawStake(
    amount: number
  ): Promise<FinalizedCallTxData<StateraContract, 'withdrawStake'>> {
    this.logger?.info(
      `Withdrawing ${amount} from your effective stake pool balance...`
    )
    // Construct tx with dynamic coin data
    const txData = await this.allReadyDeployedContract.callTx.withdrawStake(
      BigInt(amount)
    )

    this.logger?.trace({
      transactionAdded: {
        circuit: 'withdrawStake',
        txHash: txData.public.txHash,
        blockDetails: {
          blockHash: txData.public.blockHash,
          blockHeight: txData.public.blockHeight
        }
      }
    })
    return txData
  }

  async liquidatePosition(
    collateralId: string,
    providers: StateraContractProviders
  ) {
    this.logger?.info(
      `Liquidating colateral position with ID: ${collateralId}...`
    )
    const privateState = await providers.privateStateProvider.get(
      'stateraPrivateState'
    )
    // Construct tx with dynamic coin data
    const txData =
      await this.allReadyDeployedContract.callTx.liquidateDebtPosition(
        privateState?.mint_metadata.collateral as bigint, // _totalCollateral
        privateState?.mint_metadata.debt as bigint, // _totalDebt
        privateState?.mint_metadata.debt as bigint, // _debtToLiquidate (full debt)
        utils.hexStringToUint8Array(collateralId) // _depositId
      )

    this.logger?.trace({
      transactionAdded: {
        circuit: 'liquidateCollateralPosition',
        txHash: txData.public.txHash,
        blockDetails: {
          blockHash: txData.public.blockHash,
          blockHeight: txData.public.blockHeight
        }
      }
    })
    return txData
  }

  // Used to get the private state from the wallets privateState Provider
  // Redeems sUSD for ADA from the reserve pool
  async redeemSUSD(
    amount: number,
    oraclePrice: number,
    oraclePk: string
  ): Promise<FinalizedCallTxData<StateraContract, 'redeemSUSD'>> {
    this.logger?.info(
      `Redeeming ${amount} sUSD for ADA at oracle price ${oraclePrice} from oracle ${oraclePk}...`
    )

    const txData = await this.allReadyDeployedContract.callTx.redeemSUSD(
      this.sUSD_coin(amount),
      BigInt(amount),
      BigInt(oraclePrice),
      utils.hexStringToUint8Array(oraclePk)
    )

    this.logger?.trace({
      transactionAdded: {
        circuit: 'redeemSUSD',
        txHash: txData.public.txHash,
        amountRedeemed: amount,
        oraclePrice: oraclePrice,
        oraclePk: oraclePk,
        blockDetails: {
          blockHash: txData.public.blockHash,
          blockHeight: txData.public.blockHeight
        }
      }
    })

    return txData
  }

  // Sets the redemption fee (admin only)
  async setRedemptionFee(
    feeInBasisPoints: number
  ): Promise<FinalizedCallTxData<StateraContract, 'setRedemptionFee'>> {
    this.logger?.info(
      `Setting redemption fee to ${feeInBasisPoints} basis points...`
    )

    const txData = await this.allReadyDeployedContract.callTx.setRedemptionFee(
      BigInt(feeInBasisPoints)
    )

    this.logger?.trace({
      transactionAdded: {
        circuit: 'setRedemptionFee',
        txHash: txData.public.txHash,
        feeInBasisPoints: feeInBasisPoints,
        blockDetails: {
          blockHash: txData.public.blockHash,
          blockHeight: txData.public.blockHeight
        }
      }
    })

    return txData
  }

  private static async getPrivateState(
    providers: StateraContractProviders
  ): Promise<StateraPrivateState> {
    const existingPrivateState = await providers.privateStateProvider.get(
      stateraPrivateStateId
    )

    // Validate existing private state
    if (existingPrivateState) {
      // Check if secret_key is valid
      if (existingPrivateState.secret_key &&
          existingPrivateState.secret_key.length === 32 &&
          existingPrivateState.secret_key instanceof Uint8Array) {
        return existingPrivateState
      }
      // If secret_key is invalid, fall through to create new state
      console.warn('Existing private state has invalid secret_key, recreating...')
    }

    // Create new private state with random secret key
    const secretKey = utils.randomNonceBytes(32)
    if (!secretKey || secretKey.length !== 32) {
      throw new Error('Failed to generate valid secret key')
    }

    const newPrivateState = createPrivateStateraState(secretKey)

    // Save the new private state immediately
    await providers.privateStateProvider.set(stateraPrivateStateId, newPrivateState)

    return newPrivateState
  }
}

export * as utils from './utils.js'

export * from './common-types.js'
