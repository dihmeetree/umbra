/**
 * Custom error classes for the simulator
 */

export enum SimulatorErrorCode {
  CIRCUIT_NOT_FOUND = 'CIRCUIT_NOT_FOUND',
  IMPURE_CIRCUIT_NOT_FOUND = 'IMPURE_CIRCUIT_NOT_FOUND',
  INVALID_COIN_INPUT = 'INVALID_COIN_INPUT',
  MULTIPLE_OUTPUTS_FOUND = 'MULTIPLE_OUTPUTS_FOUND',
  OUTPUT_NOT_FOUND = 'OUTPUT_NOT_FOUND',
  WALLET_NOT_FOUND = 'WALLET_NOT_FOUND',
  INVALID_TOKEN_TYPE = 'INVALID_TOKEN_TYPE',
  CIRCUIT_EXECUTION_FAILED = 'CIRCUIT_EXECUTION_FAILED',
  INVALID_SNAPSHOT = 'INVALID_SNAPSHOT',
}

export class SimulatorError extends Error {
  constructor(
    public code: SimulatorErrorCode,
    message: string,
    public details?: any
  ) {
    super(message);
    this.name = 'SimulatorError';
  }
}

export class CircuitNotFoundError extends SimulatorError {
  constructor(circuitName: string, isPure: boolean = true) {
    super(
      isPure ? SimulatorErrorCode.CIRCUIT_NOT_FOUND : SimulatorErrorCode.IMPURE_CIRCUIT_NOT_FOUND,
      `${isPure ? 'Circuit' : 'Impure circuit'} '${circuitName}' not found in contract`,
      { circuitName, isPure }
    );
    this.name = 'CircuitNotFoundError';
  }
}

export class MultipleOutputsError extends SimulatorError {
  constructor(recipient: string, count: number) {
    super(
      SimulatorErrorCode.MULTIPLE_OUTPUTS_FOUND,
      `Multiple outputs (${count}) found for recipient ${recipient.slice(0, 8)}..., use getOutputsByRecipient instead`,
      { recipient, count }
    );
    this.name = 'MultipleOutputsError';
  }
}

export class OutputNotFoundError extends SimulatorError {
  constructor(recipient: string) {
    super(
      SimulatorErrorCode.OUTPUT_NOT_FOUND,
      `No output found for recipient ${recipient.slice(0, 8)}...`,
      { recipient }
    );
    this.name = 'OutputNotFoundError';
  }
}

export class WalletNotFoundError extends SimulatorError {
  constructor(walletName: string) {
    super(
      SimulatorErrorCode.WALLET_NOT_FOUND,
      `Wallet '${walletName}' not found`,
      { walletName }
    );
    this.name = 'WalletNotFoundError';
  }
}

export class CircuitExecutionError extends SimulatorError {
  constructor(circuitName: string, originalError: Error) {
    super(
      SimulatorErrorCode.CIRCUIT_EXECUTION_FAILED,
      `Circuit '${circuitName}' execution failed: ${originalError.message}`,
      { circuitName, originalError }
    );
    this.name = 'CircuitExecutionError';
  }
}
