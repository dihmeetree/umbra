/**
 * Logger configuration for the simulator
 *
 * Allows controlling verbosity of simulator output during tests
 */

export enum LogLevel {
  NONE = 0,
  ERROR = 1,
  WARN = 2,
  INFO = 3,
  DEBUG = 4,
  TRACE = 5
}

class Logger {
  private level: LogLevel = LogLevel.WARN
  private prefix: string = '[Simulator]'

  setLevel(level: LogLevel): void {
    this.level = level
  }

  getLevel(): LogLevel {
    return this.level
  }

  setPrefix(prefix: string): void {
    this.prefix = prefix
  }

  error(message: string, ...args: any[]): void {
    if (this.level >= LogLevel.ERROR) {
      console.error(`${this.prefix} ERROR:`, message, ...args)
    }
  }

  warn(message: string, ...args: any[]): void {
    if (this.level >= LogLevel.WARN) {
      console.warn(`${this.prefix} WARN:`, message, ...args)
    }
  }

  info(message: string, ...args: any[]): void {
    if (this.level >= LogLevel.INFO) {
      console.log(`${this.prefix} INFO:`, message, ...args)
    }
  }

  debug(message: string, ...args: any[]): void {
    if (this.level >= LogLevel.DEBUG) {
      console.log(`${this.prefix} DEBUG:`, message, ...args)
    }
  }

  trace(message: string, ...args: any[]): void {
    if (this.level >= LogLevel.TRACE) {
      console.log(`${this.prefix} TRACE:`, message, ...args)
    }
  }

  group(label: string): void {
    if (this.level >= LogLevel.DEBUG) {
      console.group(`${this.prefix} ${label}`)
    }
  }

  groupEnd(): void {
    if (this.level >= LogLevel.DEBUG) {
      console.groupEnd()
    }
  }
}

export const logger = new Logger()

/**
 * Enable verbose logging for debugging
 */
export function enableDebugLogging(): void {
  logger.setLevel(LogLevel.DEBUG)
}

/**
 * Enable trace logging (most verbose)
 */
export function enableTraceLogging(): void {
  logger.setLevel(LogLevel.TRACE)
}

/**
 * Disable all logging except errors
 */
export function disableLogging(): void {
  logger.setLevel(LogLevel.ERROR)
}

/**
 * Set to quiet mode (only warnings and errors)
 */
export function setQuietMode(): void {
  logger.setLevel(LogLevel.WARN)
}
