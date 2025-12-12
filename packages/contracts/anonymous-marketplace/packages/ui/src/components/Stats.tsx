import { Component } from 'solid-js'
import type { Stats } from '../lib/api'

interface StatsProps {
  stats: Stats | null
}

export const StatsDisplay: Component<StatsProps> = (props) => {
  return (
    <div class="grid grid-cols-2 md:grid-cols-4 gap-4">
      <div class="bg-gray-800 rounded-lg p-4 text-center">
        <p class="text-3xl font-bold text-blue-400">
          {props.stats?.totalWallets ?? '-'}
        </p>
        <p class="text-sm text-gray-400">Wallets</p>
      </div>

      <div class="bg-gray-800 rounded-lg p-4 text-center">
        <p class="text-3xl font-bold text-purple-400">
          {props.stats?.totalListings ?? '-'}
        </p>
        <p class="text-sm text-gray-400">Total Listings</p>
      </div>

      <div class="bg-gray-800 rounded-lg p-4 text-center">
        <p class="text-3xl font-bold text-green-400">
          {props.stats?.activeListings ?? '-'}
        </p>
        <p class="text-sm text-gray-400">Active Listings</p>
      </div>

      <div class="bg-gray-800 rounded-lg p-4 text-center">
        <p class="text-3xl font-bold text-yellow-400">
          {props.stats?.totalSales ?? '-'}
        </p>
        <p class="text-sm text-gray-400">Total Sales</p>
      </div>
    </div>
  )
}
