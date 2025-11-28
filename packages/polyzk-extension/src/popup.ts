// Popup script - wallet connection only
export {};

interface WalletState {
  connected: boolean;
  address: string;
  privateKey: string;
}

let walletState: WalletState = {
  connected: false,
  address: "",
  privateKey: "",
};

const elements = {
  notConnected: document.getElementById("not-connected") as HTMLElement,
  connected: document.getElementById("connected") as HTMLElement,
  walletAddress: document.getElementById("wallet-address") as HTMLElement,
  privateKeyInput: document.getElementById("private-key") as HTMLInputElement,
  connectBtn: document.getElementById("connect-btn") as HTMLButtonElement,
  disconnectBtn: document.getElementById("disconnect-btn") as HTMLButtonElement,
};

async function init() {
  // Load wallet state from storage
  const stored = await chrome.storage.local.get(["wallet"]);
  if (stored.wallet?.connected) {
    walletState = stored.wallet;
    showConnectedState();
  } else {
    showNotConnectedState();
  }

  setupEventListeners();
}

function showNotConnectedState() {
  elements.notConnected.classList.remove("hidden");
  elements.connected.classList.add("hidden");
}

function showConnectedState() {
  elements.notConnected.classList.add("hidden");
  elements.connected.classList.remove("hidden");
  elements.walletAddress.textContent = walletState.address;
}

async function connectWallet() {
  const privateKey = elements.privateKeyInput.value.trim();

  if (!privateKey) {
    return;
  }

  // Validate private key format (basic check)
  if (!privateKey.startsWith("0x") || privateKey.length < 64) {
    alert("Invalid private key format");
    return;
  }

  try {
    // Derive address from private key (simplified - just show truncated key as address)
    const address = `${privateKey.slice(0, 10)}...${privateKey.slice(-8)}`;

    walletState = {
      connected: true,
      address,
      privateKey,
    };

    await chrome.storage.local.set({ wallet: walletState });
    elements.privateKeyInput.value = "";
    showConnectedState();
  } catch (error) {
    console.error("Failed to connect wallet:", error);
    alert("Failed to connect wallet");
  }
}

async function disconnectWallet() {
  walletState = {
    connected: false,
    address: "",
    privateKey: "",
  };

  await chrome.storage.local.remove("wallet");
  showNotConnectedState();
}

function setupEventListeners() {
  elements.connectBtn.addEventListener("click", connectWallet);
  elements.disconnectBtn.addEventListener("click", disconnectWallet);

  // Allow Enter key to submit
  elements.privateKeyInput.addEventListener("keydown", (e) => {
    if (e.key === "Enter") {
      connectWallet();
    }
  });
}

document.addEventListener("DOMContentLoaded", init);
