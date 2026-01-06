// Browser stub for node-rsa
// The @microsoft/dev-tunnels-ssh library imports node-rsa but uses WebCrypto as fallback
// This stub prevents the import error in browsers

export default class NodeRSA {
  constructor() {
    throw new Error("node-rsa is not available in browser - use WebCrypto instead");
  }
}
