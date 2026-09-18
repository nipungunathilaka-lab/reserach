import { useState, useEffect } from 'react';
import { useAuth } from '../auth/AuthContext';
import { ShieldAlert, ShieldCheck, Loader2, AlertTriangle, Key } from 'lucide-react';
import api, { apiError } from '../api/client';
import { generateSigningKeyPair, signChallenge, hasSigningKey, getLocalSigningKeyFingerprint } from '../utils/cryptoSigning';

export default function SigningSetup({ onStateChange }) {
  const { user } = useAuth();
  const [status, setStatus] = useState('checking'); // checking, UNINITIALIZED, SERVER_ONLY, BOUND, MISMATCHED, error, generating
  const [error, setError] = useState(null);
  const [fingerprint, setFingerprint] = useState(null);

  useEffect(() => {
    if (onStateChange) {
      onStateChange(status, fingerprint);
    }
  }, [status, fingerprint, onStateChange]);

  useEffect(() => {
    if (!user) return;
    checkStatus();
  }, [user]);

  const checkStatus = async () => {
    try {
      const res = await api.get('/crypto/key-status');
      const hasBackendKey = res.data.has_active_key;
      const backendFingerprint = res.data.fingerprint;
      
      const hasLocalKey = await hasSigningKey(user.id);
      let localFingerprint = null;
      if (hasLocalKey) {
        localFingerprint = await getLocalSigningKeyFingerprint(user.id);
      }

      if (hasBackendKey && hasLocalKey) {
        if (localFingerprint === backendFingerprint) {
          setFingerprint(backendFingerprint);
          setStatus('BOUND');
        } else {
          setStatus('MISMATCHED');
        }
      } else if (hasBackendKey && !hasLocalKey) {
        setStatus('SERVER_ONLY');
      } else if (!hasBackendKey && hasLocalKey) {
        // Technically LOCAL_ONLY, but let's just force a re-setup/bind
        setStatus('UNINITIALIZED');
      } else {
        setStatus('UNINITIALIZED');
      }
    } catch (err) {
      setError(apiError(err));
      setStatus('error');
    }
  };

  const handleSetup = async () => {
    try {
      setStatus('generating');
      setError(null);
      
      // 1. Generate keys
      const { publicSpkiBase64, fingerprint: newFingerprint } = await generateSigningKeyPair(user.id);
      
      // 2. Request challenge
      const challengeRes = await api.post('/crypto/register-key-challenge');
      const nonce = challengeRes.data.nonce;

      // 3. Sign challenge
      const signatureBase64 = await signChallenge(user.id, nonce);

      // 4. Register public key
      await api.post('/crypto/register-key', {
        nonce,
        public_key_spki: publicSpkiBase64,
        public_key_fingerprint: newFingerprint,
        signature: signatureBase64
      });

      setFingerprint(newFingerprint);
      setStatus('BOUND');
    } catch (err) {
      setError(apiError(err));
      setStatus('error');
    }
  };

  if (status === 'checking' || status === 'generating') {
    return (
      <div className="mb-6 rounded-2xl border border-white/10 bg-slate-900/40 p-6 flex items-center shadow-xl backdrop-blur-md">
        <Loader2 className="mr-3 h-5 w-5 animate-spin text-cyan-400" />
        <p className="text-sm font-medium text-slate-300">
          {status === 'generating' ? 'Generating RSA-PSS keys in browser securely...' : 'Checking security bindings...'}
        </p>
      </div>
    );
  }

  if (status === 'UNINITIALIZED') {
    return (
      <div className="mb-6 rounded-2xl border border-amber-500/20 bg-amber-500/10 p-6 shadow-[0_0_15px_rgba(245,158,11,0.1)] transition-all">
        <div className="flex items-start">
          <ShieldAlert className="mr-4 mt-1 h-6 w-6 text-amber-400" />
          <div className="flex-1">
            <h3 className="text-lg font-bold text-amber-100">Setup Cryptographic Signing</h3>
            <p className="mt-2 text-sm text-amber-100/80">
              Generate a local RSA-PSS signing key to authorize file transfers. 
              The private key remains in this browser and is never sent to the server.
            </p>
            {error && <p className="mt-3 text-sm font-medium text-red-400">{error}</p>}
            <button
              onClick={handleSetup}
              className="mt-4 rounded-xl bg-amber-500/20 px-4 py-2 text-sm font-semibold text-amber-200 transition-colors hover:bg-amber-500/30"
            >
              Generate & Bind Signing Key
            </button>
          </div>
        </div>
      </div>
    );
  }

  if (status === 'SERVER_ONLY' || status === 'MISMATCHED') {
    return (
      <div className="mb-6 rounded-2xl border border-red-500/20 bg-red-500/10 p-6 shadow-[0_0_15px_rgba(239,68,68,0.1)] transition-all">
        <div className="flex items-start">
          <AlertTriangle className="mr-4 mt-1 h-6 w-6 text-red-400" />
          <div className="flex-1">
            <h3 className="text-lg font-bold text-red-100">Signing key unavailable on this device</h3>
            <p className="mt-2 text-sm text-red-100/80">
              Your account has a registered signing key, but the private key is missing or mismatched on this device. 
              You must register a new key to send files from this browser.
            </p>
            {error && <p className="mt-3 text-sm font-medium text-red-400">{error}</p>}
            <button
              onClick={handleSetup}
              className="mt-4 flex items-center gap-2 rounded-xl bg-red-500/20 px-4 py-2 text-sm font-semibold text-red-200 transition-colors hover:bg-red-500/30"
            >
              <Key className="h-4 w-4" />
              Register New Signing Key
            </button>
          </div>
        </div>
      </div>
    );
  }

  if (status === 'error') {
     return (
      <div className="mb-6 rounded-2xl border border-red-500/20 bg-red-500/10 p-6">
        <div className="flex items-start">
          <AlertTriangle className="mr-4 mt-1 h-6 w-6 text-red-400" />
          <div className="flex-1">
            <h3 className="text-lg font-bold text-red-100">Security Check Failed</h3>
            <p className="mt-2 text-sm text-red-100/80">{error}</p>
            <button
              onClick={checkStatus}
              className="mt-4 rounded-xl bg-slate-800 px-4 py-2 text-sm font-semibold text-white transition-colors hover:bg-slate-700"
            >
              Retry
            </button>
          </div>
        </div>
      </div>
     );
  }

  return (
    <div className="mb-6 rounded-2xl border border-emerald-500/20 bg-emerald-500/10 p-4 shadow-[0_0_15px_rgba(16,185,129,0.1)]">
      <div className="flex items-center">
        <ShieldCheck className="mr-3 h-5 w-5 text-emerald-400" />
        <div>
          <h3 className="text-sm font-bold text-emerald-100">Signing Key Active</h3>
          <p className="text-xs text-emerald-200/80 mt-1">This browser is ready to cryptographically sign file transfers.</p>
          <p className="text-xs text-emerald-200/60 font-mono mt-0.5">Fingerprint: {fingerprint}</p>
        </div>
      </div>
    </div>
  );
}
