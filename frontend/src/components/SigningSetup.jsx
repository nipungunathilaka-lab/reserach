import { useState, useEffect } from 'react';
import { useAuth } from '../auth/AuthContext';
import { ShieldAlert, ShieldCheck, Loader2 } from 'lucide-react';
import api, { apiError } from '../api/client';
import { generateSigningKeyPair, signChallenge, hasSigningKey } from '../utils/cryptoSigning';

export default function SigningSetup() {
  const { user } = useAuth();
  const [status, setStatus] = useState('checking'); // checking, setup_needed, registered, error
  const [error, setError] = useState(null);
  const [fingerprint, setFingerprint] = useState(null);

  useEffect(() => {
    if (!user) return;
    checkStatus();
  }, [user]);

  const checkStatus = async () => {
    try {
      const res = await api.get('/crypto/key-status');
      const hasBackendKey = res.has_active_key;
      const backendFingerprint = res.fingerprint;
      
      const hasLocalKey = await hasSigningKey(user.id);

      if (hasBackendKey && hasLocalKey) {
        setFingerprint(backendFingerprint);
        setStatus('registered');
      } else {
        setStatus('setup_needed');
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
      const { publicSpkiBase64, fingerprint } = await generateSigningKeyPair(user.id);
      
      // 2. Request challenge
      const challengeRes = await api.post('/crypto/register-key-challenge');
      const nonce = challengeRes.nonce;

      // 3. Sign challenge
      const signatureBase64 = await signChallenge(user.id, nonce);

      // 4. Register public key
      await api.post('/crypto/register-key', {
        nonce,
        public_key_spki: publicSpkiBase64,
        public_key_fingerprint: fingerprint,
        signature: signatureBase64
      });

      setFingerprint(fingerprint);
      setStatus('registered');
    } catch (err) {
      setError(err.message || apiError(err));
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

  if (status === 'setup_needed') {
    return (
      <div className="mb-6 rounded-2xl border border-amber-500/20 bg-amber-500/10 p-6 shadow-[0_0_15px_rgba(245,158,11,0.1)] transition-all">
        <div className="flex items-start">
          <ShieldAlert className="mr-4 mt-1 h-6 w-6 text-amber-400" />
          <div className="flex-1">
            <h3 className="text-lg font-bold text-amber-100">Setup Cryptographic Non-Repudiation</h3>
            <p className="mt-2 text-sm text-amber-100/80">
              To send files securely, you must generate a local RSA-PSS signing key. 
              The private key will remain securely locked in this browser and will never be sent to the server.
            </p>
            {error && <p className="mt-3 text-sm font-medium text-red-400">{error}</p>}
            <button
              onClick={handleSetup}
              className="mt-4 rounded-xl bg-amber-500/20 px-4 py-2 text-sm font-semibold text-amber-200 transition-colors hover:bg-amber-500/30"
            >
              Generate & Bind Keys
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
          <p className="text-sm font-semibold text-emerald-100">Cryptographic Identity Bound (RSA-PSS)</p>
          <p className="text-xs text-emerald-200/60 font-mono mt-0.5">Fingerprint: {fingerprint}</p>
        </div>
      </div>
    </div>
  );
}
