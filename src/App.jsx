/**
 * Routes. Anything under the shell requires a token; a 401 anywhere in the app
 * clears it and returns here, which is why the handler is installed once at the
 * root rather than in each page.
 */
import { useEffect, useState } from 'react';
import { Navigate, Route, Routes, useNavigate } from 'react-router-dom';
import { setUnauthorizedHandler, tokenStore } from './api';
import { Shell } from './components/Shell';

import Login from './pages/Login';
import Dashboard from './pages/Dashboard';
import Findings from './pages/Findings';
import FindingDetail from './pages/FindingDetail';
import Assets from './pages/Assets';
import AssetDetail from './pages/AssetDetail';
import Controls from './pages/Controls';
import Exposure from './pages/Exposure';
import Optimizer from './pages/Optimizer';
import Simulator from './pages/Simulator';
import Monitor from './pages/Monitor';

export default function App() {
  const [signedIn, setSignedIn] = useState(() => Boolean(tokenStore.get()));
  const navigate = useNavigate();

  useEffect(() => {
    setUnauthorizedHandler(() => {
      setSignedIn(false);
      navigate('/login', { replace: true });
    });
  }, [navigate]);

  if (!signedIn) {
    return (
      <Routes>
        <Route path="/login" element={<Login onSignedIn={() => setSignedIn(true)} />} />
        <Route path="*" element={<Navigate to="/login" replace />} />
      </Routes>
    );
  }

  return (
    <Shell>
      <Routes>
        <Route path="/" element={<Navigate to="/dashboard" replace />} />
        <Route path="/login" element={<Navigate to="/dashboard" replace />} />
        <Route path="/dashboard" element={<Dashboard />} />
        <Route path="/findings" element={<Findings />} />
        <Route path="/findings/:id" element={<FindingDetail />} />
        <Route path="/assets" element={<Assets />} />
        <Route path="/assets/:id" element={<AssetDetail />} />
        <Route path="/controls" element={<Controls />} />
        <Route path="/exposure" element={<Exposure />} />
        <Route path="/optimizer" element={<Optimizer />} />
        <Route path="/simulator" element={<Simulator />} />
        <Route path="/monitor" element={<Monitor />} />
        <Route path="*" element={
          <div className="page">
            <div className="empty">
              That page does not exist yet.
              <a className="btn" href="/dashboard">Back to the dashboard</a>
            </div>
          </div>
        } />
      </Routes>
    </Shell>
  );
}
