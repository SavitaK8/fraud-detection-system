
/**
 * ThreatList Component
 * Displays list of detected threats
 */

import React from 'react';
import { AlertTriangle } from 'lucide-react';

const ThreatList = ({ threats }) => {
  if (!threats || threats.length === 0) {
    return null;
  }

  return (
    <div className="bg-red-50 rounded-xl p-6 border-2 border-red-200">
      <h3 className="text-xl font-bold text-red-800 mb-4 flex items-center gap-2">
        <AlertTriangle className="w-6 h-6" />
        Threats Detected ({threats.length})
      </h3>
      <div className="space-y-2">
        {threats.map((threat, idx) => (
          <div key={idx} className="flex items-start gap-3 p-3 bg-white rounded-lg shadow-sm">
            <span className="text-red-600 font-mono text-sm flex-shrink-0 font-bold">
              #{idx + 1}
            </span>
            <span className="text-gray-800 flex-1">{threat}</span>
          </div>
        ))}
      </div>
    </div>
  );
};

export default ThreatList;
