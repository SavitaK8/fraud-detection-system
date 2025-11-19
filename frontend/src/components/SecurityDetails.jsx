
/**
 * SecurityDetails Component
 * Displays security analysis details
 */

import React from 'react';
import { Info } from 'lucide-react';

const SecurityDetails = ({ details }) => {
  if (!details || details.length === 0) {
    return null;
  }

  return (
    <div className="bg-blue-50 rounded-xl p-6 border-2 border-blue-200">
      <h3 className="text-xl font-bold text-blue-800 mb-4 flex items-center gap-2">
        <Info className="w-6 h-6" />
        Security Details ({details.length})
      </h3>
      <div className="space-y-2">
        {details.map((detail, idx) => (
          <div key={idx} className="flex items-start gap-3 p-3 bg-white rounded-lg shadow-sm">
            <span className="text-blue-600 font-mono text-sm flex-shrink-0 font-bold">
              #{idx + 1}
            </span>
            <span className="text-gray-800 flex-1">{detail}</span>
          </div>
        ))}
      </div>
    </div>
  );
};

export default SecurityDetails;
