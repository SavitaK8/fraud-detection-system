
/*
 * AnalysisTab Component
 * Individual tab button for analysis types
 */

import React from 'react';

const AnalysisTab = ({ tab, isActive, onClick, icon: Icon }) => {
  return (
    <button
      onClick={onClick}
      className={`flex-1 flex items-center justify-center gap-2 px-6 py-4 font-semibold transition-all ${
        isActive
          ? 'bg-blue-50 text-blue-600 border-b-2 border-blue-600'
          : 'text-gray-600 hover:bg-gray-50'
      }`}
    >
      <Icon className="w-5 h-5" />
      {tab.label}
    </button>
  );
};

export default AnalysisTab;
