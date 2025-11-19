
import React from 'react';
import { Brain, AlertTriangle, Info, CheckCircle } from 'lucide-react';

const RiskDisplay = ({ result }) => {
  const getRiskColor = (riskLevel) => {
    const colors = {
      'HIGH RISK': 'red',
      'MEDIUM RISK': 'yellow',
      'LOW RISK': 'blue',
      'SAFE': 'green',
    };
    return colors[riskLevel] || 'gray';
  };

  const getRiskColorClass = (color) => {
    const colors = {
      red: 'bg-red-500',
      yellow: 'bg-yellow-500',
      blue: 'bg-blue-500',
      green: 'bg-green-500',
    };
    return colors[color] || 'bg-gray-500';
  };

  const getRiskBorderClass = (color) => {
    const borders = {
      red: 'bg-red-50 border-red-200',
      yellow: 'bg-yellow-50 border-yellow-200',
      blue: 'bg-blue-50 border-blue-200',
      green: 'bg-green-50 border-green-200',
    };
    return borders[color] || 'bg-gray-50 border-gray-200';
  };

  const getRiskIcon = (color) => {
    if (color === 'red' || color === 'yellow') {
      return <AlertTriangle className={`w-8 h-8 ${color === 'red' ? 'text-red-600' : 'text-yellow-600'}`} />;
    } else if (color === 'blue') {
      return <Info className="w-8 h-8 text-blue-600" />;
    } else {
      return <CheckCircle className="w-8 h-8 text-green-600" />;
    }
  };

  const getRiskTextClass = (color) => {
    const textColors = {
      red: 'text-red-700',
      yellow: 'text-yellow-700',
      blue: 'text-blue-700',
      green: 'text-green-700',
    };
    return textColors[color] || 'text-gray-700';
  };

  const color = getRiskColor(result.risk_level);

  return (
    <div className="bg-gradient-to-br from-gray-50 to-gray-100 rounded-xl p-6 border-2 border-gray-200">
      <div className="flex items-center justify-between mb-4">
        <h3 className="text-2xl font-bold text-gray-800">Risk Assessment</h3>
        <span className="text-sm text-gray-500">
          Analysis Time: {result.analysis_time_ms?.toFixed(2)}ms
        </span>
      </div>
      
      <div className="mb-4">
        <div className="flex justify-between items-center mb-2">
          <span className="text-lg font-semibold text-gray-700">Risk Score</span>
          <span className="text-3xl font-bold text-gray-900">{result.risk_score}/100</span>
        </div>
        <div className="w-full bg-gray-200 rounded-full h-4 overflow-hidden">
          <div
            className={`h-full ${getRiskColorClass(color)} transition-all duration-1000 ease-out`}
            style={{ width: `${result.risk_score}%` }}
          />
        </div>
      </div>

      <div className={`flex items-center gap-3 p-4 rounded-lg border-2 ${getRiskBorderClass(color)}`}>
        {getRiskIcon(color)}
        <div className="flex-1">
          <div className={`text-xl font-bold ${getRiskTextClass(color)}`}>
            {result.risk_level}
          </div>
          <div className="text-sm text-gray-700 mt-1">{result.recommendation}</div>
        </div>
      </div>

      {result.ml_confidence !== null && result.ml_confidence !== undefined && (
        <div className="mt-4 flex items-center justify-between p-3 bg-purple-50 rounded-lg border border-purple-200">
          <span className="text-sm font-medium text-purple-700 flex items-center gap-2">
            <Brain className="w-4 h-4" />
            ML Model Confidence
          </span>
          <span className="text-lg font-bold text-purple-900">
            {(result.ml_confidence * 100).toFixed(1)}%
          </span>
        </div>
      )}
    </div>
  );
};

export default RiskDisplay;
