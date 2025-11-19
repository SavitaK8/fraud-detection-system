
/**
 * Home Page Component
 * Main page with all analysis functionality
 */

import React, { useState } from 'react';
import { Shield, Mail, Link2, Phone, Image, Zap, Brain, Eye } from 'lucide-react';
import { analyzeURL, analyzeEmail, analyzePhone, analyzeImage } from '../services/api';
import { TABS, PROJECT_INFO } from '../utils/constants';
import RiskDisplay from '../components/RiskDisplay';
import ThreatList from '../components/ThreatList';
import SecurityDetails from '../components/SecurityDetails';

const Home = () => {
  const [activeTab, setActiveTab] = useState('url');
  const [inputValue, setInputValue] = useState('');
  const [imageFile, setImageFile] = useState(null);
  const [analyzing, setAnalyzing] = useState(false);
  const [result, setResult] = useState(null);
  const [error, setError] = useState(null);

  const handleAnalysis = async () => {
    if (activeTab !== 'image' && !inputValue.trim()) {
      setError('Please enter content to analyze');
      return;
    }
    if (activeTab === 'image' && !imageFile) {
      setError('Please select an image file');
      return;
    }

    setAnalyzing(true);
    setError(null);
    setResult(null);

    try {
      let analysisResult;
      
      switch(activeTab) {
        case 'url':
          analysisResult = await analyzeURL(inputValue);
          break;
        case 'email':
          analysisResult = await analyzeEmail(inputValue);
          break;
        case 'phone':
          analysisResult = await analyzePhone(inputValue);
          break;
        case 'image':
          analysisResult = await analyzeImage(imageFile);
          break;
        default:
          throw new Error('Invalid analysis type');
      }

      setResult(analysisResult);
    } catch (err) {
      const errorMessage = err.detail || err.message || 'Analysis failed. Please try again.';
      setError(errorMessage);
    } finally {
      setAnalyzing(false);
    }
  };

  const handleTabChange = (tabId) => {
    setActiveTab(tabId);
    setInputValue('');
    setImageFile(null);
    setResult(null);
    setError(null);
  };

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-900 via-blue-900 to-slate-900 p-6">
      <div className="max-w-5xl mx-auto">
        {/* Header */}
        <div className="text-center mb-8">
          <div className="flex items-center justify-center mb-4">
            <Shield className="w-16 h-16 text-blue-400 mr-3" />
            <h1 className="text-4xl font-bold text-white">{PROJECT_INFO.title}</h1>
          </div>
          <p className="text-blue-200 text-lg">{PROJECT_INFO.subtitle}</p>
          <div className="flex justify-center gap-6 mt-4 text-sm text-blue-300">
            <div className="flex items-center gap-2">
              <Zap className="w-4 h-4" />
              <span>&lt;500ms Response</span>
            </div>
            <div className="flex items-center gap-2">
              <Brain className="w-4 h-4" />
              <span>90%+ Accuracy</span>
            </div>
            <div className="flex items-center gap-2">
              <Eye className="w-4 h-4" />
              <span>&lt;5% False Positives</span>
            </div>
          </div>
        </div>

        {/* Main Card */}
        <div className="bg-white rounded-2xl shadow-2xl overflow-hidden">
          {/* Tabs */}
          <div className="flex border-b border-gray-200">
            {TABS.map(tab => {
              const IconComponent = {
                url: Link2,
                email: Mail,
                phone: Phone,
                image: Image,
              }[tab.id];

              return (
                <button
                  key={tab.id}
                  onClick={() => handleTabChange(tab.id)}
                  className={`flex-1 flex items-center justify-center gap-2 px-6 py-4 font-semibold transition-all ${
                    activeTab === tab.id
                      ? 'bg-blue-50 text-blue-600 border-b-2 border-blue-600'
                      : 'text-gray-600 hover:bg-gray-50'
                  }`}
                >
                  <IconComponent className="w-5 h-5" />
                  {tab.label}
                </button>
              );
            })}
          </div>

          {/* Input Section */}
          <div className="p-8">
            <div className="mb-6">
              {activeTab === 'image' ? (
                <div>
                  <input
                    type="file"
                    accept="image/*"
                    onChange={(e) => {
                      setImageFile(e.target.files[0]);
                      setError(null);
                    }}
                    className="w-full px-4 py-3 border-2 border-gray-300 rounded-lg focus:border-blue-500 focus:outline-none"
                  />
                  {imageFile && (
                    <p className="mt-2 text-sm text-gray-600">
                      Selected: {imageFile.name} ({(imageFile.size / 1024).toFixed(2)} KB)
                    </p>
                  )}
                </div>
              ) : activeTab === 'email' ? (
                <textarea
                  value={inputValue}
                  onChange={(e) => {
                    setInputValue(e.target.value);
                    setError(null);
                  }}
                  placeholder={TABS.find(t => t.id === activeTab).placeholder}
                  className="w-full h-40 px-4 py-3 border-2 border-gray-300 rounded-lg focus:border-blue-500 focus:outline-none text-gray-800 resize-none"
                />
              ) : (
                <input
                  type="text"
                  value={inputValue}
                  onChange={(e) => {
                    setInputValue(e.target.value);
                    setError(null);
                  }}
                  placeholder={TABS.find(t => t.id === activeTab).placeholder}
                  className="w-full px-4 py-3 border-2 border-gray-300 rounded-lg focus:border-blue-500 focus:outline-none text-gray-800"
                />
              )}
            </div>

            {error && (
              <div className="mb-6 p-4 bg-red-50 border-2 border-red-200 rounded-lg">
                <p className="font-semibold text-red-700">Error:</p>
                <p className="text-red-600">{error}</p>
              </div>
            )}

            <button
              onClick={handleAnalysis}
              disabled={analyzing || (activeTab !== 'image' && !inputValue.trim()) || (activeTab === 'image' && !imageFile)}
              className="w-full bg-gradient-to-r from-blue-600 to-blue-700 text-white py-4 rounded-lg font-semibold text-lg hover:from-blue-700 hover:to-blue-800 disabled:from-gray-400 disabled:to-gray-500 disabled:cursor-not-allowed transition-all transform hover:scale-[1.02] active:scale-[0.98] shadow-lg"
            >
              {analyzing ? (
                <span className="flex items-center justify-center gap-2">
                  <div className="w-5 h-5 border-2 border-white border-t-transparent rounded-full animate-spin" />
                  Analyzing with 12-Layer Detection Engine...
                </span>
              ) : (
                'Analyze for Threats'
              )}
            </button>

            {result && (
              <div className="mt-8 space-y-6 animate-fade-in">
                <RiskDisplay result={result} />
                <ThreatList threats={result.threats} />
                <SecurityDetails details={result.details} />
              </div>
            )}
          </div>
        </div>

        {/* Footer */}
        <div className="mt-8 text-center text-blue-200 text-sm">
          <p className="mb-2">Powered by Random Forest ML • TF-IDF Vectorization • Levenshtein String Matching</p>
          <p>{PROJECT_INFO.college} • CSE Project {PROJECT_INFO.session}</p>
          <p className="mt-1">Team: {PROJECT_INFO.team.join(', ')}</p>
        </div>
      </div>
    </div>
  );
};

export default Home;
