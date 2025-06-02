/**
 * CVSS Score Prediction & Risk Assessment Tool
 * Frontend JavaScript for the CVSS Prediction Page
 */

// Constants for CVSS score calculation and risk assessment
const CVSS_WEIGHTS = {
    // Access Vector weights
    accessVector: {
        'L': 0.395, // Local
        'A': 0.646, // Adjacent Network
        'N': 1.0    // Network
    },
    // Access Complexity weights
    accessComplexity: {
        'H': 0.35,  // High
        'M': 0.61,  // Medium
        'L': 0.71   // Low
    },
    // Authentication weights
    authentication: {
        'M': 0.45,  // Multiple
        'S': 0.56,  // Single
        'N': 0.704  // None
    },
    // Confidentiality Impact weights
    confidentiality: {
        'N': 0.0,   // None
        'P': 0.275, // Partial
        'C': 0.660  // Complete
    },
    // Integrity Impact weights
    integrity: {
        'N': 0.0,   // None
        'P': 0.275, // Partial
        'C': 0.660  // Complete
    },
    // Availability Impact weights
    availability: {
        'N': 0.0,   // None
        'P': 0.275, // Partial
        'C': 0.660  // Complete
    }
};

// Risk Classification Thresholds
const RISK_THRESHOLDS = {
    LOW: 3.5,
    MEDIUM: 6.5,
    HIGH: 8.5
};

// DOM elements
const elements = {
    form: document.getElementById('cvss-form'),
    loadingIndicator: document.querySelector('.loading-indicator'),
    resultSection: document.getElementById('prediction-result'),
    cvssMeter: document.getElementById('cvss-meter'),
    cvssScore: document.getElementById('cvss-score'),
    riskCategory: document.getElementById('risk-category'),
    exploitabilityScore: document.getElementById('exploitability-score'),
    impactScore: document.getElementById('impact-score'),
    vectorString: document.getElementById('vector-string'),
    addToDashboardBtn: document.getElementById('add-to-dashboard'),
    viewDashboardBtn: document.getElementById('view-dashboard'),
    mobileMenuToggle: document.getElementById('mobile-menu-toggle'),
    mainNav: document.getElementById('main-nav')
};

// Mobile menu toggle
elements.mobileMenuToggle.addEventListener('click', () => {
    elements.mainNav.classList.toggle('active');
});

// Event listeners
document.addEventListener('DOMContentLoaded', () => {
    // Form submission event
    if (elements.form) {
        elements.form.addEventListener('submit', handleFormSubmit);
    }
    
    // Add to Dashboard button event
    if (elements.addToDashboardBtn) {
        elements.addToDashboardBtn.addEventListener('click', addAssessmentToDashboard);
    }
    
    // View Dashboard button event
    if (elements.viewDashboardBtn) {
        elements.viewDashboardBtn.addEventListener('click', () => {
            window.location.href = 'dashboard.html';
        });
    }
    
    // Mobile menu toggle event
    if (elements.mobileMenuToggle) {
        elements.mobileMenuToggle.addEventListener('click', () => {
            elements.mainNav.classList.toggle('active');
        });
    }
    
    // Close mobile menu when clicking outside
    document.addEventListener('click', (event) => {
        if (elements.mainNav && elements.mainNav.classList.contains('active') && 
            !elements.mainNav.contains(event.target) && 
            event.target !== elements.mobileMenuToggle) {
            elements.mainNav.classList.remove('active');
        }
    });
});

/**
 * Handle form submission for CVSS score prediction
 * @param {Event} event - The form submission event
 */
async function handleFormSubmit(event) {
    event.preventDefault();
    
    // Show loading indicator
    elements.loadingIndicator.classList.remove('hidden');
    
    // Get form data
    const formData = new FormData(elements.form);
    const assessmentData = {
        cwe: formData.get('cwe-code'),
        access_vector: formData.get('access-vector'),
        access_complexity: formData.get('access-complexity'),
        authentication: formData.get('authentication'),
        confidentiality: formData.get('confidentiality'),
        integrity: formData.get('integrity'),
        availability: formData.get('availability'),
        summary: formData.get('vulnerability-summary')
    };
    
    try {
        // Call backend API for CVSS prediction
        const response = await fetch('/api/cvss/predict', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify(assessmentData)
        });
        
        const result = await response.json();
        
        if (response.ok && result.success) {
            displayResults(result);
            
            // Save to localStorage for dashboard
            saveAssessmentToStorage({
                ...assessmentData,
                cvssScore: result.cvss_score,
                riskCategory: result.risk_category,
                date: new Date().toISOString(),
                id: Date.now().toString()
            });
        } else {
            throw new Error(result.error || 'Prediction failed');
        }
    } catch (error) {
        console.error('Error:', error);
        // Fallback to client-side calculation if API fails
        console.log('Falling back to client-side calculation');
        const result = calculateCVSSScore(assessmentData);
        displayResults(result);
    } finally {
        // Hide loading indicator
        elements.loadingIndicator.classList.add('hidden');
    }
}

/**
 * Calculate CVSS Base Score
 * @param {Object} data - The vulnerability assessment data
 * @returns {Object} The calculated scores and risk classification
 */
function calculateCVSSScore(data) {
    // Fix property names to match form data and add null checks
    const accessVectorWeight = CVSS_WEIGHTS.accessVector[data.access_vector] || 0.5;
    const accessComplexityWeight = CVSS_WEIGHTS.accessComplexity[data.access_complexity] || 0.5;
    const authenticationWeight = CVSS_WEIGHTS.authentication[data.authentication] || 0.5;
    
    // Calculate Exploitability sub-score
    const exploitability = 20 * accessVectorWeight * accessComplexityWeight * authenticationWeight;
    
    // Get impact weights with fallbacks
    const confidentialityWeight = CVSS_WEIGHTS.confidentiality[data.confidentiality] || 0.0;
    const integrityWeight = CVSS_WEIGHTS.integrity[data.integrity] || 0.0;
    const availabilityWeight = CVSS_WEIGHTS.availability[data.availability] || 0.0;
    
    // Calculate Impact sub-score
    const impact = 10.41 * (1 - (1 - confidentialityWeight) * 
        (1 - integrityWeight) * 
        (1 - availabilityWeight));
    
    // Calculate Base Score
    let baseScore;
    if (impact === 0) {
        baseScore = 0;
    } else {
        const f_impact = impact === 0 ? 0 : 1.176;
        baseScore = ((0.6 * impact) + (0.4 * exploitability) - 1.5) * f_impact;
    }
    
    // Round to 1 decimal place and ensure it's not NaN
    baseScore = Math.round(baseScore * 10) / 10;
    
    // Validate results and handle NaN cases
    if (isNaN(baseScore) || isNaN(exploitability) || isNaN(impact)) {
        console.error('NaN detected in CVSS calculation:', { baseScore, exploitability, impact, data });
        baseScore = 0;
    }
    
    // Simple NLP analysis weight based on keywords in the summary (simplified for demo)
    const vulnerabilityAnalysis = calculateVulnerabilityAnalysis(data.summary);
    
    // Calculate weighted Risk Classification Score (RCS)
    const exploitabilityWeight = exploitability / 20 * 0.3; // 30% weight
    const impactWeight = (impact / 10.41) * 0.5; // 50% weight
    const summaryWeight = vulnerabilityAnalysis * 0.2; // 20% weight
    
    const rcs = (exploitabilityWeight + impactWeight + summaryWeight) * 10;
    
    // Determine risk category
    let riskCategory;
    if (rcs < RISK_THRESHOLDS.LOW) {
        riskCategory = 'Low';
    } else if (rcs < RISK_THRESHOLDS.MEDIUM) {
        riskCategory = 'Medium';
    } else if (rcs < RISK_THRESHOLDS.HIGH) {
        riskCategory = 'High';
    } else {
        riskCategory = 'Critical';
    }
    
    // Generate CVSS vector string with correct property names
    const vectorString = `AV:${data.access_vector}/AC:${data.access_complexity}/Au:${data.authentication}/C:${data.confidentiality}/I:${data.integrity}/A:${data.availability}`;
    
    return {
        baseScore,
        exploitability,
        impact,
        riskCategory,
        vectorString,
        rcs,
        vulnerabilityAnalysis,
        assessmentData: data,
        date: new Date().toISOString()
    };
}

/**
 * Simple text analysis for vulnerability summary (demo implementation)
 * @param {string} summary - The vulnerability summary text
 * @returns {number} A score between 0 and 1 based on keyword analysis
 */
function calculateVulnerabilityAnalysis(summary) {
    const text = summary.toLowerCase();
    
    // Define severity keywords with weights
    const severityKeywords = {
        critical: ['critical', 'severe', 'dangerous', 'exploit', 'arbitrary code', 'remote execution', 'root access'],
        high: ['high', 'serious', 'significant', 'elevated', 'important', 'sensitive data', 'authentication bypass'],
        medium: ['medium', 'moderate', 'limited', 'partial', 'potential', 'information disclosure'],
        low: ['low', 'minor', 'minimal', 'small', 'unlikely', 'difficult to exploit']
    };
    
    let keywordScore = 0;
    let keywordCount = 0;
    
    // Check for critical keywords (highest weight)
    severityKeywords.critical.forEach(keyword => {
        if (text.includes(keyword)) {
            keywordScore += 1.0;
            keywordCount++;
        }
    });
    
    // Check for high keywords
    severityKeywords.high.forEach(keyword => {
        if (text.includes(keyword)) {
            keywordScore += 0.75;
            keywordCount++;
        }
    });
    
    // Check for medium keywords
    severityKeywords.medium.forEach(keyword => {
        if (text.includes(keyword)) {
            keywordScore += 0.5;
            keywordCount++;
        }
    });
    
    // Check for low keywords
    severityKeywords.low.forEach(keyword => {
        if (text.includes(keyword)) {
            keywordScore += 0.25;
            keywordCount++;
        }
    });
    
    // If no keywords found, assign a default score of 0.5
    if (keywordCount === 0) {
        return 0.5;
    }
    
    // Normalize the score between 0 and 1
    return Math.min(keywordScore / keywordCount, 1);
}

/**
 * Display the calculated results in the UI
 * @param {Object} result - The calculated scores and risk assessment
 */
function displayResults(result) {
    // Handle both API response and client-side calculation formats with proper null checking
    const score = result.cvss_score ?? result.baseScore ?? 0;
    const category = result.risk_category || result.riskCategory || 'Unknown';
    
    // Calculate exploitability and impact with null checks
    let exploitability = result.exploitability_score;
    if (exploitability === undefined && result.exploitability !== undefined) {
        exploitability = (result.exploitability / 20) * 10;
    }
    exploitability = exploitability ?? 0;
    
    let impact = result.impact_score;
    if (impact === undefined && result.impact !== undefined) {
        impact = (result.impact / 10.41) * 10;
    }
    impact = impact ?? 0;
    
    const vector = result.cvss_vector || result.vectorString || 'N/A';
    
    // Validate all values before displaying
    if (isNaN(score) || isNaN(exploitability) || isNaN(impact)) {
        console.error('NaN values detected in displayResults:', { score, exploitability, impact, result });
        elements.cvssScore.textContent = '0.0';
        elements.exploitabilityScore.textContent = '0.0';
        elements.impactScore.textContent = '0.0';
        elements.vectorString.textContent = 'Error in calculation';
        elements.riskCategory.textContent = 'Error';
        return;
    }
    
    // Update the UI with the calculated values
    elements.cvssScore.textContent = score.toFixed(1);
    elements.exploitabilityScore.textContent = exploitability.toFixed(1);
    elements.impactScore.textContent = impact.toFixed(1);
    elements.vectorString.textContent = vector;
    
    // Update risk category with appropriate class
    elements.riskCategory.textContent = category;
    elements.riskCategory.className = 'risk-category';
    elements.riskCategory.classList.add(`risk-${category.toLowerCase()}`);
    
    // Update meter value width based on score (0-10)
    elements.cvssMeter.style.width = `${score * 10}%`;
    
    // Store current assessment in session storage for "Add to Dashboard" functionality
    sessionStorage.setItem('currentAssessment', JSON.stringify(result));
    
    // Show results section
    elements.resultSection.classList.remove('hidden');
}

/**
 * Get color based on risk category
 * @param {string} category - Risk category
 * @returns {string} Color value
 */
function getRiskColor(category) {
    const colors = {
        'Low': '#10b981',
        'Medium': '#f59e0b',
        'High': '#ef4444',
        'Critical': '#dc2626'
    };
    return colors[category] || '#6b7280';
}

/**
 * Save assessment to localStorage for dashboard
 * @param {Object} assessment - The assessment data
 */
function saveAssessmentToStorage(assessment) {
    try {
        const existingAssessments = JSON.parse(localStorage.getItem('cvssAssessments') || '[]');
        existingAssessments.push(assessment);
        localStorage.setItem('cvssAssessments', JSON.stringify(existingAssessments));
    } catch (error) {
        console.error('Error saving assessment to localStorage:', error);
    }
}

/**
 * Add the current assessment to the dashboard data
 */
function addAssessmentToDashboard() {
    // Get current assessment from session storage
    const currentAssessment = JSON.parse(sessionStorage.getItem('currentAssessment'));
    
    if (!currentAssessment) {
        alert('No assessment data available. Please calculate a CVSS score first.');
        return;
    }
    
    // Get existing assessments from local storage or initialize empty array
    let assessments = JSON.parse(localStorage.getItem('vulnerabilityAssessments')) || [];
    
    // Add unique ID to the assessment
    currentAssessment.id = Date.now().toString();
    
    // Add to assessments array
    assessments.push(currentAssessment);
    
    // Save back to local storage
    localStorage.setItem('vulnerabilityAssessments', JSON.stringify(assessments));
    
    // Show success message
    alert('Assessment added to dashboard successfully!');
}
